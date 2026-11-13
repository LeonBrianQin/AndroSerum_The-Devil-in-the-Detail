"""F3 orchestration, independently committed method protocol, and conservative origin mapping."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Literal

from pydantic import Field, TypeAdapter

from androserum import __version__
from androserum.facts.extractor import ALL, ExtractionOptions, ExtractionResult, extract_apk
from androserum.facts.identity import canonical_json, filesystem_path, fingerprint, record_id, sha256_file
from androserum.facts.io import loads_facts, strict_json_syntax
from androserum.facts.jimple import BackendEnd, BackendStart, IRValue, JimpleMethod, MethodCommit, compatible_origin, verify_jimple_evidence
from androserum.facts.models import (
    AnalysisNodeRecord, AnalysisPosition, AnalysisScope, AnalysisStatus, ClassRecord, ConfigurationRecord,
    Endpoint, FactBundle, FactConfig, InstructionRecord, MethodRecord, ProgramSlot, Provenance, RelationRecord,
    StrictModel, ToolVersion, ValueInfo, VersionedArtifact,
)
from androserum.facts.validation import walk_models

ROOT = Path(__file__).resolve().parents[3]
PROJECT = ROOT / "java/fact-backend"
SDK = ROOT / ".tools/android-sdk"
JDK = ROOT / ".tools/jdk-17"
BACKEND_VERSION = "0.2.0"


class JavaConfig(StrictModel):
    schema_version: Literal["java-config.v1"] = "java-config.v1"
    platform_api: int | None = Field(default=None, ge=1, le=1000)
    fallback_api: int | None = Field(default=16, ge=1, le=1000)
    timeout_seconds: float = Field(default=120, gt=0, le=3600)
    heap_mb: int = Field(default=2048, ge=128, le=16384)
    max_methods: int = Field(default=100000, ge=1, le=1000000)
    max_units_per_method: int = Field(default=1000000, ge=1, le=10000000)
    max_method_file_bytes: int = Field(default=32 * 1024 * 1024, ge=1)
    max_output_bytes: int = Field(default=256 * 1024 * 1024, ge=1)
    export_cfg: bool = False


def _normal(path):
    value = str(path)
    if value.startswith("\\\\?\\UNC\\"):
        return "\\\\" + value[8:]
    return value[4:] if value.startswith("\\\\?\\") else value


def _read(path: Path, limit=32 * 1024 * 1024):
    if path.stat().st_size > limit:
        raise ValueError("Java protocol file budget exceeded")
    text = path.read_text(encoding="utf-8")
    strict_json_syntax(text)
    return json.loads(text)


def _sources():
    files = [PROJECT / "pom.xml", *sorted((PROJECT / "src/main/java").rglob("*.java"))]
    return {path.relative_to(ROOT).as_posix(): sha256_file(path) for path in files}


def build_java_backend() -> dict:
    target = filesystem_path(PROJECT / "target")
    target.relative_to(filesystem_path(PROJECT))
    if not (PROJECT / "src/main/java/org/androserum/backend/FactBackend.java").is_file():
        raise ValueError("Java backend entry source is missing")
    if target.exists():
        shutil.rmtree(target)
    env = os.environ.copy()
    env["JAVA_HOME"] = str(JDK)
    env["PATH"] = str(JDK / "bin") + os.pathsep + env.get("PATH", "")
    argv = [str(ROOT / ".tools/apache-maven-3.9.16/bin/mvn.cmd"), "-o", "-B", "-s", str(ROOT / "configs/maven-settings.xml"),
            f"-Dmaven.repo.local={ROOT / '.tools/m2'}", "-f", str(PROJECT / "pom.xml"), "package", "dependency:copy-dependencies"]
    result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, timeout=180)
    target = PROJECT / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "build.stdout.log").write_bytes(result.stdout)
    (target / "build.stderr.log").write_bytes(result.stderr)
    if result.returncode:
        raise ValueError("Java backend build failed; see java/fact-backend/target/build.stdout.log")
    jars = sorted((target / "dependency").glob("*.jar"))
    soot = target / "dependency/soot-4.7.1.jar"
    original = ROOT / ".tools/m2/org/soot-oss/soot/4.7.1/soot-4.7.1.jar"
    if sha256_file(soot) != sha256_file(original):
        raise ValueError("Soot copy differs from the fixed local dependency")
    outputs = [target / f"fact-backend-{BACKEND_VERSION}.jar", *sorted((target / "classes").rglob("*.class")), *jars]
    report = {"schema_version": "java-build.v1", "status": "passed", "source_sha256": _sources(),
              "argv": argv, "exit_code": result.returncode,
              "java_runtime_sha256": sha256_file(JDK / "bin/java.exe"),
              "java_compiler_sha256": sha256_file(JDK / "bin/javac.exe"),
              "output_sha256": {path.relative_to(ROOT).as_posix(): sha256_file(path) for path in outputs}}
    (target / "build.json").write_text(canonical_json(report) + "\n", encoding="utf-8")
    return report


def verify_build():
    report = _read(PROJECT / "target/build.json")
    if report.get("schema_version") != "java-build.v1" or report.get("source_sha256") != _sources():
        raise ValueError("Java backend build is missing or stale; run build-java")
    if (report.get("java_runtime_sha256") != sha256_file(JDK / "bin/java.exe") or
            report.get("java_compiler_sha256") != sha256_file(JDK / "bin/javac.exe")):
        raise ValueError("Java build/runtime environment changed; run build-java")
    target = PROJECT / "target"
    actual = {path.relative_to(ROOT).as_posix() for path in [target / f"fact-backend-{BACKEND_VERSION}.jar",
              *sorted((target / "classes").rglob("*.class")), *sorted((target / "dependency").glob("*.jar"))]}
    if actual != set(report["output_sha256"]):
        raise ValueError("Java backend classpath content differs from its build manifest")
    for path, digest in report["output_sha256"].items():
        if sha256_file(ROOT / path) != digest:
            raise ValueError("Java backend build output checksum mismatch")
    return report


def select_platform(facts: FactBundle, config: JavaConfig, sdk: str | Path = SDK):
    sdk = filesystem_path(sdk)
    available = sorted(int(path.parent.name.removeprefix("android-")) for path in (sdk / "platforms").glob("android-*/android.jar")
                       if path.parent.name.removeprefix("android-").isdigit())
    compile_sdk = None
    android = "{http://schemas.android.com/apk/res/android}"
    for record in facts.elements:
        if isinstance(record, ConfigurationRecord) and record.value.status == "known" and record.value.value.get("tag") == "manifest":
            compile_sdk = record.value.value["attributes"].get(android + "compileSdkVersion")
    def number(value):
        return int(value) if isinstance(value, (int, str)) and str(value).isdigit() else None
    compile_sdk, target = number(compile_sdk), number(facts.run.apk_metadata.get("target_sdk"))
    selected, basis, fallback = None, None, False
    if config.platform_api is not None:
        if config.platform_api in available:
            selected, basis = config.platform_api, "explicit"
        else:
            basis = "explicit_platform_missing"
    elif compile_sdk in available:
        selected, basis = compile_sdk, "declared_compile_sdk"
    elif target in available:
        selected, basis = target, "target_sdk_heuristic"
    elif config.fallback_api in available:
        selected, basis, fallback = config.fallback_api, "configured_fallback", True
    else:
        basis = "no_applicable_installed_platform"
    path = sdk / "platforms" / f"android-{selected}" / "android.jar" if selected is not None else None
    return {"schema_version": "android-selection.v1", "selected_api": selected, "basis": basis, "fallback": fallback,
            "compile_sdk": compile_sdk, "target_sdk": target, "available_apis": available,
            "jar": _normal(path) if path else None, "sha256": sha256_file(path) if path else None,
            "limits": "Platform selection is explicit policy/heuristic; it does not prove full API compatibility"}


def _request(facts, apk, config, platform):
    class_counts = Counter(record.descriptor for record in facts.elements if isinstance(record, ClassRecord))
    definitions = [record for record in facts.elements if isinstance(record, MethodRecord) and record.is_definition]
    signatures = [record.signature for record in definitions if class_counts[record.signature.split("->")[0]] == 1]
    return {"schema_version": "jimple-request.v1", "apk_path": _normal(filesystem_path(apk)), "apk_sha256": facts.run.apk_sha256,
            "run_ref": facts.run.run_id, "android_jar": platform["jar"], "android_jar_sha256": platform["sha256"],
            "method_signatures": sorted(signatures), "max_methods": config.max_methods,
            "max_units_per_method": config.max_units_per_method, "max_method_file_bytes": config.max_method_file_bytes,
            "max_output_bytes": config.max_output_bytes, "export_cfg": config.export_cfg}


def _launch(request, work, config):
    request_path = work / "request.json"
    request_path.write_text(canonical_json(request) + "\n", encoding="utf-8")
    argv = [str(JDK / "bin/java.exe"), f"-Xmx{config.heap_mb}m", "-Dfile.encoding=UTF-8", "-cp",
            str(PROJECT / "target/classes") + os.pathsep + str(PROJECT / "target/dependency/*"),
            "org.androserum.backend.FactBackend", _normal(request_path), _normal(work)]
    with (work / "stdout.log").open("wb") as stdout, (work / "stderr.log").open("wb") as stderr:
        try:
            result = subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr, timeout=config.timeout_seconds)
            state, code = ("exited" if result.returncode == 0 else "failed"), result.returncode
        except subprocess.TimeoutExpired:
            state, code = "timeout", None
        except OSError as error:
            state, code = "launch_failed", None
            stderr.write(str(error).encode("utf-8"))
    result = {"argv": argv, "state": state, "exit_code": code, "request_sha256": sha256_file(request_path)}
    (work / "process.json").write_text(canonical_json(result) + "\n", encoding="utf-8")
    return result


def read_backend(work, request, process, config):
    """Only checksum-bound, complete per-method commits survive partial process output."""
    methods, errors = [], []
    request_hash = process["request_sha256"]
    total = sum(path.stat().st_size for path in work.rglob("*") if path.is_file())
    if total > config.max_output_bytes:
        return [], {"state": "failed", "reason": "Java output budget exceeded"}, ["java_output_budget"]
    try:
        start = BackendStart.model_validate_json(canonical_json(_read(work / "start.json"))).model_dump(mode="json")
        if (start.get("schema_version") != "jimple-run.v1" or start.get("request_sha256") != request_hash or
                start.get("apk_sha256") != request["apk_sha256"] or start.get("android_jar_sha256") != request["android_jar_sha256"]):
            raise ValueError("Java start identity mismatch")
    except (ValueError, OSError) as error:
        return [], {"state": "failed", "reason": str(error)}, ["java_start_invalid"]
    seen, commits = set(), []
    for path in sorted((work / "methods").glob("*.commit.json"), key=lambda path:
                       (int(path.name.split(".")[0]) if path.name.split(".")[0].isdigit() else 10**30, path.name)):
        try:
            commit = MethodCommit.model_validate_json(canonical_json(_read(path))).model_dump(mode="json")
            if (set(commit) != {"schema_version", "request_sha256", "apk_sha256", "path", "sha256", "signature"} or
                    commit["schema_version"] != "jimple-commit.v1" or commit["request_sha256"] != request_hash or
                    commit["apk_sha256"] != request["apk_sha256"] or not re.fullmatch(r"methods/[0-9]{5,}\.json", commit["path"])):
                raise ValueError("Invalid method commit identity/path")
            target = filesystem_path(work / commit["path"])
            target.relative_to(work)
            if sha256_file(target) != commit["sha256"]:
                raise ValueError("Method commit checksum mismatch")
            raw = _read(target, config.max_method_file_bytes)
            method = JimpleMethod.model_validate_json(canonical_json(raw))
            if method.signature != commit["signature"] or method.signature not in request["method_signatures"] or method.signature in seen:
                raise ValueError("Method identity is absent/ambiguous/duplicated")
            seen.add(method.signature)
            methods.append((method, commit["path"]))
            commits.append(path.relative_to(work).as_posix())
        except (ValueError, OSError) as error:
            errors.append(path.name + ": " + str(error))
    try:
        end = BackendEnd.model_validate_json(canonical_json(_read(work / "end.json"))).model_dump(mode="json")
        if (set(end) != {"schema_version", "request_sha256", "apk_sha256", "state", "reason", "commits", "method_budget_exhausted", "phantom_classes"} or
                end["schema_version"] != "jimple-end.v1" or end["request_sha256"] != request_hash or end["apk_sha256"] != request["apk_sha256"] or
                end["commits"] != commits or end["state"] not in {"complete", "partial", "failed"}):
            raise ValueError("Java end frame identity/commit list mismatch")
    except (ValueError, OSError) as error:
        errors.append("java_end_invalid: " + str(error))
        end = {"state": "partial" if methods else "failed", "reason": str(error), "method_budget_exhausted": False, "phantom_classes": []}
    if process["state"] != "exited":
        errors.append("java_process_" + process["state"])
    return methods, end, errors


def _slots(unit):
    slots, locals_seen = [], set()
    def add_local(value):
        if value.local_index is not None and value.local_index not in locals_seen:
            locals_seen.add(value.local_index)
            slots.append(ProgramSlot(slot_kind="local", slot_index=value.local_index, type_descriptor=value.type_descriptor,
                value=ValueInfo(status="unknown", reason="Jimple local identity; runtime value needs subsequent analysis")))
        for child in value.children:
            add_local(child)
    for value in unit.definitions + unit.uses:
        add_local(value)
    if unit.definitions:
        slots.append(ProgramSlot(slot_kind="result", type_descriptor=unit.definitions[0].type_descriptor,
            value=ValueInfo(status="unknown", reason="IR definition; no reaching-definition inference performed")))
    if unit.invoke:
        if unit.invoke.receiver:
            slots.append(ProgramSlot(slot_kind="receiver", type_descriptor=unit.invoke.receiver.type_descriptor,
                value=ValueInfo(status="unknown", reason="IR invocation receiver")))
        for i, argument in enumerate(unit.invoke.arguments):
            slots.append(ProgramSlot(slot_kind="argument", slot_index=i, type_descriptor=argument.type_descriptor,
                value=ValueInfo(status="unknown", reason="IR argument; structured operand is retained in the IR artifact")))
    return slots


def extract_java(apk: str | Path, *, config: JavaConfig | None = None, extraction: ExtractionOptions | None = None,
                 work_directory: str | Path | None = None) -> ExtractionResult:
    config = JavaConfig.model_validate((config or JavaConfig()).model_dump())
    extraction = extraction or ExtractionOptions()
    base = extract_apk(apk, FactConfig(requested_capabilities=list(ALL), options=extraction.model_dump()))
    facts = base.facts
    facts.run.configuration.options = {"extraction": extraction.model_dump(), "java": config.model_dump(mode="json")}
    facts.run.config_fingerprint = fingerprint(facts.run.configuration.model_dump(mode="json"))
    platform = select_platform(facts, config)
    facts.run.apk_metadata["java_platform_selection"] = platform
    facts.run.tools.extend([ToolVersion(tool_id="tool:soot", name="soot", version="4.7.1"),
                            ToolVersion(tool_id="tool:java-adapter", name="androserum-java-adapter", version=__version__)])
    java_source = PROJECT / "src/main/java/org/androserum/backend/FactBackend.java"
    implementation = {}
    for identifier, name, path in [("rule:jimple-export", "structured-jimple-export-v1", java_source),
                                    ("rule:java-orchestration", "java-orchestration-v1", Path(__file__)),
                                    ("rule:structured-ir", "structured-ir-and-origin-checks-v1", Path(__file__).with_name("jimple.py"))]:
        entry = "analysis/rules/" + path.name
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        base.blobs[digest], base.entry_digests[entry] = data, digest
        implementation[entry] = digest
        facts.run.artifacts.append(VersionedArtifact(artifact_id=identifier, kind="rule", name=name, version="1", sha256=digest, location=entry))
    rule = canonical_json({"schema_version": "dex-jimple-rule.v1", "soot_version": "4.7.1", "offset_bytes_factor": 2,
        "checks": ["unambiguous method/DEX ownership", "retained origin tag", "opcode/category/signature/kind agreement"],
        "is_execution_order": False, "implementation_sha256": implementation}).encode("utf-8")
    digest = hashlib.sha256(rule).hexdigest()
    entry = "analysis/rules/dex-jimple-origin.json"
    base.blobs[digest], base.entry_digests[entry] = rule, digest
    facts.run.artifacts.append(VersionedArtifact(artifact_id="rule:dex-jimple-origin", kind="rule",
        name="checked-dex-offset-tag-origin-v1", version="1", sha256=digest, location=entry))
    if platform["selected_api"] is not None:
        facts.run.artifacts.append(VersionedArtifact(artifact_id="platform:android", kind="platform", name=f"android-{platform['selected_api']}",
            version=str(platform["selected_api"]), sha256=platform["sha256"], location=platform["jar"]))
    run_ref = facts.run.run_id
    def identifier(kind, value):
        return record_id(run_ref, kind, value)
    issues = []
    def issue(code, reason, *, element=None, state="partial"):
        status = AnalysisStatus(id=identifier("status", ["java", code, element, reason]), run_ref=run_ref, tool_ref="tool:java-adapter",
            capability="dex_jimple_mapping", scope=AnalysisScope(kind="element", element_ref=element) if element else AnalysisScope(kind="run"),
            state=state, reason=reason, issue_code=code)
        issues.append(status)
    methods, end, errors, process = [], {"state": "failed", "reason": "Java was not launched"}, [], None
    # Private work directories are retained for audit; published evidence copies the consumed artifacts.
    if work_directory is None:
        parent = ROOT / "artifacts/work/f3"
        parent.mkdir(parents=True, exist_ok=True)
        work = filesystem_path(tempfile.mkdtemp(prefix="java_", dir=parent))
    else:
        work = filesystem_path(work_directory)
        work.mkdir(parents=True, exist_ok=False)
    (work / "selection.json").write_text(canonical_json(platform) + "\n", encoding="utf-8")
    if platform["fallback"]:
        issue("java_platform_fallback", "Configured fallback platform selected; full API compatibility is not established")
    if platform["selected_api"] is None:
        issue("java_platform_unavailable", platform["basis"], state="unavailable")
    else:
        try:
            build = verify_build()
            request = _request(facts, apk, config, platform)
            process = _launch(request, work, config)
            methods, end, errors = read_backend(work, request, process, config)
            if (work / "start.json").exists():
                try:
                    start = BackendStart.model_validate_json(canonical_json(_read(work / "start.json")))
                    facts.run.tools.append(ToolVersion(tool_id="tool:java-runtime", name="Java runtime", version=start.java_version))
                except ValueError:
                    pass  # Protocol failure is already recorded by read_backend.
            (work / "build.json").write_text(canonical_json(build) + "\n", encoding="utf-8")
        except (ValueError, OSError) as error:
            issue("java_backend_unavailable", str(error), state="failed")
    for error in errors:
        issue("java_protocol_or_process_issue", error)
    if end.get("state") == "failed" and platform["selected_api"] is not None:
        issue("java_backend_failed", end.get("reason") or "No valid Java completion", state="failed")
    if end.get("phantom_classes"):
        issues.append(AnalysisStatus(id=identifier("status", ["java-phantoms", end["phantom_classes"]]), run_ref=run_ref,
            tool_ref="tool:soot", capability="dex_jimple_mapping", scope=AnalysisScope(kind="location",
                location=AnalysisPosition(kind="analysis", artifact_path="analysis/java/end.json", position_label="phantom_classes")),
            state="partial", reason="Soot loaded unresolved class stubs; not all of these stubs need occur in exported units",
            unknowns=end["phantom_classes"], issue_code="java_phantom_classes"))
    definitions = defaultdict(list)
    instructions = defaultdict(dict)
    class_counts = Counter(record.descriptor for record in facts.elements if isinstance(record, ClassRecord))
    for record in facts.elements:
        if isinstance(record, MethodRecord) and record.is_definition:
            definitions[record.signature].append(record)
        if isinstance(record, InstructionRecord):
            instructions[record.position.method_ref][record.position.offset_bytes] = record
    seen, mapping_counts, method_counts = set(), Counter(), Counter()
    for method, filename in methods:
        seen.add(method.signature)
        candidates = definitions[method.signature]
        if len(candidates) != 1 or class_counts[method.signature.split("->")[0]] != 1:
            issue("java_method_ambiguous", method.signature)
            continue
        owner = candidates[0]
        method_counts[method.state] += 1
        if method.state != "complete":
            expected = method.state in {"abstract", "native"}
            status = "unavailable" if expected or method.state == "unavailable" else "truncated" if method.state == "truncated" else "failed"
            issue("java_body_not_applicable" if expected else "java_method_" + method.state,
                  method.reason or method.state, element=owner.id, state=status)
            continue
        entry = "analysis/java/" + filename
        for unit in method.units:
            node_id = identifier("analysis", [owner.id, unit.index])
            origins = []
            for offset in sorted(set(unit.offsets_code_units)):
                original = instructions[owner.id].get(offset * 2)
                if original is not None and compatible_origin(original, unit):
                    origins.append(original)
            node = AnalysisNodeRecord(id=node_id, run_ref=run_ref, provenance=Provenance(kind="static_analysis", tool_ref="tool:soot",
                support_refs=[owner.id, *[value.id for value in origins]], rule_ref="rule:jimple-export"), kind="analysis_node",
                node_kind="jimple", position=AnalysisPosition(kind="analysis", artifact_path=entry, position_label=f"unit:{unit.index}"),
                method_ref=owner.id, text=unit.text, slots=_slots(unit))
            facts.elements.append(node)
            if any(isinstance(value, IRValue) and value.truncated for value, _ in walk_models(unit, "unit")):
                issue("jimple_operand_truncated", "Structured operand depth budget was reached", element=node_id, state="truncated")
            if unit.operation == "identity" and unit.right and unit.right.identity_kind in {"this", "parameter"}:
                mapping_counts["implicit_identity"] += 1
            elif not origins:
                mapping_counts["unmapped"] += 1
                issue("jimple_origin_unresolved", "No compatible DEX instruction at a retained offset tag; no position is guessed", element=node_id)
            else:
                multiple = len(set(unit.offsets_code_units)) != 1
                mapping_counts["candidate" if multiple else "resolved"] += 1
                if multiple:
                    issue("jimple_origin_candidate", "Several retained tags remain; candidates are not one deterministic origin", element=node_id)
                for original in origins:
                    facts.relations.append(RelationRecord(id=identifier("relation", ["dex_jimple_mapping", original.id, node_id]), run_ref=run_ref,
                        provenance=Provenance(kind="static_analysis", tool_ref="tool:java-adapter", rule_ref="rule:dex-jimple-origin",
                            support_refs=[owner.id, original.id, node_id]), relation_kind="dex_jimple_mapping",
                        source=Endpoint(element_ref=original.id, slot_kind="element", position_label=original.position.position_label),
                        target=Endpoint(element_ref=node_id, slot_kind="element", position_label=node.position.position_label),
                        resolution="partial" if multiple else "resolved",
                        unresolved_reason="Several offset tags remain; origin is a candidate" if multiple else None,
                        source_selector=entry + f"#/units/{unit.index}/offsets_code_units"))
            if unit.invoke and unit.invoke.phantom_owner:
                issue("java_phantom_call_owner", unit.invoke.signature, element=node_id)
    for signature, owners in definitions.items():
        if signature in seen:
            continue
        ambiguous = len(owners) != 1 or class_counts[signature.split("->")[0]] != 1
        for owner in owners:
            issue("java_definition_ambiguous" if ambiguous else "java_method_not_completed", signature,
                element=owner.id, state="unavailable" if ambiguous else "truncated" if end.get("method_budget_exhausted") or (process and process["state"] == "timeout") else "failed")
    meaningful = [value for value in issues if value.issue_code != "java_body_not_applicable"]
    state = "failed" if not methods else "partial" if meaningful or end.get("state") != "complete" else "complete"
    existing = next(value for value in facts.statuses if value.capability == "dex_jimple_mapping" and value.scope.kind == "run")
    existing.tool_ref, existing.state = "tool:java-adapter", state
    existing.reason = None if state == "complete" else "Java processing/mapping has explicit gaps; see analysis statuses and IR artifacts"
    run_issues = [value for value in issues if value.scope.kind == "run"]
    if run_issues:
        existing.issue_code = run_issues[0].issue_code
        existing.reason += "; " + "; ".join(value.reason for value in run_issues)
    facts.statuses.extend(value for value in issues if value.scope.kind != "run")
    adapter_summary = {"schema_version": "java-analysis.v1", "platform": platform, "process": process, "end": end,
        "protocol_errors": errors, "methods": dict(method_counts), "mapping": dict(mapping_counts),
        "rule": "Retained code-unit tags times two plus operation/signature checks; tags are conversion origins, not execution order",
        "limits": ["Optimized/folded instructions need not survive as Jimple units", "Absent/inherited incompatible tags remain unresolved",
                   "No reaching-definition, points-to, control-dependence, event, or FlowDroid tracing is performed"]}
    (work / "analysis.json").write_text(canonical_json(adapter_summary) + "\n", encoding="utf-8")
    required = {filename for _, filename in methods}
    paths = sorted(work.rglob("*"), key=lambda path: (path.relative_to(work).as_posix() not in required, path.as_posix()))
    copied, omitted = 0, []
    for path in paths:
        if path.is_file() and not path.name.endswith(".tmp"):
            size = path.stat().st_size
            if copied + size > config.max_output_bytes:
                omitted.append({"path": path.relative_to(work).as_posix(), "bytes": size, "sha256": sha256_file(path)})
                continue
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            base.blobs[digest] = data
            base.entry_digests["analysis/java/" + path.relative_to(work).as_posix()] = digest
            copied += size
    capture = canonical_json({"schema_version": "java-capture.v1", "copied_bytes": copied, "omitted": omitted}).encode("utf-8")
    digest = hashlib.sha256(capture).hexdigest()
    base.blobs[digest], base.entry_digests["analysis/java/capture.json"] = capture, digest
    if sha256_file(apk) != facts.run.apk_sha256:
        raise OSError("APK changed during Java analysis; result is not published")
    if platform["jar"] is not None and sha256_file(platform["jar"]) != platform["sha256"]:
        raise OSError("Android platform changed during Java analysis; result is not published")
    base.facts = loads_facts(facts.model_dump_json())
    verify_jimple_evidence(base.facts, lambda entry: base.blobs[base.entry_digests[entry]])
    base.summary.update(stage="F3", schema_version=facts.schema_version, java=adapter_summary,
        element_counts=dict(Counter(value.kind for value in facts.elements)),
        relation_counts=dict(Counter(value.relation_kind for value in facts.relations)),
        coverage={value.capability: value.state for value in facts.statuses if value.scope.kind == "run"},
        issues=sum(value.issue_code is not None for value in facts.statuses))
    base.summary["outcome"] = "failed" if not definitions else "complete" if base.summary["outcome"] == state == "complete" else "partial"
    return base
