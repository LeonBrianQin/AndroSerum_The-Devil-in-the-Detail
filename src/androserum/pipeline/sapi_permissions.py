"""Audit and explicitly activate a bounded, versioned SAPI supplement.

This format distinguishes source annotations, documented requirements, and
verified wrappers. It does not turn FlowDroid sinks into sources or silently
promote a candidate into the active signature catalog.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import shutil
from uuid import uuid4

from androserum.facts.identity import parse_method_signature
from androserum.facts.sapi import api_signatures, dalvik_signature
from androserum.facts.identity import canonical_json, fingerprint


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _local(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Candidate evidence path escapes the resource bundle")
    return path


def load_permission_candidates(path: Path) -> dict:
    """Verify pinned raw evidence and return still-inactive exact signatures."""
    path = Path(path)
    manifest = json.loads(path.read_text("utf-8"))
    if manifest.get("schema_version") != "permission-candidates.v1":
        raise ValueError("Unsupported permission candidate schema")
    if manifest.get("candidate_only") is not True or manifest.get("active_catalog_changed") is not False:
        raise ValueError("This loader only accepts inactive candidate resources")
    root = path.parent
    index_path = _local(root, manifest["fetch_index_path"])
    raw_index = index_path.read_bytes()
    if _sha(raw_index) != manifest["fetch_index_sha256"]:
        raise ValueError("Fetch index hash mismatch")
    index = json.loads(raw_index)
    sources = {}
    for source in index["sources"]:
        raw = _local(root, source["local_path"]).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if _sha(raw) != source["sha256"] or blob != source["official_git_blob_sha1"]:
            raise ValueError("Pinned source content or Git blob mismatch")
        if not source["url"].startswith("https://android.googlesource.com/"):
            raise ValueError("Unrecognized source origin")
        sources[source["source_id"]] = raw.decode("utf-8").splitlines()
    api = index["api_basis"]
    raw_api = _local(root, api["stdout_path"]).read_bytes()
    if _sha(raw_api) != api["stdout_sha256"]:
        raise ValueError("Platform descriptor evidence hash mismatch")
    signatures = set(api_signatures(raw_api))
    entries = {entry["candidate_id"]: entry for entry in manifest["candidates"]}
    if len(entries) != len(manifest["candidates"]):
        raise ValueError("Duplicate permission candidate identity")
    for entry in [*manifest["candidates"], *manifest.get("annotation_controls", [])]:
        parse_method_signature(entry["signature"])
        if entry["signature"] not in signatures:
            raise ValueError("Exact method signature absent from pinned API descriptors")
        if entry["basis_kind"] not in {"source_javadoc", "source_annotation", "verified_delegation"}:
            raise ValueError("Unrecognized permission evidence role")
        if entry.get("catalog_role") != "permission_operation_candidate" or entry.get("active_anchor") is not False:
            raise ValueError("Resource candidates cannot activate source or sink roles")
        roles = {}
        for evidence in entry["evidence"]:
            start, end = evidence["start_line"], evidence["end_line"]
            lines = sources[evidence["source_id"]]
            if not (isinstance(start, int) and isinstance(end, int) and 1 <= start <= end <= len(lines)):
                raise ValueError("Invalid source excerpt range")
            excerpt = "\n".join(lines[start - 1:end])
            if excerpt != evidence["excerpt"] or _sha(excerpt.encode("utf-8")) != evidence["excerpt_sha256"]:
                raise ValueError("Source excerpt does not match pinned file and lines")
            roles[evidence["role"]] = evidence
        declaration = roles.get("method_declaration")
        if declaration is None:
            raise ValueError("Candidate lacks an exact source declaration")
        source_text = "\n".join(sources[declaration["source_id"]])
        package = re.search(r"(?m)^package ([\w.]+);", source_text)
        method = re.search(r"public(?:\s+final)?\s+(\w+)\s+(\w+)\s*\(([^)]*)\)", declaration["excerpt"])
        if package is None or method is None:
            raise ValueError("Unsupported bounded Java declaration")
        aliases = {"String": "java.lang.String", "PendingIntent": "android.app.PendingIntent", "void": "void"}
        parameters = [part.strip().split()[0] for part in method[3].split(",") if part.strip()]
        parameter_types = ",".join(aliases.get(part, part) for part in parameters)
        derived = dalvik_signature(f"<{package[1]}.SmsManager: {aliases.get(method[1], method[1])} {method[2]}({parameter_types})>")
        if derived != entry["signature"]:
            raise ValueError("Permission evidence was attached to a different source method")
        if entry["basis_kind"] == "source_annotation":
            annotation = roles.get("permission_annotation")
            if annotation is None or "@RequiresPermission" not in annotation["excerpt"] or annotation["end_line"] != declaration["start_line"] - 1:
                raise ValueError("Permission annotation is not adjacent to this exact declaration")
            if entry.get("has_direct_requires_permission_annotation") is not True:
                raise ValueError("A source annotation must preserve its direct-annotation role")
        if entry["basis_kind"] == "source_javadoc" and "permission_javadoc" not in roles:
            raise ValueError("Documented candidate lacks permission documentation")
        permissions = entry["permission_requirements"].get("all_of", [])
        if not permissions or any(not isinstance(p, str) or not p.startswith("android.permission.") for p in permissions):
            raise ValueError("Expected explicit Android permission requirements")
        if entry["basis_kind"] != "verified_delegation":
            permission_text = roles["permission_annotation" if entry["basis_kind"] == "source_annotation" else "permission_javadoc"]["excerpt"]
            for permission in permissions:
                name = permission.rsplit(".", 1)[1]
                if f"permission#{name}" not in permission_text and f"permission.{name}" not in permission_text:
                    raise ValueError("Claimed permission is absent from its source evidence")
        if entry["basis_kind"] == "verified_delegation":
            target = entries.get(entry.get("delegates_to_candidate"))
            if target is None or target["permission_requirements"] != entry["permission_requirements"]:
                raise ValueError("Delegated requirement lacks the explicit target candidate")
            if "delegation_body" not in roles or "delegate_receiver_type" not in roles:
                raise ValueError("Delegation requires its body and receiver type evidence")
        if entry["basis_kind"] != "source_annotation" and entry.get("has_direct_requires_permission_annotation") is not False:
            raise ValueError("Documented or delegated requirements cannot be labeled direct annotations")
    return {"schema_version": "permission-candidate-audit.v1", "valid": True,
            "candidate_count": len(manifest["candidates"]),
            "exact_signatures": [entry["signature"] for entry in manifest["candidates"]],
            "candidates": manifest["candidates"], "active_catalog_changed": False,
            "pending_activation_policy": manifest["pending_activation_policy"]}


SMS_DESCRIPTOR = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V"
SMS_MODERN = "Landroid/telephony/SmsManager;->sendTextMessage" + SMS_DESCRIPTOR
SMS_LEGACY = "Landroid/telephony/gsm/SmsManager;->sendTextMessage" + SMS_DESCRIPTOR
NETWORK_BASE = "Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;"
NETWORK_ALIAS = "Ljava/net/HttpURLConnection;->getInputStream()Ljava/io/InputStream;"
REFLECTION_LOOKUP = "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"


def _support(root: Path) -> dict:
    api = json.loads((root / "api28-class-manifest.json").read_text("utf-8"))
    if api.get("platform_api") != 28 or api.get("host_module_resolution_used") is not False:
        raise ValueError("Supplement requires exact Android API28 class-file evidence")
    classes = {}
    for item in api["classes"]:
        raw_class = _local(root, item["class_path"]).read_bytes()
        raw_output = _local(root, item["stdout_path"]).read_bytes()
        if _sha(raw_class) != item["class_sha256"] or _sha(raw_output) != item["stdout_sha256"]:
            raise ValueError("Android class/descriptor evidence changed")
        if "SHA-256 checksum " + item["class_sha256"] not in raw_output.decode("utf-8"):
            raise ValueError("javap output is not tied to the extracted Android class bytes")
        classes[item["entry"]] = {"metadata": item, "text": raw_output.decode("utf-8"),
                                  "signatures": set(api_signatures(raw_output))}
    http = classes["java/net/HttpURLConnection.class"]
    connection = classes["java/net/URLConnection.class"]
    if "class java.net.HttpURLConnection extends java.net.URLConnection" not in http["text"]:
        raise ValueError("Network alias lacks the exact superclass evidence")
    if NETWORK_BASE not in connection["signatures"] or NETWORK_ALIAS in http["signatures"]:
        raise ValueError("Network alias is not the selected inherited declaration")
    if REFLECTION_LOOKUP not in classes["java/lang/Class.class"]["signatures"]:
        raise ValueError("Exact reflection lookup absent from Android API28")
    aosp = json.loads((root / "aosp-manifest.json").read_text("utf-8"))
    source_rows = {}
    for item in aosp["sources"]:
        raw = _local(root, item["local_path"]).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        tree = json.loads(_local(root, item["tree_evidence"]).read_text("utf-8")[4:])
        commit = json.loads(_local(root, item["commit_evidence"]).read_text("utf-8")[4:])
        filename = item["repository_path"].rsplit("/", 1)[1]
        if (item["tag"] != "android-9.0.0_r1" or item["repository"] != "platform/libcore"
                or _sha(raw) != item["sha256"] or blob != item["git_blob_sha1"]
                or commit["commit"] != item["resolved_commit"]
                or not any(e["name"] == filename and e["id"] == blob for e in tree["entries"])):
            raise ValueError("Pinned libcore source/tag/blob evidence changed")
        source_rows[filename] = {**item, "text": raw.decode("utf-8")}
    if "public static Class<?> forName(String className)" not in source_rows["Class.java"]["text"]:
        raise ValueError("Reflection source declaration changed")
    return {"api": api, "classes": classes, "aosp": source_rows}


def _compile_active(root: Path, config: dict) -> dict:
    from androserum.facts.sapi import load_catalog
    if config.get("schema_version") != "sapi-limited-activation.v1" or config.get("rule_version") != "sms-network-reflection.v1":
        raise ValueError("Unsupported limited SAPI activation policy")
    if config.get("activated_signatures") != [SMS_MODERN, SMS_LEGACY, NETWORK_ALIAS, REFLECTION_LOOKUP]:
        raise ValueError("Activation exceeds the declared four-signature supplement")
    if _sha((root / "base/catalog.json").read_bytes()) != config["base_catalog_sha256"]:
        raise ValueError("Base catalog bytes changed")
    base = load_catalog(root / "base")
    if base["schema_version"] != "sapi-catalog.v1" or base["catalog_id"] != config["base_catalog_id"]:
        raise ValueError("Activation must extend the pinned original catalog")
    for name, expected in config["supplement_file_sha256"].items():
        if _sha(_local(root, name).read_bytes()) != expected:
            raise ValueError("Supplement source or policy bytes changed")
    permission = load_permission_candidates(root / "permissions/candidate-manifest.json")
    if permission["exact_signatures"] != [SMS_MODERN, SMS_LEGACY]:
        raise ValueError("Permission supplement differs from the two reviewed SMS methods")
    support = _support(root / "support")
    entries = {row["signature"]: deepcopy(row) for row in base["entries"]}
    if "sink" not in entries[SMS_MODERN]["roles"] or "source" in entries[SMS_MODERN]["roles"]:
        raise ValueError("The existing SMS role must remain a sink, not a source")
    for candidate in permission["candidates"]:
        signature = candidate["signature"]
        origin = {"source_id": "aosp-android9-sms-permission", "version": "android-9.0.0_r1",
                  "resource_sha256": _sha((root / "permissions/candidate-manifest.json").read_bytes()),
                  "line": next(e["start_line"] for e in candidate["evidence"] if e["role"] == "method_declaration"),
                  "raw_signature": signature, "metadata": {"basis_kind": candidate["basis_kind"],
                  "has_direct_requires_permission_annotation": False,
                  "permission_requirements": candidate["permission_requirements"],
                  "source_manifest": "permissions/candidate-manifest.json", "candidate_id": candidate["candidate_id"],
                  "delegate_target": SMS_MODERN if signature == SMS_LEGACY else None,
                  "sink_role_basis": "Original FlowDroid modern method sink plus verified unchanged legacy delegation",
                  "runtime_success_inferred": False}}
        row = entries.setdefault(signature, {"signature": signature, "roles": [], "origins": [], "anchor": False})
        row["roles"] = sorted(set(row["roles"]) | {"permission_operation", "sink"})
        row["origins"].append(origin)
        row["anchor"] = True
    source = entries[NETWORK_BASE]
    if set(source["roles"]) != {"source", "sink"} or not source["anchor"]:
        raise ValueError("Network alias cannot invent or promote source/sink roles")
    entries[NETWORK_ALIAS] = {"signature": NETWORK_ALIAS, "roles": list(source["roles"]), "anchor": True,
        "origins": [{"source_id": "android28-inherited-declared-owner-alias", "version": "28-r6",
                     "resource_sha256": _sha((root / "support/api28-class-manifest.json").read_bytes()),
                     "raw_signature": NETWORK_ALIAS, "line": None,
                     "metadata": {"basis_signature": NETWORK_BASE, "basis_origins": source["origins"],
                                  "subclass": "java.net.HttpURLConnection", "superclass": "java.net.URLConnection",
                                  "api_jar_sha256": support["api"]["jar_sha256"],
                                  "method_scope": "Exact inherited declared-owner alias only; no general subclass expansion",
                                  "stream_contents_or_success_inferred": False}}]}
    reflection_source = support["aosp"]["Class.java"]
    reflection_line = next(i + 1 for i, line in enumerate(reflection_source["text"].splitlines())
                           if "public static Class<?> forName(String className)" in line)
    entries[REFLECTION_LOOKUP] = {"signature": REFLECTION_LOOKUP, "roles": ["reflection_operation"], "anchor": True,
        "origins": [{"source_id": "aosp-android9-reflection-lookup", "version": "android-9.0.0_r1",
                     "resource_sha256": reflection_source["sha256"], "raw_signature": REFLECTION_LOOKUP,
                     "line": reflection_line, "metadata": {key: reflection_source[key] for key in
                         ("url", "resolved_commit", "git_blob_sha1", "repository_path")},
                     "interpretation": "Class lookup/initialization request only; target resolution, success, invoked code and maliciousness are not inferred"}]}
    policy = deepcopy(base["role_policy"])
    policy.update(permission_operation="anchor_from_explicit_documented_or_delegated_permission_policy; not a taint source",
                  reflection_operation="anchor_lookup_request_only; not a FlowDroid source or resolved dynamic target",
                  inherited_declared_owner_alias="retain original source/sink roles for exact API28 alias")
    catalog = {"schema_version": "sapi-active-catalog.v1", "import_config": config,
               "scope": "Pinned base plus two SMS permission operations, one exact network source/sink owner alias, and one reflection lookup operation",
               "multi_source_catalog_complete": False, "entries": [entries[k] for k in sorted(entries)],
               "issues": deepcopy(base["issues"]), "pending_sources": deepcopy(base["pending_sources"]),
               "role_policy": policy, "base_catalog_id": base["catalog_id"],
               "source_policy_limits": ["Ordinary SMS methods have permission Javadoc/verified delegation, not direct annotations.",
                                        "The distinct WithoutPersisting annotation control is not activated.",
                                        "Network inheritance is exactly one observed API28 declared-owner alias.",
                                        "No general reflection resolver, SDK-wide permission import or propagation model is added."]}
    catalog["catalog_id"] = fingerprint(catalog)
    return catalog


def load_active_catalog(path: Path) -> dict:
    root = Path(path)
    root = root.parent if root.is_file() else root
    actual = json.loads((root / "catalog.json").read_text("utf-8"))
    expected = _compile_active(root, actual["import_config"])
    if actual != expected:
        raise ValueError("Active SAPI catalog differs from its pinned sources and limited import policy")
    return expected


def activate_catalog(base_path: Path, permission_manifest: Path, support_path: Path, output: Path) -> dict:
    """Publish a self-contained new directory; never edit the original catalog."""
    from androserum.facts.sapi import load_catalog
    base_path, permission_manifest, support_path, output = map(Path, (base_path, permission_manifest, support_path, output))
    base_path = base_path.parent if base_path.is_file() else base_path
    inputs = (base_path, permission_manifest.parent, support_path)
    if output.exists() or any(output.resolve().is_relative_to(source.resolve()) for source in inputs):
        raise ValueError("New active catalog output must be absent and outside all original source directories")
    base = load_catalog(base_path)
    load_permission_candidates(permission_manifest)
    _support(support_path)
    work = output.with_name(output.name + ".work-" + uuid4().hex)
    work.mkdir(parents=True, exist_ok=False)
    shutil.copytree(base_path, work / "base")
    shutil.copytree(permission_manifest.parent, work / "permissions")
    shutil.copytree(support_path, work / "support")
    supplement = {p.relative_to(work).as_posix(): _sha(p.read_bytes()) for directory in (work / "permissions", work / "support")
                  for p in sorted(directory.rglob("*")) if p.is_file()}
    config = {"schema_version": "sapi-limited-activation.v1", "rule_version": "sms-network-reflection.v1",
              "base_catalog_id": base["catalog_id"], "base_catalog_sha256": _sha((work / "base/catalog.json").read_bytes()),
              "activated_signatures": [SMS_MODERN, SMS_LEGACY, NETWORK_ALIAS, REFLECTION_LOOKUP],
              "supplement_file_sha256": supplement}
    catalog = _compile_active(work, config)
    (work / "catalog.json").write_text(canonical_json(catalog), "utf-8", newline="\n")
    load_active_catalog(work)
    work.rename(output)
    return catalog
