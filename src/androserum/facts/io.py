"""Strict JSON parsing and integrity-checked round-trip I/O."""

from pathlib import Path
import json

from pydantic import ValidationError

from androserum.facts.identity import filesystem_path
from androserum.facts.models import FactBundle, FactConfig
from androserum.facts.validation import CheckIssue, CheckReport, check_facts


class FactValidationError(ValueError):
    def __init__(self, report: CheckReport):
        self.report = report
        super().__init__(f"Fact validation failed with {len(report.errors)} error(s)")


def schema_error_report(error: ValidationError) -> CheckReport:
    return CheckReport(valid=False, errors=[
        CheckIssue(code="schema_validation", path=".".join(str(item) for item in issue["loc"]), message=issue["msg"])
        for issue in error.errors(include_url=False, include_context=False, include_input=False)
    ])


def strict_json_syntax(text: str) -> None:
    def unique_keys(pairs: list[tuple]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"Duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"Non-JSON numeric constant: {value}")

    try:
        json.loads(text, object_pairs_hook=unique_keys, parse_constant=invalid_constant)
    except (ValueError, RecursionError) as error:
        raise FactValidationError(CheckReport(valid=False, errors=[
            CheckIssue(code="json_format", path="$", message=str(error)),
        ])) from error


def loads_config(text: str) -> FactConfig:
    strict_json_syntax(text)
    try:
        return FactConfig.model_validate_json(text)
    except ValidationError as error:
        raise FactValidationError(schema_error_report(error)) from error


def loads_facts(text: str) -> FactBundle:
    strict_json_syntax(text)
    raw = json.loads(text)
    if isinstance(raw, dict) and raw.get("schema_version") == "program-facts.v1":
        if isinstance(raw.get("run"), dict) and raw["run"].get("schema_version", "program-facts.v1") != "program-facts.v1":
            raise FactValidationError(CheckReport(valid=False, errors=[
                CheckIssue(code="schema_validation", path="run.schema_version", message="Legacy bundle and run schema versions disagree"),
            ]))
        raw["schema_version"] = "program-facts.v2"
        raw["source_schema_version"] = "program-facts.v1"
        if isinstance(raw.get("run"), dict):
            raw["run"]["schema_version"] = "program-facts.v2"
        text = json.dumps(raw, ensure_ascii=True, allow_nan=False)
    try:
        facts = FactBundle.model_validate_json(text)
    except ValidationError as error:
        raise FactValidationError(schema_error_report(error)) from error
    report = check_facts(facts)
    if not report.valid:
        raise FactValidationError(report)
    return facts


def load_facts(path: str | Path) -> FactBundle:
    return loads_facts(filesystem_path(path).read_text(encoding="utf-8-sig"))


def dump_facts(facts: FactBundle, path: str | Path) -> None:
    # Re-parse even constructed/mutated objects before writing. Do not overwrite on failure.
    validated = loads_facts(facts.model_dump_json())
    destination = filesystem_path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(json.dumps(validated.model_dump(mode="json"), ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(destination)
