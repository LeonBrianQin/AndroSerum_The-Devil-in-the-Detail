"""Versioned BU policies and hard limits cannot be relaxed by unknown flags."""
import json
from pathlib import Path
import pytest
from pydantic import ValidationError
from androserum.facts.bu import BUConfig

ROOT = Path(__file__).resolve().parents[2]


def test_bu_schema_and_example_are_executable_contracts():
    assert json.loads((ROOT/'schemas/bu-config.v1.schema.json').read_text('utf-8')) == BUConfig.model_json_schema()
    assert BUConfig.model_validate_json((ROOT/'configs/bu.example.json').read_text('utf-8')) == BUConfig()


@pytest.mark.parametrize('value', [{'max_tasks':0}, {'max_units':0}, {'max_roots':0}, {'max_support_files':0},
    {'source_policy':'expand_all_consumers'}, {'visibility_policy':'all_archive_files'}, {'invented_option':True}])
def test_invalid_or_unsafe_scope_changes_are_rejected(value):
    with pytest.raises(ValidationError):
        BUConfig.model_validate(value)
