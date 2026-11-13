"""Source/sink/summary role separation for preparatory resource inventory only."""
import importlib.util
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('sapi_preparation',ROOT/'scripts/prepare_sapi.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_source_sink_both_and_unparsed_have_distinct_import_roles():
    entries,issues=module.classify_roles('''# comment
<example.A: java.lang.String source()> -> _SOURCE_
<example.A: void sink(java.lang.String)> -> _SINK_
<example.A: java.lang.String both(java.lang.String)> -> _BOTH_
<example.A: void none()> -> _NONE_
<unclassified raw line>
''')
    assert [x['anchor_candidate_after_normalization'] for x in entries]==[True,False,True,False]
    assert all(not x['formal_anchor'] for x in entries)
    assert entries[2]['roles']==['source','sink'] and len(issues)==1 and issues[0]['line']==6


def test_summary_and_callback_resources_are_not_automatic_anchor_sources():
    policy=json.loads((ROOT/'configs/sapi-source-policy.json').read_text('utf-8'))
    assert not policy['formal_anchor_catalog_ready']
    assert 'no_automatic_anchor' in policy['role_policy']['propagation_summary']
    assert 'no_automatic_anchor' in policy['role_policy']['callback_model']
    assert 'no_automatic_anchor' in policy['role_policy']['sink']
