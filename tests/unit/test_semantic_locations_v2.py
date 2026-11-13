"""Versioned location cleaning preserves actual behavior semantics and v1."""
from copy import deepcopy
import json
from pathlib import Path
import pytest

from androserum.encoding.models import EncodingConfig
from androserum.facts.identity import filesystem_path
from androserum.pipeline.encoding import serialize_reviewed
from androserum.pipeline.semantic_v2 import ReviewedProjectorV2,LOCATOR


def clean(text):
    projector=object.__new__(ReviewedProjectorV2);projector.internal_names=set();projector.class_names=set();projector.free_text_audit=[]
    return projector.clean(text),projector.free_text_audit


@pytest.mark.parametrize('a,b',[
    ('unit:226','unit:9999'),('Jimple unit 230','Jimple unit 777'),
    ('DEX offset 0x1234','DEX offset 0xabcd'),('code+0x1234','code+0xabcd'),
    ('goto label226','goto label999'),
    ('\u4f4d\u4e8eunit:226\u5904','\u4f4d\u4e8eunit:9999\u5904'),('goto  label226','goto\tlabel999'),
])
def test_supported_locator_renumbering_has_identical_semantic_input_and_distinct_audit(a,b):
    first,old=clean('Conditional transfer at '+a+' with unknown caller.');second,new=clean('Conditional transfer at '+b+' with unknown caller.')
    assert first==second and old!=new and not LOCATOR.search(first)
    assert old[0]['original'].endswith('with unknown caller.') and old[0]['locator_spans']


def test_semantic_numeric_values_ranges_conditions_direction_and_purpose_survive():
    text='If count > 0, copy buffer[0:226] to output[230:512] only after success; use mask 0xff and port 226, 24 kHz, then reverse direction on failure.'
    assert clean(text)[0]==text
    changed=text.replace('count > 0','count >= 1').replace('port 226','port 227')
    assert clean(text)[0]!=clean(changed)[0]
    assert clean('goto  label226 if count > 0')[0]=='goto [program location in audit] if count > 0'


def test_default_remains_v1_and_only_supported_versions_are_accepted():
    assert EncodingConfig().serializer_version=='bc-semantics.v1'
    assert EncodingConfig(serializer_version='bc-semantics.v2').revision==EncodingConfig().revision
    with pytest.raises(ValueError):EncodingConfig(serializer_version='bc-semantics.v3')


def test_retained_encoder_cannot_bypass_frozen_v2_policy(tmp_path):
    from androserum.pipeline.analyze import _query_encoder_config
    (tmp_path/'config.json').write_text(json.dumps(EncodingConfig().model_dump(mode='json')))
    assert _query_encoder_config({},tmp_path).serializer_version=='bc-semantics.v1'
    frozen={'query_encoding_config':EncodingConfig(serializer_version='bc-semantics.v2').model_dump(mode='json')}
    with pytest.raises(ValueError,match='round-frozen'):_query_encoder_config(frozen,tmp_path)
    (tmp_path/'config.json').write_text(json.dumps(frozen['query_encoding_config']))
    assert _query_encoder_config(frozen,tmp_path).serializer_version=='bc-semantics.v2'


def test_actual_migration_v1_keeps_baseline_while_v2_removes_free_text_units():
    root=filesystem_path('artifacts/method-live-20261028/samples/migration-816e49')
    if not (root/'program-freeze-result.json').exists():pytest.skip('Actual retained trial unavailable')
    freeze=filesystem_path(json.loads((root/'program-freeze-result.json').read_text())['freeze'])
    entries=json.loads((freeze/'approved-pool.json').read_text())['entries']
    entry=next(e for e in entries if 'unit:' in json.dumps(e['bc']) or any('unit:' in json.dumps(a) for a in e['actions'].values()))
    old=serialize_reviewed(entry);new=serialize_reviewed(entry,EncodingConfig(serializer_version='bc-semantics.v2'))
    assert LOCATOR.search(old['text']) and not LOCATOR.search(new['text'])
    assert old['projection']['execution']==new['projection']['execution']=='possible only'
    assert old['projection']['relations']==new['projection']['relations']
    assert old['projection']['conditions']==new['projection']['conditions']
    assert new['audit']['free_text_serialization']['fields']
    mutated=deepcopy(entry)
    def rename(value):
        if isinstance(value,str):return __import__('re').sub(r'unit:\d+','unit:9999',value)
        if isinstance(value,list):return [rename(v) for v in value]
        if isinstance(value,dict):return {k:rename(v) for k,v in value.items()}
        return value
    mutated['bc']=rename(mutated['bc']);mutated['actions']=rename(mutated['actions'])
    assert serialize_reviewed(mutated,EncodingConfig(serializer_version='bc-semantics.v2'))['text']==new['text']
