"""Signature and provenance rules; synthetic text is not upstream API coverage."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil

import pytest

from androserum.facts.identity import fingerprint
from androserum.facts.sapi import SapiImportConfig,SapiSource,dalvik_signature,import_catalog,load_catalog


@pytest.mark.parametrize('raw,expected',[
    ('<android.telephony.TelephonyManager: java.lang.String getDeviceId()>','Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;'),
    ('<example.Outer$Inner: void <init>(long,java.lang.String[][],double)>','Lexample/Outer$Inner;-><init>(J[[Ljava/lang/String;D)V'),
    ('<example.Test: int[] f(byte[],boolean,char,short,float)>','Lexample/Test;->f([BZCSF)[I'),
    ('Lexample/Test;->x()V','Lexample/Test;->x()V')])
def test_full_signature_conversion(raw,expected):assert dalvik_signature(raw)==expected


@pytest.mark.parametrize('raw',['<example.Test: void broken)>','<example.Test: int <init>()>','<example.Test: void x(void)>','<example.Test: java.util.List<X> get()>'])
def test_invalid_or_ambiguous_signatures_are_not_repaired(raw):
    with pytest.raises(ValueError):dalvik_signature(raw)


def configuration(tmp_path):
    raw='''# Explicit synthetic import fixture
<example.Test: java.lang.String read()> android.permission.TEST -> _SOURCE_
<example.Test: void send(java.lang.String)> -> _SINK_
<example.Test: java.lang.String both()> -> _BOTH_
<example.Test: java.lang.String read()> -> _SOURCE_
<example.Test: void broken)> -> _SOURCE_
'''.encode()
    path=tmp_path/'rules.txt';path.write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
    return SapiImportConfig(sources=[SapiSource(source_id='synthetic-import-test-only',version=version,path=str(path),sha256=digest,resource_sha256=digest) for version in ['1','2']])


def test_merge_preserves_all_versions_lines_metadata_and_roles(tmp_path):
    config=configuration(tmp_path);catalog=import_catalog(config,tmp_path/'catalog')
    entries={x['signature']:x for x in catalog['entries']}
    read=entries['Lexample/Test;->read()Ljava/lang/String;']
    assert read['anchor'] and len(read['origins'])==4
    assert {x['version'] for x in read['origins']}=={'1','2'}
    assert any(x['metadata']=='android.permission.TEST' for x in read['origins'])
    assert not entries['Lexample/Test;->send(Ljava/lang/String;)V']['anchor']
    assert entries['Lexample/Test;->both()Ljava/lang/String;']['anchor']
    assert len(catalog['issues'])==2 and not catalog['multi_source_catalog_complete']
    assert load_catalog(tmp_path/'catalog')==catalog


def test_catalog_moves_without_original_source_path(tmp_path):
    config=configuration(tmp_path);before=import_catalog(config,tmp_path/'catalog')
    moved=tmp_path/'moved';shutil.copytree(tmp_path/'catalog',moved);Path(config.sources[0].path).unlink()
    assert load_catalog(moved)==before


def test_checksum_mismatch_and_unknown_formats_do_not_publish(tmp_path):
    config=configuration(tmp_path);config.sources[0].sha256='0'*64
    with pytest.raises(ValueError):import_catalog(config,tmp_path/'bad')
    assert not (tmp_path/'bad').exists()
    with pytest.raises(ValueError):SapiImportConfig.model_validate({'sources':[{'source_id':'x','version':'1','path':'x','sha256':'0'*64,'resource_sha256':'0'*64,'format':'propagation_summary'}]})
    with pytest.raises(ValueError):SapiImportConfig.model_validate({'schema_version':'sapi-import-config.v999','sources':[]})


@pytest.mark.parametrize('damage',['signature','anchor','source_bytes'])
def test_tampering_rejected_even_with_recomputed_catalog_id(tmp_path,damage):
    config=configuration(tmp_path);root=tmp_path/'catalog';catalog=import_catalog(config,root)
    if damage=='source_bytes':
        (root/'sources'/config.sources[0].resource_sha256).write_bytes(b'changed upstream input')
    else:
        if damage=='signature':catalog['entries'][0]['signature']='Lforged/Test;->x()V'
        else:catalog['entries'][0]['anchor']=not catalog['entries'][0]['anchor']
        catalog.pop('catalog_id');catalog['catalog_id']=fingerprint(catalog)
        (root/'catalog.json').write_text(json.dumps(catalog),encoding='utf-8')
    with pytest.raises(ValueError):load_catalog(root)
