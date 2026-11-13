"""APK-owned library namespaces and retained unavailable context roots."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import pytest
from androserum.facts.context_heap import ContextHeapConfig,ContextHeapReport,entry_for,extend_context_heap,verify_context_heap
from androserum.facts.heap_flow import extract_heap
from androserum.facts.identity import canonical_json
ROOT=Path(__file__).resolve().parents[2]
def read(result,entry):return result.blobs[result.entry_digests[entry]]
@pytest.fixture(scope='module')
def context_actual(tmp_path_factory):
    sys.path.insert(0,str(ROOT/'scripts'))
    from build_local_fixture import main
    out=tmp_path_factory.mktemp('root-coverage')
    main(source=ROOT/'tests/fixtures/context_roots',output=out,label='missing-context-root')
    base=extract_heap(out/'valid.apk')
    return out,None,base

def test_apk_library_namespace_is_exported_and_missing_native_root_is_retained(context_actual):
    _,_,base=context_actual
    from androserum.facts.call_flow import _inputs
    flows,methods,_,_=_inputs(base.facts,lambda e:read(base,e))
    signature='Ljavax/androserum/LibraryOwned;->passthrough(Ljava/lang/String;)Ljava/lang/String;'
    native='Ljavax/androserum/LibraryOwned;->unsupportedNative(Ljava/lang/String;)Ljava/lang/String;'
    assert signature in {m.signature for m in methods.values()}
    config=ContextHeapConfig(root_signatures=[signature,native])
    result=extend_context_heap(deepcopy(base),config)
    refs={e.signature:e.id for e in result.facts.elements if e.kind=='method' and e.is_definition}
    good=ContextHeapReport.model_validate_json(read(result,entry_for(refs[signature])))
    missing=ContextHeapReport.model_validate_json(read(result,entry_for(refs[native])))
    assert good.state=='complete' and good.projection
    assert missing.state=='unavailable' and missing.projection is None
    reason=json.loads(missing.reason)
    assert reason['body_status']=='native' and reason['analysis_started'] is False
    assert any(s['issue_code']=='java_body_not_applicable' for s in reason['upstream_statuses'])
    assert len(result.summary['context_heap']['methods'])==2
    assert verify_context_heap(result.facts,lambda e:read(result,e))['relations']>0
    corrupt=deepcopy(result)
    data=missing.model_dump(mode='json');data['reason']='invented completion'
    raw=canonical_json(data).encode();digest=hashlib.sha256(raw).hexdigest()
    corrupt.blobs[digest]=raw;corrupt.entry_digests[entry_for(refs[native])]=digest
    with pytest.raises(ValueError,match='replay mismatch'):
        verify_context_heap(corrupt.facts,lambda e:read(corrupt,e))


def test_nonexistent_context_root_is_rejected_instead_of_invented(context_actual):
    _,_,base=context_actual
    with pytest.raises(ValueError,match='absent from APK definitions'):
        extend_context_heap(deepcopy(base),ContextHeapConfig(root_signatures=['Labsent/Owner;->noSuchMethod()V']))


def test_export_budget_omission_preserves_declared_root_and_original_truncation(context_actual):
    from androserum.facts.java_backend import JavaConfig
    out,_,_=context_actual
    base=extract_heap(out/'valid.apk',java_config=JavaConfig(max_methods=1))
    signature='Ljavax/androserum/LibraryOwned;->passthrough(Ljava/lang/String;)Ljava/lang/String;'
    result=extend_context_heap(base,ContextHeapConfig(root_signatures=[signature]))
    ref=next(e.id for e in result.facts.elements if e.kind=='method' and e.is_definition and e.signature==signature)
    item=ContextHeapReport.model_validate_json(read(result,entry_for(ref)))
    reason=json.loads(item.reason)
    assert item.state=='unavailable' and item.projection is None
    assert reason['body_status']=='available' and reason['analysis_started'] is False
    assert any(s['state']=='truncated' and s['issue_code']=='java_method_not_completed' for s in reason['upstream_statuses'])
    assert result.summary['context_heap']['counts']=={'unavailable':1}
    assert verify_context_heap(result.facts,lambda e:read(result,e))['relations']==0
