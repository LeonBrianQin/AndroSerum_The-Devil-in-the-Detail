"""Native summary configuration/resource identity and explicit failure policy."""
from copy import deepcopy
import json

import pytest

from androserum.facts import flow_summaries as summaries
from androserum.facts.selected_flow import FlowConfig,MethodFlowConfig,SummaryFlowConfig,load_flow_config


def test_legacy_configurations_remain_explicitly_without_summaries():
    assert FlowConfig().taint_wrapper=='none'
    assert MethodFlowConfig(entry_methods=['La;->run()V']).taint_wrapper=='none'
    assert 'summary_resource_id' not in FlowConfig().model_dump()
    assert type(load_flow_config(FlowConfig().model_dump())) is FlowConfig
    assert type(load_flow_config(MethodFlowConfig(entry_methods=['La;->run()V']).model_dump())) is MethodFlowConfig


def test_v3_pins_real_manual_resources_and_provider():
    config=SummaryFlowConfig();policy,assets=summaries.summary_request(config)
    manifest=summaries._verify_bundle(assets[summaries.MANIFEST_ENTRY],assets[summaries.JAR_ENTRY])
    assert len(policy['xml_files'])==348 and manifest['class_summary_XML_count']==347
    assert manifest['metadata_XML_count']==1
    assert policy['jar_sha256']==summaries.JAR_SHA256
    assert load_flow_config(config.model_dump())==config


def test_missing_resource_refuses_loading_without_silently_disabling(tmp_path,monkeypatch):
    monkeypatch.setattr(summaries,'RESOURCE',tmp_path)
    with pytest.raises(FileNotFoundError):summaries.summary_request(SummaryFlowConfig())
    policy,assets=summaries.summary_request(SummaryFlowConfig(taint_wrapper='none'))
    assert policy['mode']=='none' and assets=={}


def test_native_bundle_tamper_is_rejected():
    _,assets=summaries.summary_request(SummaryFlowConfig())
    with pytest.raises(ValueError,match='identity differs'):
        summaries._verify_bundle(assets[summaries.MANIFEST_ENTRY],assets[summaries.JAR_ENTRY]+b'changed')


def test_entry_scope_cannot_mix_android_and_explicit_method_claims():
    with pytest.raises(ValueError):SummaryFlowConfig(entry_methods=['La;->run()V'])
    with pytest.raises(ValueError):SummaryFlowConfig(entry_scope='conditional_explicit_methods_not_android_reachability')
    with pytest.raises(ValueError):SummaryFlowConfig(entry_scope='conditional_explicit_methods_not_android_reachability',entry_methods=['La;->run()V'],callbacks=True)


def test_worker_must_really_confirm_loaded_provider_and_no_fallback():
    config=SummaryFlowConfig();policy,assets=summaries.summary_request(config)
    manifest=json.loads(assets[summaries.MANIFEST_ENTRY])
    loaded=[x['name'][:-4] for x in manifest['xml_files'] if x['name']!='SummaryMetaData.xml']
    raw={'state':'complete','summary_wrapper':{'state':'loaded','mode':'flowdroid_summary','resource_id':summaries.RESOURCE_ID,
        'manifest_sha256':summaries.MANIFEST_SHA256,'provider':manifest['provider'],'wrapper':manifest['wrapper'],
        'provider_loading_errors':False,'fallback_wrapper':None,'loaded_classes':loaded}}
    summaries.validate_summary_worker(raw,config,{'summary_config':policy},assets.__getitem__)
    for field,value in [('state','not_confirmed'),('loaded_classes',[]),('fallback_wrapper','invented_wrapper'),('provider_loading_errors',True)]:
        changed=deepcopy(raw);changed['summary_wrapper'][field]=value
        with pytest.raises(ValueError,match='not fully loaded'):
            summaries.validate_summary_worker(changed,config,{'summary_config':policy},assets.__getitem__)


def test_disabled_control_cannot_claim_loaded_or_applied_summaries():
    config=SummaryFlowConfig(taint_wrapper='none');policy,_=summaries.summary_request(config)
    raw={'state':'complete','summary_wrapper':{'mode':'none','state':'disabled','resource_id':summaries.RESOURCE_ID,
        'manifest_sha256':summaries.MANIFEST_SHA256,'applications':[],'loaded_classes':[]}}
    summaries.validate_summary_worker(raw,config,{'summary_config':policy},lambda _:None)
    raw['summary_wrapper']['state']='loaded'
    with pytest.raises(ValueError,match='Disabled wrapper'):
        summaries.validate_summary_worker(raw,config,{'summary_config':policy},lambda _:None)
