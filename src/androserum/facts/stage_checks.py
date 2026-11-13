"""Concrete semantic gates used by independent CLI stage acceptance."""
import json


def select(facts,caller,target):
    records={x.id:x for x in facts.elements}
    return [x.id for x in facts.elements if x.kind=='instruction' and x.operation=='invoke' and ('->'+caller+'(') in records[x.position.method_ref].signature
        and x.declared_target and ('->'+target+'(') in x.declared_target.signature]


def check_stage(stage,view,check,report,output):
    facts=view.export_bundle()
    if stage=='operations':
        from androserum.facts.operations import ENTRY
        r=json.loads(view.read_evidence(ENTRY));ref=select(facts,'guarded','jointSink')[0];report['query_refs']=[ref]
        q=view.operation_evidence([ref])['operations'][0]
        check('operation source is current device-ID call with path',any(x['metadata'].get('signature')=='Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;' and x['path'] for x in q['arguments'][0]['candidates']))
        check('control association explicitly deferred',q['conditions']['state']=='not_started' and not q['conditions']['absence_is_unconditional'])
        fixed=view.operation_evidence(select(facts,'negative','negativeSink'))['operations'][0]
        check('fixed argument and static/void nonapplicability',fixed['receiver']['value_status']==fixed['result']['value_status']=='not_applicable' and fixed['arguments'][0]['candidates'][0]['value']['value']=='fixed')
        check('finite effects preserve objects rule and unknown key',any(x['property']=='extra' and x['key']=='payload' and x['object'] for x in r['effects']) and any(x['property']=='extra' and x['key'] is None and x['issues'] for x in r['effects']))
        report['coverage_notes']={'engineering':'passed','operations':len(r['operations']),'finite_effects':len(r['effects']),'control_association':'pending_F6'}
    elif stage=='control':
        first=select(facts,'earlyReturn','negativeSink')[0];second=select(facts,'guarded','jointSink')[0];report['query_refs']=[first,second]
        q=view.control_evidence([first,second])['operations']
        check('early return and guarded send require true local boolean',all(x['conditions'] and all(c['record']['expected_value']['value'] is True for c in x['conditions']) for x in q))
        check('judgment source is a recorded parameter',any(x['root']['kind']=='parameter' for c in q[0]['conditions'] for s in c['analysis']['source_evidence'] for x in s.get('roots',[])))
        merged=view.operation_evidence(select(facts,'bothBranches','negativeSink'))['operations']
        row=next(x for x in merged if len(x['arguments'][0]['candidates'])==2)
        check('F5 branch candidates retain separate local condition scopes',all(c['local_conditions']['source_scopes'] for c in row['arguments'][0]['candidates']) and not row['conditions']['refs'])
        check('control covers only declared normal-completion scope',view.manifest.coverage['control']=='partial' and view.manifest.coverage['events']=='not_started')
        report['coverage_notes']={'engineering':'passed','scope':'explicit_if_normal_completion','exceptions_and_global_paths':'not complete'}
    elif stage=='events':
        from androserum.facts.events import ENTRY
        r=json.loads(view.read_evidence(ENTRY));sink=select(facts,'guarded','jointSink')[0]
        sends=select(facts,'guarded','startActivity')+select(facts,'unknownPayload','startActivity');report['query_refs']=[sink,*sends]
        q=view.event_evidence([sink])['operations'][0]
        check('selected callback has possible two-call background',len(q['background'])==1 and q['background'][0]['root']['kind']=='click' and len(q['background'][0]['call_background']['call_path_refs'])==2)
        check('registration not treated as immediate execution',not q['registration_implies_immediate_execution'] and not q['execution_asserted'])
        explicit=next(x for x in r['icc'] if x['callsite_ref']==sends[0]);unknown=next(x for x in r['icc'] if x['callsite_ref']==sends[1])
        check('target and payload bindings independently justified',explicit['targets'] and explicit['payloads'] and explicit['dominance_evidence'])
        check('known target with unknown payload retained',unknown['targets'] and unknown['payload_state']=='unknown' and not unknown['payloads'])
        check('actual FlowDroid callback and event model agree',r['flow_joint_validation']['state']=='selected_entry_callback_models_agree')
        check('all event models remain partial',view.manifest.coverage['events']=='partial' and r['unsupported'])
        report['coverage_notes']={'engineering':'passed','event_roots':len(r['roots']),'icc_sites':len(r['icc']),'flow_callback_joint':r['flow_joint_validation'],'unsupported':r['unsupported']}
    elif stage=='joint':
        from androserum.facts.sapi import SapiImportConfig,import_catalog,load_catalog,match_sapi
        from pathlib import Path
        from androserum.facts.identity import sha256_file
        import subprocess,sys
        root=Path(__file__).resolve().parents[3]
        config=SapiImportConfig.model_validate_json((root/'configs/sapi-expanded.example.json').read_text('utf-8'))
        catalog=import_catalog(config,output/'sapi')
        report['sapi']={'path':(output/'sapi').relative_to(root).as_posix(),'catalog_id':catalog['catalog_id'],'entries':len(catalog['entries']),
            'anchors':sum(x['anchor'] for x in catalog['entries']),'crypto_anchors':sum('crypto_operation' in x['roles'] for x in catalog['entries']),
            'issues':len(catalog['issues']),'pending_sources':catalog['pending_sources']}
        source=select(facts,'guarded','getDeviceId')[0];sink=select(facts,'guarded','jointSink')[0]
        sends=select(facts,'guarded','startActivity')+select(facts,'unknownPayload','startActivity');refs=[source,sink,*sends];report['query_refs']=refs
        q=view.joint_evidence(refs,load_catalog(output/'sapi'),limit=5000)
        check('joint selected source is a real catalog match',len(q['sapi']['matches'])==1 and q['sapi']['matches'][0]['callsite_ref']==source)
        sink_row=next(x for x in q['operations'] if x['operation_ref']==sink)
        check('joint sink retains current source and cross-method storage path',any(x['metadata'].get('signature')=='Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;' and x['path'] for x in sink_row['arguments'][0]['candidates']))
        check('joint local true condition and parameter source available',next(x for x in q['control']['operations'] if x['operation_ref']==sink)['conditions'][0]['record']['expected_value']['value'] is True)
        check('joint callback background and actual callback flow agree',q['events']['flow_joint_validation']['state']=='selected_entry_callback_models_agree' and q['selected_flows'])
        check('joint explicit ICC target/data with unknown-payload comparison',q['events']['operations'][2]['icc'][0]['payload_state']=='bound_sources' and q['events']['operations'][3]['icc'][0]['payload_state']=='unknown')
        check('joint support closure is complete within budget',not q['support']['truncated'] and not q['support']['missing_refs'] and q['support']['file_closure_complete'])
        check('joint is explicit evidence assembly not BU',not q['is_bu_extraction'] and not q['remaining_gaps']['full_program_coverage'])
        subprocess.run([sys.executable,'scripts/build_crypto_fixture.py'],cwd=root,check=True,capture_output=True)
        from androserum.facts.extractor import extract_apk
        crypto=extract_apk(root/'artifacts/fixtures/crypto/valid.apk');crypto_matches=match_sapi(crypto.facts,catalog)
        (output/'crypto-matches.json').write_text(json.dumps(crypto_matches,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        check('pinned JCA rules match six real compiled operations',len(crypto_matches['matches'])==6 and report['sapi']['crypto_anchors']==37)
        report['crypto_match_report']=(output/'crypto-matches.json').relative_to(root).as_posix()
        report['coverage_notes']={'engineering':'passed','coverage':'selected mechanisms only; all program capabilities partial','remaining_gaps':q['remaining_gaps']}
        (output/'joint-review.json').write_text(json.dumps(q,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    else:raise ValueError('Stage checker not implemented: '+stage)
