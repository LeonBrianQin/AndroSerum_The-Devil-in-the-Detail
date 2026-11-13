"""Source-accounting and real-APK matching acceptance for the Method catalog."""
import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import patch

from androserum.facts.identity import sha256_file
from androserum.facts.sapi import load_catalog, match_sapi
from androserum.facts.sapi_multisource import compile_multisource
from androserum.facts.store import FactView


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--prepared', type=Path, action='append', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    catalog_root = args.catalog.parent if args.catalog.is_file() else args.catalog
    catalog = load_catalog(catalog_root)
    config = catalog['import_config']
    # Prove replay does not silently depend on original source file locations.
    original_read = Path.read_bytes
    attempted_original_reads = []
    original_paths = {Path(s['path']).resolve() for s in config['sources']+config['api_bases']}

    def archive_only(path):
        if path.resolve() in original_paths:
            attempted_original_reads.append(str(path))
            raise AssertionError('Replay accessed an original acquisition path')
        return original_read(path)

    with patch.object(Path, 'read_bytes', archive_only):
        assert load_catalog(catalog_root) == catalog
    resources = {s['sha256']: (catalog_root/'sources'/s['sha256']).read_bytes() for s in config['sources']+config['api_bases']}
    corrupted = dict(resources)
    corrupted[config['sources'][0]['sha256']] = b'forged annotation resource'
    try:
        compile_multisource(config, corrupted)
    except ValueError:
        checksum_rejected = True
    else:
        raise AssertionError('Changed original resource was accepted')
    entries = {x['signature']: x for x in catalog['entries']}
    phone = entries['Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;']
    phone_families = {x['family'] for x in phone['origins']}
    assert {'sdk_annotations', 'pscout_published', 'axplorer_maps', 'flowdroid_tagged'} <= phone_families
    assert len({x['signature'] for x in catalog['entries']}) == len(catalog['entries'])
    sink_only = [x for x in catalog['entries'] if x['roles'] == ['sink']]
    assert sink_only and all(not x['anchor'] for x in sink_only)
    assert all(x['anchor'] == bool(set(x['roles']) & {'source','crypto_operation','permission_operation'}) for x in catalog['entries'])
    sms = entries['Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/app/PendingIntent;Landroid/app/PendingIntent;)V']
    assert sms['anchor'] and 'source' not in sms['roles']
    constructor = entries['Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V']
    assert constructor['anchor'] and 'crypto_operation' in constructor['roles']
    jca = next(x for x in catalog['source_status'] if x['family'] == 'crypto_jca')
    assert len(jca['summary']['specs']) == 51
    assert all(x['state'] == 'imported' for x in jca['summary']['specs'])
    assert not any(x['family'] == 'crypto_jca' for x in catalog['issues'])
    assert all(x['state'] == 'blocked_invalid_upstream_signature' and x['family'] == 'flowdroid_tagged' for x in catalog['issues'])
    assert all(not o['metadata'].get('constraints_order_predicates_evaluated', False)
               for e in catalog['entries'] for o in e['origins'] if o['family'] == 'crypto_jca')
    samples = []
    for index, prepared_file in enumerate(args.prepared):
        prepared = json.loads(prepared_file.read_text('utf-8-sig'))
        with FactView(prepared['snapshot']) as view:
            facts = view.export_bundle()
        assert facts.run.apk_sha256 == prepared['apk_sha256']
        actual = match_sapi(facts, catalog)
        path = args.output/f'sample-{index}-actual-matches.json'
        path.write_text(json.dumps(actual, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
        records = {x.id:x for x in facts.elements}
        rows=[]
        for match in actual['matches']:
            rows.append({'callsite_ref': match['callsite_ref'],
                'method_signature': records[match['method_ref']].signature,
                'context_ref': match['context_ref'], 'endpoint_status': match['endpoint_status'],
                'routes': match['routes'], 'source_families': sorted({o['family'] for e in match['catalog_entries'] for o in e['origins']}),
                'evidence_origins': [{'signature':e['signature'],'roles':e['roles'],
                    'origin_count':len(e['origins']), 'versions':sorted({o['version'] for o in e['origins']})} for e in match['catalog_entries']]})
        samples.append({'prepared':str(prepared_file),'prepared_sha256':sha256_file(prepared_file),
            'snapshot':prepared['snapshot'],'source_run_ref':facts.run.run_id,'apk_sha256':prepared['apk_sha256'],
            'physical_matched_calls':len({m['callsite_ref'] for m in actual['matches']}),
            'context_match_records':len(actual['matches']),
            'family_actual_match_counts':dict(Counter(f for r in rows for f in r['source_families'])),
            'match_file':str(path),'match_file_sha256':sha256_file(path),'matches':rows,
            'no_runtime_or_maliciousness_inference':all(m['maliciousness_inferred'] is False for m in actual['matches'])})
    all_actual_families = {f for s in samples for f in s['family_actual_match_counts']}
    assert {'sdk_annotations','pscout_published','axplorer_maps','flowdroid_tagged','crypto_jca'} <= all_actual_families
    result={'schema_version':'method-SAPI-acceptance.v1','catalog':str(catalog_root),
        'catalog_sha256':sha256_file(catalog_root/'catalog.json'),'catalog_id':catalog['catalog_id'],
        'decision':'source_adapters_and_actual_matching_pass; pinned_invalid_upstream_lines_remain_blocked',
        'all_five_families_have_imports_and_actual_APK_matches':True,
        'source_status':catalog['source_status'],'blocked_items':catalog['issues'],
        'catalog_entries':len(catalog['entries']),'origin_count':sum(len(e['origins']) for e in catalog['entries']),
        'signature_dedup_keeps_origins':True,'four_source_phone_entry_origin_count':len(phone['origins']),
        'direct_annotation_vs_Javadoc_delegation':'New catalog SDK roles are actual external method annotations; earlier Javadoc/delegation catalogs remain separate and unchanged.',
        'SAPI_sink_and_propagation_roles_distinguished':True,'sink_only_nonanchors':len(sink_only),
        'full_JCA_spec_count':51,'all_JCA_spec_input_items_accounted':True,
        'SMS_is_permission_operation_and_sink_not_taint_source':True,'new_SecretKeySpec_constructor_anchor':True,
        'reload_without_original_resource_reads':not attempted_original_reads,
        'corrupted_original_resource_rejected':checksum_rejected,
        'multi_source_catalog_complete':catalog['multi_source_catalog_complete'],
        'samples':samples,'new_LLM_calls':0,'APK_executed':False,'old_snapshots_or_catalogs_modified':False,
        'scope_limit':'Actual matching uses immutable prior fact snapshots. This verifies the SAPI import/match interface, not new whole-APK BU coverage or model mining.'}
    (args.output/'acceptance.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'path':str(args.output/'acceptance.json'),'sha256':sha256_file(args.output/'acceptance.json'),
        'actual_APK_matches':[(s['apk_sha256'],s['physical_matched_calls'],s['family_actual_match_counts']) for s in samples]}))


if __name__=='__main__':
    main()
