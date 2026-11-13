"""Read-only replay of stored accepted proposals against their shown evidence."""
from pathlib import Path
import hashlib
import json
from androserum.facts.identity import filesystem_path,sha256_file,fingerprint
from androserum.mining.checker import check_proposal
from androserum.mining.ledger import Ledger
from androserum.mining.models import MiningConfig, CurrentMiningConfig
from androserum.mining.models import strict_model_schema
from androserum.mining.runner import load_catalog

# Exact hashes of the pre-amendment v2 policy. No archived Python is executed:
# current checks must replay every accepted state byte-for-byte. This permits
# evidence-only monotonic updates without discarding the old audit chain.
COMPATIBLE_V2_RULES={"checker.py":"6648efc4092f7638e3119b57aa2d81b03edc9a906ad52c5f3a457ba29624605d","verification.py":"bc4c5d9986fe67de926af665a5f11540f8188931a23238607a5552bd3ffe6d39","session.py":"a5f1df11d9205dfb6254ad4d02608e3270f0811418980c24e6f433eedfcaa177","runner.py":"5e0b7d047dead7e3279e28572577041ef48651c23912fa5cde15f5662d8822f6"}


# Known complete rule sets; archived Python is never executed. Every accepted state must replay identically.
COMPATIBLE_RULE_PROFILES=[{'assembly.py': '745d21fddefddf5f22c8ce43b85e5e91723223656f13fc24b8e5051340249e74', 'checker.py': '6648efc4092f7638e3119b57aa2d81b03edc9a906ad52c5f3a457ba29624605d', 'evidence.py': '0e78c76ade574cf07e1ac2f071634b671d7ce79bde1ef46660fcb9ba3721408e', 'ledger.py': 'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715', 'models.py': 'bf56a1e6becab4a8efd3feb627bd8aba4fd2f21067e3e9e3e9210c38812c585b', 'prompt.txt': '7f00ea84a91abefa915130fd5340659d6e314088315a4e4e21bea2e97ba326cf', 'providers.py': '0ec250452bc020bc376ae464363f483b02dc42434871fe494715cf46c758f378', 'runner.py': '5e0b7d047dead7e3279e28572577041ef48651c23912fa5cde15f5662d8822f6', 'session.py': 'a5f1df11d9205dfb6254ad4d02608e3270f0811418980c24e6f433eedfcaa177', 'verification.py': 'bc4c5d9986fe67de926af665a5f11540f8188931a23238607a5552bd3ffe6d39', '__init__.py': '75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a'}, {'assembly.py': '745d21fddefddf5f22c8ce43b85e5e91723223656f13fc24b8e5051340249e74', 'checker.py': '5e3ef57c664a17b36d653e2df5af106eff1f9c3bee406201b980b643dbc19453', 'evidence.py': '0e78c76ade574cf07e1ac2f071634b671d7ce79bde1ef46660fcb9ba3721408e', 'ledger.py': 'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715', 'models.py': 'bf56a1e6becab4a8efd3feb627bd8aba4fd2f21067e3e9e3e9210c38812c585b', 'prompt.txt': '7f00ea84a91abefa915130fd5340659d6e314088315a4e4e21bea2e97ba326cf', 'providers.py': '0ec250452bc020bc376ae464363f483b02dc42434871fe494715cf46c758f378', 'runner.py': '2daa92ec6df0f87ade8fd3587f14872889235bd4fb285821a6f96f68926e6a15', 'session.py': 'c923a7aa91cebb6b0c21a5087e9224498e9347ea6e89f9c7136c64291bc85dfa', 'verification.py': 'f54917a9a25fd5f21114705e1be32e7ca81e3f1cdf696e6f1707c90e66eadd1a', '__init__.py': '75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a'}]

COMPATIBLE_RULE_PROFILES.append({'assembly.py': 'b7fd21af3c9fc9186700c054699dd652cc9cea8c1f9318d06efdd54310d1cce7', 'checker.py': '5e3ef57c664a17b36d653e2df5af106eff1f9c3bee406201b980b643dbc19453', 'evidence.py': '7d8d6795b609aa042e9f8c4b91d851eee761edbace302361895aabbf4dea8bf8', 'ledger.py': 'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715', 'models.py': 'bf56a1e6becab4a8efd3feb627bd8aba4fd2f21067e3e9e3e9210c38812c585b', 'prompt.txt': '2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499', 'providers.py': '0ec250452bc020bc376ae464363f483b02dc42434871fe494715cf46c758f378', 'runner.py': '0c148890e6750c363b241a9c9946cd7606cace118329bc0c9f5a186c6dc24cef', 'session.py': 'dfb8fb3ef4c7f467949776a56dd7007c8d3dbedb1388dc9d3772f9029b5a63c5', 'verification.py': '2d88bb1e8ab7d10ef956a6e2d3b805a8a6e1f7bdd7d31af00f26452450bb80c3', '__init__.py': '75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a'})

# Exact pre-method-output profile. Replay still checks all historical proposals;
# the new optional endpoint role is absent from these old visible registries.
COMPATIBLE_RULE_PROFILES.append({"__init__.py":"75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a","assembly.py":"b7fd21af3c9fc9186700c054699dd652cc9cea8c1f9318d06efdd54310d1cce7","checker.py":"5e3ef57c664a17b36d653e2df5af106eff1f9c3bee406201b980b643dbc19453","evidence.py":"7d8d6795b609aa042e9f8c4b91d851eee761edbace302361895aabbf4dea8bf8","ledger.py":"ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715","models.py":"bf56a1e6becab4a8efd3feb627bd8aba4fd2f21067e3e9e3e9210c38812c585b","prompt.txt":"2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499","providers.py":"0ec250452bc020bc376ae464363f483b02dc42434871fe494715cf46c758f378","runner.py":"0c148890e6750c363b241a9c9946cd7606cace118329bc0c9f5a186c6dc24cef","session.py":"ffd6d12437fc2e43bbdebd0241ef2928ac6a88a84bcf3533d753268114c5e5eb","verification.py":"e6e46b8093c33cb610f654b85485f5099002e032cf24a2be6691091324c86c6f"})


# Exact policy before optional v2 FlowDroid scope metadata was carried into
# source_limits. v1 catalogs remain byte-identical and all proposals replay.
COMPATIBLE_RULE_PROFILES.append({"__init__.py":"75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a","assembly.py":"b7fd21af3c9fc9186700c054699dd652cc9cea8c1f9318d06efdd54310d1cce7","checker.py":"e6671571655089915e8ef9eb385b365e4af636c1b490f1463daa567e95b4497e","evidence.py":"ffcdd1bcc6be65e8581fb4b1fdc9c35ca96f2c58cff7ee2c6fe6c39f0064d901","ledger.py":"ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715","models.py":"bf56a1e6becab4a8efd3feb627bd8aba4fd2f21067e3e9e3e9210c38812c585b","prompt.txt":"2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499","providers.py":"0ec250452bc020bc376ae464363f483b02dc42434871fe494715cf46c758f378","runner.py":"0c148890e6750c363b241a9c9946cd7606cace118329bc0c9f5a186c6dc24cef","session.py":"ffd6d12437fc2e43bbdebd0241ef2928ac6a88a84bcf3533d753268114c5e5eb","verification.py":"34f8439a5731f3d90e8c00e6084c2fe1678f173d9f677c44349a1f46dcffa8af"})


# Exact pre-Method-consistency profile; historical proposals still replay.
COMPATIBLE_RULE_PROFILES.append({'assembly.py': 'b7fd21af3c9fc9186700c054699dd652cc9cea8c1f9318d06efdd54310d1cce7', 'checker.py': 'e6671571655089915e8ef9eb385b365e4af636c1b490f1463daa567e95b4497e', 'evidence.py': 'ffcdd1bcc6be65e8581fb4b1fdc9c35ca96f2c58cff7ee2c6fe6c39f0064d901', 'ledger.py': 'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715', 'models.py': 'bf56a1e6becab4a8efd3feb627bd8aba4fd2f21067e3e9e3e9210c38812c585b', 'prompt.txt': '2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499', 'providers.py': '0ec250452bc020bc376ae464363f483b02dc42434871fe494715cf46c758f378', 'runner.py': '060d6fd0097ba9ea0caaec0005d7346166168fc7b492913876b319cc68b7c916', 'session.py': 'cd2877f13e2539e0188e3b9aa5ccc19f08e31cf76452a05c7fd3f72ed9f39cba', 'verification.py': '4af60c641fd05231335c38113e894d17c8b5d967bd3d9dd0850b34563fc46adb', '__init__.py': '75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a'})


# Exact rules immediately before the clean-catalog continuation restoration.
# Historical Python is never executed; current checkers replay every accepted
# state, typed decision, binding, condition and displayed field unchanged.
COMPATIBLE_RULE_PROFILES.append({'__init__.py':'75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a',
    'assembly.py':'c5a3151b2939aa92bf8563d91b6b0323fcfad6d272ec516c90ffcd4ef89ddace',
    'checker.py':'31277b9151709caf4ce8039a823baa16822f1e41665fda9d651bbce2e0e5d331',
    'evidence.py':'ffcdd1bcc6be65e8581fb4b1fdc9c35ca96f2c58cff7ee2c6fe6c39f0064d901',
    'ledger.py':'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715',
    'models.py':'a83213fc17b5dd294acb0990c90085de1739df7400e314adb178384a8501dd3d',
    'prompt.txt':'2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499',
    'providers.py':'d949f6f6bafe8a4339d8324a4deead3294403e317a423587b1203d40df2e65b1',
    'runner.py':'742344ed77bfbd0c1ad71e78d0f582142addc89dd14d3e8f5aa1b90502b954df',
    'session.py':'354c27f963c4e1d37835c3ed722e996d6bfa12bb71502175d7ae165c256f974c',
    'verification.py':'4855758030e28f87fb7ccb72a50205055b8e11bc4655ec5b3111833c34c53ba1'})


# Exact source profile before opt-in lossless bundle accounting. Current
# checkers still replay every accepted state; archived Python is not executed.
COMPATIBLE_RULE_PROFILES.append({'assembly.py': 'c5a3151b2939aa92bf8563d91b6b0323fcfad6d272ec516c90ffcd4ef89ddace', 'checker.py': '31277b9151709caf4ce8039a823baa16822f1e41665fda9d651bbce2e0e5d331', 'evidence.py': 'ffcdd1bcc6be65e8581fb4b1fdc9c35ca96f2c58cff7ee2c6fe6c39f0064d901', 'ledger.py': 'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715', 'models.py': 'a83213fc17b5dd294acb0990c90085de1739df7400e314adb178384a8501dd3d', 'prompt.txt': '2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499', 'providers.py': 'd949f6f6bafe8a4339d8324a4deead3294403e317a423587b1203d40df2e65b1', 'runner.py': '742344ed77bfbd0c1ad71e78d0f582142addc89dd14d3e8f5aa1b90502b954df', 'session.py': '0e812cbbf891bc4c994467b7d5c524226aecfea747842fe16f23d9a0f44731a5', 'verification.py': 'f5bd1828f69622c9c07ed36b11cc8d74da952b7fc64edf9f5afa410e3859ede1', '__init__.py': '75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a'})

# Exact pre-scoped-role adapter rules; replay still uses current checks and every accepted state.
COMPATIBLE_RULE_PROFILES.append({'assembly.py': '58035f3bd18b1b90ee7bc5b18d71a6747030e5e8982850c3591d159b46bec7a1', 'checker.py': '31277b9151709caf4ce8039a823baa16822f1e41665fda9d651bbce2e0e5d331', 'evidence.py': 'ffcdd1bcc6be65e8581fb4b1fdc9c35ca96f2c58cff7ee2c6fe6c39f0064d901', 'ledger.py': 'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715', 'models.py': 'a83213fc17b5dd294acb0990c90085de1739df7400e314adb178384a8501dd3d', 'providers.py': 'd949f6f6bafe8a4339d8324a4deead3294403e317a423587b1203d40df2e65b1', 'runner.py': '0b05623d5ae74011c1e15517b0de8e1d67a58c39ac4942ca1de75b9244a4a9b8', 'session.py': 'ff1ca35dcde964248e7b46497f72f63269478596d9bfef4008268ea957d94f41', 'verification.py': '94887aaf21597915bc284c90abc85c511fcf5b2021c4b7ee0d41362feb02671c', '__init__.py': '75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a', 'prompt.txt': '2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499'})

# Exact frozen batch20 profile; every accepted proposal still replays.
COMPATIBLE_RULE_PROFILES.append({'assembly.py': '58035f3bd18b1b90ee7bc5b18d71a6747030e5e8982850c3591d159b46bec7a1', 'checker.py': '31277b9151709caf4ce8039a823baa16822f1e41665fda9d651bbce2e0e5d331', 'evidence.py': 'ffcdd1bcc6be65e8581fb4b1fdc9c35ca96f2c58cff7ee2c6fe6c39f0064d901', 'ledger.py': 'ade0847a3ce4aff44a8d7c84bce9757acd7c1dd7bfb5c5d5796ee7951ef7b715', 'models.py': 'a83213fc17b5dd294acb0990c90085de1739df7400e314adb178384a8501dd3d', 'prompt.txt': '2bcbd0984d9abb741570b8d0b0d30ff8ca47fdb51cde7aad515b8aa1a5efa499', 'providers.py': 'd949f6f6bafe8a4339d8324a4deead3294403e317a423587b1203d40df2e65b1', 'runner.py': '179686e2e2a6af3e9d2480e84c04b2cc6eb8b748a9119ac61a56849e43ff621f', 'session.py': '7d878893e033f9247feec126065db9556692939b511f61f5eaa3f78f43aabf70', 'verification.py': '1a287e319ca5964575ed9bd7bc9f9e05d0ff6324759712cc19b1d2438b94525e', '__init__.py': '75e5b4a20f06610e87f324b27c4cd0ad2d67586a5201cae769118720ef05669a'})

def verify_mining(path,package,view):
    info=json.loads((filesystem_path(path)/'run.json').read_text('utf-8'))
    profile=info['identity']['source'].get('packing_profile')
    catalog=load_catalog(package,view,info['identity']['selected_bu_ids'],packing_profile=profile)
    return verify_package(path,catalog,view)


def verify_package(path,catalog,view):
    root=filesystem_path(path)
    manifest=json.loads((root/'manifest.json').read_text('utf-8'))
    if manifest['schema_version']!='behavior-mining-manifest.v1':raise ValueError('Unsupported mining package')
    for entry,item in manifest['files'].items():
        dest=filesystem_path(root/entry)
        if not dest.is_relative_to(root) or sha256_file(dest)!=item['sha256'] or dest.stat().st_size!=item['bytes']:
            raise ValueError('Mining file hash/inventory mismatch')
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual!=set(manifest['files'])|{'manifest.json'}:raise ValueError('Mining file inventory differs')
    info=json.loads((root/'run.json').read_text('utf-8'));report=json.loads((root/'report.json').read_text('utf-8'))
    if info['identity']!=manifest['identity'] or report['identity']!=info['identity']:raise ValueError('Mining identity mismatch')
    if catalog.identity!=info['identity']['source']:raise ValueError('Mining source APK/snapshot/package mismatch')
    if info['identity']['source'].get('packing_profile'):
        from androserum import mining_packing,mining_storage
        auxiliary={'mining_packing.py':Path(mining_packing.__file__),'mining_storage.py':Path(mining_storage.__file__)}
        if catalog.identity.get('packing_profile')=='lossless-scoped-compact.v3':
            from androserum import mining_catalog,mining_packing_v3
            auxiliary.update({'mining_catalog.py':Path(mining_catalog.__file__),
                              'mining_packing_v3.py':Path(mining_packing_v3.__file__)})
        expected={name:sha256_file(file) for name,file in auxiliary.items()}
        if info.get('packing_auxiliary_sha256')!=expected:
            raise ValueError('Packed input/storage auxiliary source version differs')
        if any(sha256_file(root/'packing-rules'/name)!=digest for name,digest in expected.items()):
            raise ValueError('Packed input/storage archived rule differs')
    if {b:fingerprint(u['model_visible']) for b,u in catalog.units.items()}!=info['source_visible_sha256']:raise ValueError('Source visible evidence differs')
    expected_source={'identity':catalog.identity,'units':{b:{'model_visible':u['model_visible'],'extraction_status':u['extraction_status']} for b,u in catalog.units.items()}}
    if json.loads((root/'source-visible.json').read_text('utf-8'))!=expected_source:raise ValueError('Source projection differs from current BU package')
    compatible=[]
    current_files=[p for p in Path(__file__).parent.iterdir() if p.suffix in {'.py','.txt'}]
    archived_rules={p.name:sha256_file(root/'rules'/p.name) for p in current_files}
    recognized=archived_rules in COMPATIBLE_RULE_PROFILES
    for path in Path(__file__).parent.iterdir():
        if path.suffix in {'.py','.txt'} and sha256_file(root/'rules'/path.name)!=sha256_file(path):
            archived=sha256_file(root/'rules'/path.name)
            if info['identity'].get('mining_version')!='behavior-mining.v2' or not recognized:
                raise ValueError('Use the matching mining rule version to verify this historical ledger')
            compatible.append({'file':path.name,'archived_sha256':archived,'current_sha256':sha256_file(path)})
    config=(CurrentMiningConfig if info['config'].get('schema_version')=='mining-config.v2' else MiningConfig).model_validate(info['config'])
    if info.get('query_evidence_protocol') in {'typed_context.v1','typed_context.v2'}:
        for name,digest in info['query_rule_sha256'].items():
            current=Path(__file__).parents[1]/'facts'/name
            if sha256_file(current)!=digest or sha256_file(root/'query-rules'/name)!=digest:
                raise ValueError('Use the matching controlled query/admission rule version for this mining run')
    if report.get('current_fact_queries'):
        from androserum.facts.queries import verify_query_report
        if info.get('query_delivery_policy'):
            from androserum.facts.query_reuse import verify_reuse_report,POLICY
            if info['query_delivery_policy']!=POLICY:raise ValueError('Unsupported query reuse policy')
            verify_reuse_report(report['current_fact_queries'],view)
        else:verify_query_report(report['current_fact_queries'],view)
    with Ledger(root/'ledger.sqlite',readonly=True) as ledger:
        checked=ledger.verify();audit=ledger.report()
        if audit['accepted_state']!=report['accepted_state'] or audit['attempts']!=report['attempts'] or audit['system_unresolved']!=report['system_unresolved']:
            raise ValueError('Exported report differs from ledger')
        for use in report.get('current_fact_queries',{}).get('uses',[]):
            attempt=next((a for a in audit['attempts'] if a['request_id']==use['request_id'] and a['status']=='accepted'),None)
            if not attempt:raise ValueError('Query use lacks an accepted actual model proposal')
            rr=next(r for r in report['requests'] if r['request_id']==use['request_id'])
            used_packet=json.loads((root/rr['directory']/'request.json').read_text('utf-8'))
            used_proposal=json.loads((root/rr['directory']/'proposal.json').read_text('utf-8'))
            from androserum.mining.checker import proposal_handles
            cited=proposal_handles(used_proposal)
            actual_refs={e.get('record_ref') for h,e in used_packet['evidence'].items() if h in cited}
            if not set(use['record_refs'])<=actual_refs:raise ValueError('Query use is not cited in the actual accepted proposal')
        versions={row[0]:json.loads(row[1]) for row in ledger.db.execute('SELECT revision,payload FROM versions')}
        applied_queries=set();applied_typed=set()
        for attempt in audit['attempts']:
            request_record=next(x for x in report['requests'] if x['request_id']==attempt['request_id'])
            directory=root/request_record['directory']
            packet=json.loads((directory/'request.json').read_text('utf-8'))
            if fingerprint(packet)!=attempt['request_sha256'] or fingerprint(packet)!=request_record['request_sha256']:
                raise ValueError('Stored request does not match the actual request manifest')
            for event in report.get('query_typed_admissions',[]):
                key=fingerprint([event['request_id'],event['receipt_id'],event['source_bu_refs']])
                if key in applied_typed:continue
                prior=next((x for x in audit['attempts'] if x['request_id']==event['request_id']),None)
                if not prior or prior['status']!='accepted' or prior['after_revision']>packet['base_revision']:continue
                origin=next(r for r in report['requests'] if r['request_id']==event['request_id'])
                original_packet=json.loads((root/origin['directory']/'request.json').read_text('utf-8'))
                original_proposal=json.loads((root/origin['directory']/'proposal.json').read_text('utf-8'))
                receipt=next(q for q in report['current_fact_queries']['queries'] if q['receipt_id']==event['receipt_id'])
                from androserum.facts.queries import CurrentFactQuery
                selectors=[CurrentFactQuery.model_validate(q).model_dump(mode='json') for q in original_proposal['fact_queries']]
                if event['source_bu_refs']!=original_packet['manifest']['source_bu_refs'] or receipt['query'] not in selectors:
                    raise ValueError('Typed query grant lacks the actual accepted model selector/scope')
                from androserum.facts.query_evidence import adapt_query_evidence
                from androserum.facts.query_reuse import records_for
                actual=adapt_query_evidence(catalog,view,records_for(receipt,report['current_fact_queries']),event['source_bu_refs'],query_id=event['query_id'])
                if actual!=event['admission']:raise ValueError('Typed supplemental operation/endpoint/path admission differs')
                applied_typed.add(key)
            for query in report['queries']:
                query_key=(query['request_id'],query['query_id'],query['record_ref'])
                if query_key in applied_queries or query['state']!='admitted_for_next_request':continue
                if report.get('query_typed_admissions') and query.get('query_receipt_id'):continue
                prior=next((x for x in audit['attempts'] if x['request_id']==query['request_id']),None)
                if not prior or prior['after_revision']>packet['base_revision'] or prior['status']!='accepted':continue
                record=view.get_records([query['record_ref']],limit=1).records[0].model_dump(mode='json')
                if fingerprint(record)!=query['record_sha256']:raise ValueError('Supplement differs from current APK facts')
                catalog.supplement(record,query['query_id'],query['source_bu_refs'])
                applied_queries.add(query_key)
            # Reconstruct only handles actually shown, with their explicit BU
            # provenance. No raw archive is loaded into the model registry.
            expected=catalog.render(packet['evidence'],set(packet['manifest']['source_bu_refs']))
            if expected!=packet['evidence']:raise ValueError('Shown evidence differs from BU visibility and admitted supplements')
            raw=(directory/'proposal.json').read_text('utf-8') if attempt['files']['proposal'] else ''
            if hashlib.sha256(raw.encode('utf-8')).hexdigest()!=attempt['response_sha256']:
                raise ValueError('Response differs from attempt audit')
            if (directory/'check.json').is_file() and json.loads((directory/'check.json').read_text('utf-8'))!=attempt['check']:
                raise ValueError('Saved checker result differs from audit')
            if attempt['provider'].get('real_model') and (directory/'input.txt').is_file():
                expected_input='REQUEST_JSON\n'+json.dumps(packet,ensure_ascii=False,separators=(',',':'))
                schema=json.loads((directory/'proposal.schema.json').read_text('utf-8'))
                if schema!=strict_model_schema(packet.get('fact_query_protocol')):raise ValueError('Provider output schema differs')
                actual_input=(directory/'input.txt').read_text('utf-8')
                if actual_input not in {expected_input,expected_input+'\nOUTPUT_SCHEMA\n'+(directory/'proposal.schema.json').read_text('utf-8')}:
                    raise ValueError('Actual provider input differs from the checked request')
                if (directory/'instructions.txt').read_text('utf-8')!=(root/'rules/prompt.txt').read_text('utf-8'):
                    prior_manifest=json.loads((root/'parent-manifest.json').read_text('utf-8')) if info.get('parent') else {}
                    entry=(directory/'instructions.txt').relative_to(root).as_posix()
                    old=prior_manifest.get('files',{}).get(entry)
                    digest=sha256_file(directory/'instructions.txt')
                    normalized=hashlib.sha256((directory/'instructions.txt').read_text('utf-8').encode('utf-8')).hexdigest()
                    if not old or old['sha256']!=digest or normalized not in {p['prompt.txt'] for p in COMPATIBLE_RULE_PROFILES}:
                        raise ValueError('Historical provider instructions lack matching parent hash and known rule profile')
            if attempt['status']=='accepted':
                result,state=check_proposal(raw,packet,versions[attempt['base_revision']],config)
                if not result['valid'] or state!=versions[attempt['after_revision']]:raise ValueError('Accepted proposal/check/transaction replay differs')
            else:
                if attempt['after_revision']!=attempt['base_revision']:raise ValueError('Failed proposal changed accepted ledger revision')
        if info['identity'].get('mining_version')=='behavior-mining.v2':
            from androserum.mining.session import work_plan,coverage,support_additions,TERMINAL,apply_work_amendment,AMENDABLE_BUDGETS
            from androserum.mining.evidence import EvidenceCatalog
            from androserum.mining_packing import clone_catalog
            fresh=clone_catalog(catalog)
            rows,pending=work_plan(fresh,config)
            if [r['chunk'] for r in rows]!=info['plan'] or fingerprint(info['plan'])!=info['plan_sha256']:
                raise ValueError('Fixed chunk plan differs')
            # The original plan is immutable. New review work is derived only
            # from a persisted amendment of the verified parent progress.
            parent_report=json.loads((root/'parent-report.json').read_text('utf-8')) if info.get('parent') else None
            amendment=info.get('new_work_amendment')
            expected_rows=rows
            if info.get('work_amendments'):
                if not parent_report:raise ValueError('Review work lacks parent')
                from copy import deepcopy
                expected_rows=deepcopy(parent_report['chunk_progress'])
                inherited=[]
                # Existing row annotations are continuous through descendants.
                for row in expected_rows:
                    a=row.get('work_amendment')
                    if a and a not in inherited:inherited.append(a)
                if amendment:
                    apply_work_amendment(expected_rows,amendment)
                    if amendment in inherited:raise ValueError('Repeated work amendment')
                    inherited.append(amendment)
                if info['work_amendments']!=inherited:raise ValueError('Work amendment history differs')
            progress=report['chunk_progress']
            if [(r['chunk_id'],r['chunk']) for r in expected_rows]!=[(r['chunk_id'],r['chunk']) for r in progress]:raise ValueError('Chunk identity differs')
            addition_events=[]
            for row in progress:
                expected_row=next(r for r in expected_rows if r['chunk_id']==row['chunk_id'])
                if row.get('work_amendment')!=expected_row.get('work_amendment') or row.get('prior_terminal_state')!=expected_row.get('prior_terminal_state') or row.get('followup_target_ref')!=expected_row.get('followup_target_ref'):
                    raise ValueError('Work amendment metadata differs')
                attempts=[a for a in audit['attempts'] if a['chunk_id']==row['chunk_id']]
                if [a['attempt_id'] for a in attempts]!=row['attempt_ids'] or [a['request_id'] for a in attempts]!=row['request_ids']:
                    raise ValueError('Chunk audit continuity differs')
                shown=set();accepted=set();cited=set()
                for attempt in attempts:
                    rr=next(r for r in report['requests'] if r['request_id']==attempt['request_id'])
                    directory=root/rr['directory'];packet=json.loads((directory/'request.json').read_text('utf-8'))
                    if packet['work_context']['chunk_id']!=row['chunk_id']:raise ValueError('Request work identity differs')
                    if packet['work_context'].get('review_task'):
                        if packet['work_context']['review_task']!=row.get('work_amendment'):raise ValueError('Request review task differs')
                    shown.update(packet['evidence'])
                    if attempt['status']=='accepted':
                        accepted.update(packet['evidence'])
                        from androserum.mining.checker import proposal_handles
                        cited.update(proposal_handles(json.loads((directory/'proposal.json').read_text('utf-8'))))
                        addition_events.extend(support_additions(versions[attempt['base_revision']],versions[attempt['after_revision']],packet))
                if sorted(shown)!=row['shown_handles'] or sorted(accepted)!=row['accepted_handles'] or sorted(cited)!=row['cited_handles']:
                    raise ValueError('Claimed chunk evidence coverage differs from actual requests')
                if row['state']=='accepted' and (not attempts or attempts[-1]['status']!='accepted'):raise ValueError('Chunk falsely marked accepted')
                if row['state']=='rejected' and (not attempts or attempts[-1]['status']!='rejected'):raise ValueError('Chunk falsely marked rejected')
                if row.get('work_amendment'):
                    amended=[a for a in attempts if json.loads((root/next(r for r in report['requests'] if r['request_id']==a['request_id'])['directory']/'request.json').read_text('utf-8'))['work_context'].get('review_task')]
                    if row['amendment_attempts_used']!=len(amended) or len(amended)>row['work_amendment']['max_attempts']:
                        raise ValueError('Work amendment budget accounting differs')
                    if parent_report:
                        previous=next((r for r in parent_report['chunk_progress'] if r['chunk_id']==row['chunk_id']),None)
                        if previous and any(row.get(k,0)!=previous.get(k,0) for k in ['repairs_used','policy_rechecks_used']):raise ValueError('Original retry counters changed during review')
            if coverage(fresh,progress,pending)!=report['coverage']:raise ValueError('Aggregate chunk coverage differs')
            if sorted(addition_events,key=lambda e:e['after_revision'])!=report['support_additions']:raise ValueError('New support claims differ')
            parent=info.get('parent')
            if parent:
                if sha256_file(root/'parent-manifest.json')!=parent['manifest_sha256']:raise ValueError('Parent manifest hash differs')
                pm=json.loads((root/'parent-manifest.json').read_text('utf-8'))
                for entry,item in pm['files'].items():
                    if entry.startswith('requests/') and (sha256_file(root/entry)!=item['sha256'] or (root/entry).stat().st_size!=item['bytes']):
                        raise ValueError('Inherited request file changed across continuation')
                if sha256_file(root/'parent-report.json')!=pm['files']['report.json']['sha256']:raise ValueError('Parent report hash differs')
                pr=json.loads((root/'parent-report.json').read_text('utf-8'))
                if pr['provider']!=info['provider']:
                    binding=info.get('provider_continuation') or {}
                    different={k for k in set(pr['provider'])|set(info['provider']) if pr['provider'].get(k)!=info['provider'].get(k)}
                    if (different!={'round_config_sha256'} or not binding.get('reason') or
                            binding.get('old')!=fingerprint(pr['provider']) or binding.get('new')!=fingerprint(info['provider']) or
                            binding.get('only_budget_round_binding_changed') is not True):
                        raise ValueError('Provider change lacks an exact same-model continuation binding')
                if info.get('query_delivery_policy'):
                    current_queries=report['current_fact_queries'];previous_queries=pr['current_fact_queries']
                    n=len(previous_queries['queries'])
                    if current_queries['queries'][:n]!=previous_queries['queries']:
                        raise ValueError('Historical query receipts changed during reuse continuation')
                    if previous_queries.get('delivery_policy'):
                        if current_queries['delivery_policy']!=previous_queries['delivery_policy']:
                            raise ValueError('Pinned query reuse history changed')
                    elif current_queries['delivery_policy']['legacy_report_sha256']!=fingerprint(previous_queries):
                        raise ValueError('Query reuse upgrade is not bound to the actual parent audit')
                prior=audit['attempts'][:parent['prior_attempts']]
                if [fingerprint(a) for a in prior]!=parent['prior_attempt_hashes'] or prior!=pr['attempts']:raise ValueError('Prior audit chain changed')
                if parent['prior_revision'] not in versions or versions[parent['prior_revision']]!=pr['accepted_state']:raise ValueError('Prior ledger versions missing')
                if report['version_sha256'][:len(pr['version_sha256'])]!=pr['version_sha256']:raise ValueError('Prior version chain changed')
                if info['config']!=pr['budgets']['config']:
                    amendment=info.get('budget_amendment')
                    changed={k for k in set(info['config'])|set(pr['budgets']['config']) if info['config'].get(k)!=pr['budgets']['config'].get(k)}
                    if not changed<=AMENDABLE_BUDGETS or not amendment or not amendment['reason'] or amendment['old_max_calls']!=pr['budgets']['config']['max_model_calls'] or amendment['new_max_calls']!=info['config']['max_model_calls'] or amendment['calls_already_used']!=len(pr['attempts']):
                        raise ValueError('Budget amendment lacks continuous accounting')
                    if any(info['config'][k]<pr['budgets']['config'][k] for k in changed):raise ValueError('Resource amendment decreased a consumed budget')
                    if changed!={'max_model_calls'} or amendment.get('changes'):
                        if amendment.get('changes')!={k:{'old':pr['budgets']['config'][k],'new':info['config'][k]} for k in sorted(changed)}:
                            raise ValueError('Resource amendment changes differ')
            actual_versions=[list(r) for r in ledger.db.execute('SELECT revision,sha256 FROM versions ORDER BY revision')]
            if actual_versions!=report['version_sha256']:raise ValueError('Version hash index differs')
        return {**checked,'compatible_archived_rules':compatible,'source_snapshot_id':catalog.identity['source_snapshot_id'],
                'real_model_attempts':report['real_model_attempts'],'real_model_accepted':report['real_model_accepted'],
                'checker_replayed':sum(x['status']=='accepted' for x in audit['attempts'])}
