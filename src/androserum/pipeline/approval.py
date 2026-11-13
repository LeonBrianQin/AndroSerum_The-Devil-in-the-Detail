"""Explicit review/freeze boundaries for arbitrary native, real-model BCs.

Approval remains a review judgment, never an inference from program checks.
Frozen query material cannot be silently promoted to the historical corpus.
"""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import json

from androserum.facts.identity import canonical_json, filesystem_path, fingerprint, sha256_file
from androserum.encoding.runner import read, write, source_backlink
from androserum.mining.ledger import Ledger
from androserum.matching.views import native_check

VERSION = 'reviewed-bc-freeze.v1'


def inventory(directory):
    directory = filesystem_path(directory)
    return {p.relative_to(directory).as_posix(): {'sha256': sha256_file(p), 'bytes': p.stat().st_size}
            for p in sorted(directory.rglob('*')) if p.is_file() and p != directory / 'manifest.json'}


def verify_files(directory):
    """Check the complete immutable package, including unexpected additions."""
    directory = filesystem_path(directory)
    manifest = read(directory / 'manifest.json')
    if inventory(directory) != manifest['files']:
        raise ValueError('Published package file inventory or hash differs: ' + str(directory))
    return manifest


def _merge_displayed(previous, evidence):
    """Merge only memberships/condition collection metadata actually shown.

    Semantic identity remains exact. A fact may retain the richer of two
    monotonic displayed projections, with identical overlapping field values.
    Nothing is read from an archive or added to the set of displayed handles.
    """
    if previous.get('category') != evidence.get('category'):
        raise ValueError('Conflicting displayed evidence category')
    a,b=deepcopy(previous),deepcopy(evidence)
    has_membership='bu_ids' in a or 'bu_ids' in b
    members_a,members_b=a.pop('bu_ids',[]),b.pop('bu_ids',[])
    membership=sorted(set(members_a)|set(members_b))
    sources_a=sources_b=None
    if a.get('category')=='condition':
        sources_a=a.pop('source_collection_by_bu',None)
        sources_b=b.pop('source_collection_by_bu',None)
        if sources_a is not None or sources_b is not None:
            sources_a,sources_b=sources_a or {},sources_b or {}
            if not set(sources_a)<=set(members_a) or not set(sources_b)<=set(members_b):
                raise ValueError('Displayed condition metadata exceeds shown BU membership')
            if any(sources_a[k]!=sources_b[k] for k in set(sources_a)&set(sources_b)):
                raise ValueError('Conflicting displayed per-BU condition source state')
    if a.get('category')=='fact':
        if a.get('record_sha256')!=b.get('record_sha256'):
            raise ValueError('Contradictory displayed fact')
        ra,rb=a['record'],b['record']
        if any(ra[k]!=rb[k] for k in set(ra)&set(rb)):
            raise ValueError('Conflicting displayed fact fields')
        if not (set(ra)<=set(rb) or set(rb)<=set(ra)):
            raise ValueError('Non-monotonic displayed fact detail')
        richer=evidence if set(ra)<=set(rb) else previous
        for key in ['record','shown_fields','detail_fields_available','supplement_query_id']:
            a.pop(key,None);b.pop(key,None)
        if a!=b:raise ValueError('Conflicting displayed fact identity')
        merged=deepcopy(richer)
    else:
        if a!=b:raise ValueError('Conflicting displayed evidence identity')
        merged=deepcopy(previous)
    if has_membership:merged['bu_ids']=membership
    if sources_a is not None or sources_b is not None:
        merged['source_collection_by_bu']={**(sources_a or {}),**(sources_b or {})}
    return merged


def shown_for_bc(run, report, bc):
    actions = {key: report['accepted_state']['actions'][key] for key in bc['action_ids']}
    requests = {bc['evidence_request_id'], *(a['evidence_request_id'] for a in actions.values())}
    accepted = {a['request_id']: a for a in report['attempts'] if a['status'] == 'accepted'}
    if not requests <= set(accepted):
        raise ValueError('Final BC/actions do not belong to accepted proposals')
    if any(not accepted[r]['provider'].get('real_model') for r in requests):
        raise ValueError('Every final BC/action must originate in an accepted real-model proposal')
    union, packets = {}, []
    for request in report['requests']:
        if request['request_id'] not in requests:
            continue
        file = filesystem_path(run / request['directory'] / 'request.json')
        if not file.is_relative_to(run):
            raise ValueError('Request escaped mining package')
        packet = read(file)
        if fingerprint(packet) != request['request_sha256']:
            raise ValueError('Shown packet changed')
        packets.append({'request_id': request['request_id'], 'file': file.relative_to(run).as_posix(),
                        'sha256': sha256_file(file)})
        for handle, evidence in packet['evidence'].items():
            if handle not in union:
                union[handle] = deepcopy(evidence)
            elif union[handle] != evidence:
                union[handle] = _merge_displayed(union[handle], evidence)
    if len(packets) != len(requests):
        raise ValueError('An accepted evidence request is missing')
    required = set(bc['evidence_handles']) | {h for a in actions.values() for h in a['evidence_handles']}
    if not required <= set(union):
        raise ValueError('Final BC cites evidence not displayed to the model')
    return actions, {'actual_request_refs': packets, 'registry': union,
                     'registry_sha256': fingerprint(union), 'archive_records_added': False}


def build_reviewed_entry(mining_run, snapshot, bu_package, bc_id, *, source_case, qualification):
    """Export one accepted BC for an explicit, subsequent semantic review.

    This function does not itself approve the interpretation. The caller must
    provide the review decision and reasons, which freeze_reviewed validates.
    """
    run = filesystem_path(mining_run)
    verify_files(run)
    report = read(run / 'report.json')
    with Ledger(run / 'ledger.sqlite', readonly=True) as ledger:
        ledger.verify()
        if ledger.report()['accepted_state'] != report['accepted_state']:
            raise ValueError('Exported report differs from accepted ledger')
    state = report['accepted_state']
    bc = state['bcs'][bc_id]
    actions, visible = shown_for_bc(run, report, bc)
    return {'qualified_ref': 'reviewed:' + fingerprint([state['identity'], state['revision'], bc_id])[:24],
            'source_case': source_case, 'source_apk_sha256': state['identity']['source']['apk_sha256'],
            'source_snapshot': str(filesystem_path(snapshot)), 'source_bu_package': str(filesystem_path(bu_package)),
            'source_mining_run': str(run), 'source_mining_manifest_sha256': sha256_file(run / 'manifest.json'),
            'ledger_revision': state['revision'], 'bc': deepcopy(bc), 'actions': actions,
            'model_visible_evidence': visible, 'qualification': deepcopy(qualification),
            'archive_support_policy': 'Original facts, BU archive and ledger remain audit support; only actually displayed evidence is model-visible'}


def validate_entry(entry, *, replay=False):
    qualification = entry['qualification']
    automatic = entry.get('admission_mode') == 'program_checked'
    if automatic:
        if qualification != {'program_check':'passed', 'semantic_review':'not_performed',
                'judgment':'Program evidence consistency only; semantic quality is evaluated separately.'}:
            raise ValueError('Automatic admission cannot claim a semantic approval')
    elif (qualification.get('program_check') != 'passed' or
          qualification.get('semantic_review') not in {'supported', 'supported_with_explicit_limits'} or
          not str(qualification.get('judgment', '')).strip()):
        raise ValueError('BC needs an explicit supported semantic review with reasons')
    run = filesystem_path(entry['source_mining_run'])
    verify_files(entry['source_bu_package'])
    snapshot = filesystem_path(entry['source_snapshot'])
    snapshot_manifest = read(snapshot / 'manifest.json')
    if sha256_file(snapshot / snapshot_manifest['database']) != snapshot_manifest['database_sha256']:
        raise ValueError('Source fact database changed')
    for item in snapshot_manifest['files']:
        from androserum.facts.store import EvidenceFile, read_evidence_file
        read_evidence_file(snapshot, EvidenceFile.model_validate(item))
    verify_files(run)
    backlink = source_backlink(entry)
    report = read(run / 'report.json')
    with Ledger(run / 'ledger.sqlite', readonly=True) as ledger:
        ledger.verify()
        state = ledger.state()
        if state != report['accepted_state']:
            raise ValueError('Mining report does not match actual ledger')
    if entry['ledger_revision'] != state['revision']:
        raise ValueError('A new freeze must review the final accepted source revision')
    source = state['identity']['source']
    snap = read(filesystem_path(entry['source_snapshot']) / 'manifest.json')
    collection = read(filesystem_path(entry['source_bu_package']) / 'collection.json')
    if (entry['source_apk_sha256'] != source['apk_sha256'] or
            source['apk_sha256'] != snap['apk_sha256'] or
            source['apk_sha256'] != collection['apk_sha256'] or
            source['source_run_ref'] != snap['run_ref'] or
            source['source_run_ref'] != collection['source_run_ref'] or
            source['source_snapshot_id'] != snap['snapshot_id'] or
            source['source_snapshot_id'] != collection['source_snapshot_id']):
        raise ValueError('APK, fact snapshot and BU provenance do not agree')
    bc = state['bcs'][entry['bc']['bc_id']]
    actions, visible = shown_for_bc(run, report, bc)
    if entry['bc'] != bc or entry['actions'] != actions or entry['model_visible_evidence']['registry'] != visible['registry']:
        raise ValueError('Approved BC/actions/visibility differ from accepted real-model source')
    native_check(entry)
    if replay:
        from androserum.facts.store import FactView
        from androserum.mining.verification import verify_mining
        with FactView(entry['source_snapshot']) as view:
            result = verify_mining(run, entry['source_bu_package'], view)
        if not result['valid']:
            raise ValueError('Source mining replay failed')
    return backlink


def freeze_reviewed(entries, rejected_candidates, review, output, *, role='query', replay=True):
    """Publish a new version; a query freeze grants no historical admission."""
    if role not in {'query', 'history'}:
        raise ValueError('Freeze role must be query or explicitly approved history')
    if not all(str(review.get(k, '')).strip() for k in ['reviewer', 'method', 'rationale']):
        raise ValueError('Reviewer, method and rationale are mandatory')
    entries = deepcopy(list(entries)); rejected_candidates = deepcopy(list(rejected_candidates))
    if any(e.get('admission_mode') == 'program_checked' for e in entries):
        raise ValueError('Use freeze_program_checked for automatic admission; semantic reviews are a separate policy')
    refs = [e['qualified_ref'] for e in entries]
    if len(set(refs)) != len(refs):
        raise ValueError('Duplicate approved BC identity')
    native = [(e.get('source_apk_sha256'), e.get('source_mining_manifest_sha256'),
               e.get('ledger_revision'), e.get('bc', {}).get('bc_id')) for e in entries]
    if len(set(native)) != len(native):
        raise ValueError('Duplicate native BC instance cannot be disguised with a new approved ID')
    rejected_refs = [c.get('qualified_ref', c.get('candidate_id', c.get('bc_id'))) for c in rejected_candidates]
    if any(not r or not str(c.get('reason', '')).strip() for r, c in zip(rejected_refs, rejected_candidates)):
        raise ValueError('Excluded candidates need an identity and reason')
    if len(set(rejected_refs)) != len(rejected_refs) or set(refs) & set(rejected_refs):
        raise ValueError('Approved and excluded identities must be disjoint and unique')
    backlinks = []
    replayed = set()
    for entry in entries:
        key = entry['source_mining_manifest_sha256']
        backlinks.append(validate_entry(entry, replay=replay and key not in replayed))
        replayed.add(key)
    directory = filesystem_path(output) / ('freeze_' + uuid4().hex)
    directory.mkdir(parents=True, exist_ok=False)
    write(directory / 'approved-pool.json', {'schema_version': 'reviewed-native-bc-pool.v1', 'entries': entries})
    write(directory / 'excluded-candidates.json', rejected_candidates)
    write(directory / 'review.json', review)
    write(directory / 'backlinks.json', backlinks)
    write(directory / 'freeze.json', {'schema_version': VERSION, 'created_utc': datetime.now(timezone.utc).isoformat(),
          'role': role, 'qualified_refs': refs, 'entry_sha256': {e['qualified_ref']: fingerprint(e) for e in entries},
          'approved_count': len(entries), 'excluded_count': len(rejected_candidates),
          'pool_sha256': sha256_file(directory / 'approved-pool.json'),
          'review_sha256': sha256_file(directory / 'review.json'), 'source_replay_performed': replay,
          'approval_scope': 'Evidence-supported interpretations within explicit limits; program checks do not certify natural-language meaning',
          'query_does_not_update_history': True, 'independent_human_review': bool(review.get('independent_human_review', False))})
    files = inventory(directory)
    write(directory / 'manifest.json', {'schema_version': 'reviewed-bc-freeze-manifest.v1', 'state': 'published',
          'freeze_id': fingerprint(files), 'files': files})
    return directory


def load_frozen(directory, *, verify_sources=True):
    directory = filesystem_path(directory)
    manifest = verify_files(directory)
    policy = read(directory / 'freeze.json')
    if policy['schema_version'] not in {VERSION, 'program-checked-bc-freeze.v1'} or manifest.get('freeze_id') != fingerprint(manifest['files']):
        raise ValueError('Unknown or modified generic BC freeze')
    if policy.get('role') not in {'query', 'history'} or not policy.get('query_does_not_update_history'):
        raise ValueError('Frozen approval role is invalid')
    entries = read(directory / 'approved-pool.json')['entries']
    if policy['schema_version'] == 'program-checked-bc-freeze.v1' and (
            policy.get('semantic_review_required') is not False or
            any(e.get('admission_mode') != 'program_checked' for e in entries)):
        raise ValueError('Automatic freeze must preserve its program-only admission role')
    refs = [e['qualified_ref'] for e in entries]
    if (refs != policy['qualified_refs'] or len(refs) != len(set(refs)) or len(refs) != policy['approved_count'] or
            policy['entry_sha256'] != {e['qualified_ref']: fingerprint(e) for e in entries} or
            sha256_file(directory / 'approved-pool.json') != policy['pool_sha256'] or
            sha256_file(directory / 'review.json') != policy['review_sha256'] or
            len(read(directory / 'excluded-candidates.json')) != policy['excluded_count']):
        raise ValueError('Frozen review inventory differs')
    if verify_sources:
        actual = [validate_entry(e) for e in entries]
        if actual != read(directory / 'backlinks.json'):
            raise ValueError('Frozen source backlinks changed')
    return policy, entries


def freeze_program_checked(mining_run, snapshot, bu_package, output, *, source_case,
                           role='query', replay=True, source_identity=None):
    """Method mainline: all final program-valid model BCs, no semantic gate.

    No model content is rewritten. Independent semantic assessments may be
    stored later as evaluation artifacts without changing this freeze.
    """
    if role not in {'query', 'history'}:
        raise ValueError('Explicit query/history role required')
    entries = []; backlinks = []; state = None
    if mining_run:
        run = filesystem_path(mining_run)
        verify_files(run)
        report = read(run/'report.json'); state = report['accepted_state']
        if replay:
            from androserum.facts.store import FactView
            from androserum.mining.verification import verify_mining
            with FactView(snapshot) as view:
                if not verify_mining(run, bu_package, view)['valid']:
                    raise ValueError('Program mining replay failed')
        for bid in sorted(state['bcs']):
            entry = build_reviewed_entry(run, snapshot, bu_package, bid, source_case=source_case,
                qualification={'program_check':'passed', 'semantic_review':'not_performed',
                    'judgment':'Program evidence consistency only; semantic quality is evaluated separately.'})
            entry['admission_mode'] = 'program_checked'
            entry['qualified_ref'] = 'program-checked:' + fingerprint([state['identity'], state['revision'], bid])[:24]
            backlinks.append(validate_entry(entry, replay=False)); entries.append(entry)
        identity = {'apk_sha256':state['identity']['source']['apk_sha256'],
                    'source_run_ref':state['identity']['source']['source_run_ref']}
    else:
        identity = deepcopy(source_identity)
        if not identity or set(identity) != {'apk_sha256', 'source_run_ref'}:
            raise ValueError('Empty model result must still identify its current APK/run')
    directory = filesystem_path(output)/('freeze_'+uuid4().hex)
    directory.mkdir(parents=True, exist_ok=False)
    write(directory/'approved-pool.json', {'schema_version':'program-checked-native-bc-pool.v1', 'entries':entries})
    write(directory/'excluded-candidates.json', [])
    write(directory/'review.json', {**identity, 'kind':'automatic_program_check_admission',
        'semantic_review_performed':False, 'native_model_content_rewritten':False})
    write(directory/'backlinks.json', backlinks)
    refs = [e['qualified_ref'] for e in entries]
    write(directory/'freeze.json', {'schema_version':'program-checked-bc-freeze.v1',
        'created_utc':datetime.now(timezone.utc).isoformat(), 'role':role, 'qualified_refs':refs,
        'entry_sha256':{e['qualified_ref']:fingerprint(e) for e in entries},
        'approved_count':len(entries), 'excluded_count':0, 'pool_sha256':sha256_file(directory/'approved-pool.json'),
        'review_sha256':sha256_file(directory/'review.json'), 'source_replay_performed':replay,
        'semantic_review_required':False, 'independent_human_review':False,
        'approval_scope':'Program structure, displayed evidence and references only; natural-language correctness is not certified',
        'query_does_not_update_history':True, 'source_identity':identity,
        'all_final_accepted_bcs_included':True, 'full_apk_behavior_coverage_claimed':False})
    files = inventory(directory)
    write(directory/'manifest.json', {'schema_version':'program-checked-bc-freeze-manifest.v1',
        'state':'published', 'freeze_id':fingerprint(files), 'files':files})
    return directory
