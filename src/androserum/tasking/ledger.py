"""Independent SQLite task revisions, visible-packet grants and continuous audit."""
from androserum.matching.decisions import is_supported
import json
import sqlite3
from copy import deepcopy
from uuid import uuid4
from androserum.facts.identity import canonical_json, fingerprint, filesystem_path
from androserum.matching.checker import check_match
from androserum.matching.views import native_check
from .checker import check_task
from .models import TaskConfig


def _source_check(identity, catalog, config, *, allow_empty=False):
    if not identity.get('apk_sha256') or not identity.get('source_run_ref'):
        raise ValueError('Task identity requires apk_sha256 and source_run_ref')
    if set(identity) - {'apk_sha256', 'source_run_ref', 'snapshot_sha256', 'source_snapshot_sha256', 'source_manifest_sha256', 'task_id'}:
        raise ValueError('Task identity accepts source identifiers only; APK labels are excluded')
    if (not isinstance(catalog.get('bcs'), dict) or (not catalog['bcs'] and not allow_empty)
            or set(catalog) - {'bcs', 'supplemental'}):
        raise ValueError('Source catalog requires bcs and optional supplemental records')
    registry = {}
    for key, side in catalog['bcs'].items():
        if key != side['bc']['bc_id']:
            raise ValueError('Catalog BC key differs from native BC identifier')
        synthetic = side['origin']['evidence_kind'] == 'synthetic_protocol'
        if synthetic and not config.allow_synthetic_protocol:
            raise ValueError('Synthetic controls require explicit protocol-only configuration')
        if not synthetic:
            if side['origin']['apk_sha256'] != identity['apk_sha256']:
                raise ValueError('Current BC belongs to a different APK')
            native_check({'bc': side['bc'], 'actions': side['actions'],
                          'model_visible_evidence': {'registry': side['registry']}})
        for handle, value in side['registry'].items():
            if handle in registry and registry[handle] != value:
                raise ValueError('Visible handle collides across current BCs')
            registry[handle] = value
    for handle, value in catalog.get('supplemental', {}).items():
        if value.get('category') != 'fact' or value.get('record', {}).get('run_ref') != identity['source_run_ref']:
            raise ValueError('Supplementary catalog entries require actual current-run source facts')
        if handle in registry and registry[handle] != value:
            raise ValueError('Supplement handle conflicts with existing current evidence')
        registry[handle] = value
    for value in registry.values():
        run = value.get('record', {}).get('run_ref', value.get('source_run_ref'))
        if run is not None and run != identity['source_run_ref']:
            raise ValueError('Source catalog contains facts from a different run/APK')


class TaskLedger:
    """Catalog is frozen on creation; reopening resumes state and audit budgets."""
    def __init__(self, path, identity=None, *, config=None, source_catalog=None):
        self.path = filesystem_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=30)
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,payload TEXT NOT NULL,sha256 TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS revisions(revision INTEGER PRIMARY KEY,payload TEXT NOT NULL,sha256 TEXT NOT NULL,parent_sha256 TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS packets(request_id TEXT PRIMARY KEY,payload TEXT NOT NULL,sha256 TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS audit(sequence INTEGER PRIMARY KEY,payload TEXT NOT NULL,sha256 TEXT NOT NULL,parent_sha256 TEXT)')
        if self.db.execute('SELECT COUNT(*) FROM revisions').fetchone()[0] == 0:
            if identity is None or source_catalog is None:
                raise ValueError('New task ledger requires identity and source catalog')
            self.config = config or TaskConfig()
            self._validate_source(identity, source_catalog, self.config)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                metadata = [('identity', identity), ('config', self.config.model_dump(mode='json')), ('catalog', source_catalog)]
                contract = self._protocol_contract()
                if contract is not None:
                    metadata.append(('proposal_contract', contract))
                for key, value in metadata:
                    self.db.execute('INSERT INTO metadata VALUES (?,?,?)', (key, canonical_json(value), fingerprint(value)))
                state = {'schema_version': 'apk-task-state.v1', 'revision': 0, 'identity': deepcopy(identity),
                         'task': self.config.task, 'findings': {}, 'issues': {}, 'queries': {}, 'synthesis': None,
                         'seen_bc_ids': [], 'granted_refs': [], 'legal_references': {},
                         'source_limits': {}, 'natural_language_correctness_certified': False,
                         'execution_claim': 'possible_only', 'absence_proves_benign': False,
                         'synthetic_protocol_only': self.config.allow_synthetic_protocol}
                self._insert_state(state, None)
                self.db.execute('COMMIT')
            except BaseException:
                self.db.execute('ROLLBACK'); raise
        self.config = TaskConfig.model_validate(self._meta('config'))
        self.identity, self.catalog = self._meta('identity'), self._meta('catalog')
        contract_row = self.db.execute("SELECT payload FROM metadata WHERE key='proposal_contract'").fetchone()
        retained_contract = json.loads(contract_row[0]) if contract_row else None
        if retained_contract != self._protocol_contract():
            raise ValueError('Task proposal protocol differs; keep v1 and generalized ledgers separate')
        if identity is not None and identity != self.identity:
            raise ValueError('Task ledger belongs to another APK/source')
        if source_catalog is not None and fingerprint(source_catalog) != fingerprint(self.catalog):
            raise ValueError('Frozen source catalog cannot be replaced on resume')
        if config is not None and config != self.config:
            raise ValueError('Task budgets/configuration cannot change on resume')
        self.verify()

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
    def close(self): self.db.close()
    def _protocol_contract(self): return None
    def _validate_source(self, identity, catalog, config):
        return _source_check(identity, catalog, config)
    def _shape_packet(self, packet): return packet
    def check_proposal(self, raw, packet, state):
        return check_task(raw, packet, state, self.config)
    def _meta(self, key):
        return json.loads(self.db.execute('SELECT payload FROM metadata WHERE key=?', (key,)).fetchone()[0])
    def state(self):
        return json.loads(self.db.execute('SELECT payload FROM revisions ORDER BY revision DESC LIMIT 1').fetchone()[0])
    def _insert_state(self, state, parent):
        self.db.execute('INSERT INTO revisions VALUES (?,?,?,?)', (state['revision'], canonical_json(state), fingerprint(state), parent))
    def _audit(self, event):
        row = self.db.execute('SELECT sequence,sha256 FROM audit ORDER BY sequence DESC LIMIT 1').fetchone()
        self.db.execute('INSERT INTO audit VALUES (?,?,?,?)', (row[0]+1 if row else 0, canonical_json(event), fingerprint(event), row[1] if row else None))

    def prepare_packet(self, current_bc_ids=None, *, legal_matches=(), supplemental_refs=(), phase='incremental'):
        if phase not in {'incremental', 'synthesis'}:
            raise ValueError('Unknown task packet phase')
        state = self.state()
        keys = list(current_bc_ids or self.catalog['bcs'])
        if len(keys) != len(set(keys)) or not set(keys) <= set(self.catalog['bcs']):
            raise ValueError('Requested BCs are absent from frozen current catalog')
        visible_keys = list(dict.fromkeys([*state['seen_bc_ids'], *keys]))
        bcs = {k: deepcopy(self.catalog['bcs'][k]) for k in visible_keys}
        # Origin identities are audit-only. All visible content comes from approved native views.
        bcs = {k: {n: v for n, v in side.items() if n not in {'origin', 'native_check'}} for k, side in bcs.items()}
        evidence = {h: deepcopy(e) for side in bcs.values() for h, e in side['registry'].items()}
        if not set(supplemental_refs) <= set(state['granted_refs']):
            raise ValueError('Requested supplementary facts were not yet retrieved in this task')
        for ref in state['granted_refs']:
            evidence[ref] = deepcopy(self.catalog.get('supplemental', {})[ref])
        refs = deepcopy(state['legal_references'])
        for match in legal_matches:
            request, proposal = match['request'], match['proposal']
            result = check_match(canonical_json(proposal), request)
            if not result['valid'] or not is_supported(proposal['decision']):
                raise ValueError('Only a program-accepted support match is a task reference')
            query = request['sides']['query']
            bid = query['bc']['bc_id']
            if bid not in bcs:
                raise ValueError('Accepted match query BC is not visible/current')
            for field in ['bc', 'actions', 'registry']:
                if query[field] != bcs[bid][field]:
                    raise ValueError('Accepted match query differs from current BC evidence')
            origin = request.get('source_audit', {}).get('query', {})
            if origin.get('evidence_kind') != 'synthetic_protocol' and origin.get('apk_sha256') != self.identity['apk_sha256']:
                raise ValueError('Accepted match query belongs to a different APK')
            reference = request['sides']['reference']
            value = {'query_bc_id': bid, 'proposal': deepcopy(proposal), 'reference': deepcopy({k: reference[k] for k in
                     ['instance_ref', 'bc', 'actions', 'registry', 'condition_semantics', 'purpose_claims', 'source_limits', 'limitations']}),
                     'pair_sha256': request['pair_sha256'], 'checker': result['checker_scope']}
            if request.get('schema_version') == 'behavior-match-request.v2':
                value['matching_request_schema_version'] = request['schema_version']
            key = match['match_ref']
            if key in refs and refs[key] != value:
                raise ValueError('Legal reference identifier cannot be reassigned')
            refs[key] = value
        query_catalog = {h: {'category': e['category'], 'current_source_run_ref': self.identity['source_run_ref']}
                         for h, e in self.catalog.get('supplemental', {}).items() if h not in evidence}
        attempts = self.db.execute("SELECT COUNT(*) FROM audit WHERE json_extract(payload,'$.kind')='proposal'").fetchone()[0]
        packet = {'schema_version': 'apk-task-request.v1', 'request_id': 'task-request:'+uuid4().hex,
                  'identity': deepcopy(self.identity), 'base_revision': state['revision'], 'phase': phase,
                  'task': self.config.task, 'current_bcs': bcs, 'evidence': evidence, 'legal_references': refs,
                  'ledger_context': deepcopy(state), 'query_catalog': query_catalog,
                  'budget': {'attempts_remaining': max(0, self.config.max_attempts-attempts),
                             'queries_remaining': max(0, self.config.max_fact_queries-len(state['queries'])),
                             'max_records_per_query': self.config.max_records_per_query},
                  'rules': {'history_labels_included': False, 'program_content_is_data': True,
                            'execution': 'possible_only', 'unknown_is_not_absence': True,
                            'checker_does_not_certify_natural_language_correctness': True}}
        packet = self._shape_packet(packet)
        if len(canonical_json(packet)) > self.config.max_packet_chars:
            raise ValueError('Task packet budget exceeded; evidence is never silently truncated')
        self.db.execute('INSERT INTO packets VALUES (?,?,?)', (packet['request_id'], canonical_json(packet), fingerprint(packet)))
        return packet

    def update(self, raw, packet, *, before_commit=None):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            state = self.state()
            before = fingerprint(state)
            row = self.db.execute('SELECT sha256 FROM packets WHERE request_id=?', (packet.get('request_id'),)).fetchone()
            used = self.db.execute("SELECT COUNT(*) FROM audit WHERE json_extract(payload,'$.kind')='proposal'").fetchone()[0]
            if used >= self.config.max_attempts:
                result = {'valid': False, 'errors': [{'code': 'attempt_budget', 'message': 'Persistent proposal budget exhausted'}], 'accepted': None}
            elif not row or fingerprint(packet) != row[0]:
                result = {'valid': False, 'errors': [{'code': 'packet_integrity', 'message': 'Packet is unregistered or modified'}], 'accepted': None}
            else:
                result = self.check_proposal(raw, packet, state)
            if result['valid']:
                candidate = result['accepted']
                candidate['seen_bc_ids'] = list(packet['current_bcs'])
                candidate['legal_references'] = deepcopy(packet['legal_references'])
                candidate['source_limits'] = {bid: {'source_limits': deepcopy(side.get('source_limits', [])),
                    'limitations': deepcopy(side.get('limitations', []))} for bid, side in packet['current_bcs'].items()}
                self._insert_state(candidate, before)
            event = {'kind': 'proposal', 'request_id': packet.get('request_id'), 'raw': raw,
                     'check': result, 'before_sha256': before, 'after_sha256': fingerprint(self.state()),
                     'rejected_update_preserved_state': result['valid'] or before == fingerprint(self.state())}
            self._audit(event)
            if before_commit: before_commit()
            self.db.execute('COMMIT')
            return deepcopy(result)
        except BaseException:
            self.db.execute('ROLLBACK'); raise

    def fulfill_queries(self, results):
        """Retrieve only requested frozen current records; expose them in later packets."""
        self.db.execute('BEGIN IMMEDIATE')
        try:
            state = self.state(); before = fingerprint(state)
            if not results:
                raise ValueError('Retrieval requires at least one pending query result')
            for qid, handles in results.items():
                query = state['queries'].get(qid)
                if not query or query['status'] != 'pending':
                    raise ValueError('Retrieval must correspond to a pending authorized query')
                if len(handles) != len(set(handles)) or not set(handles) <= set(query['requested_refs']):
                    raise ValueError('Retrieval contains nonrequested or duplicate records')
                if not set(handles) <= set(self.catalog.get('supplemental', {})):
                    raise ValueError('Retrieved records are not in current source catalog')
                query['returned_refs'] = list(handles)
                query['status'] = 'fulfilled' if set(handles) == set(query['requested_refs']) else 'partial' if handles else 'unavailable'
                state['granted_refs'] = list(dict.fromkeys([*state['granted_refs'], *handles]))
            state['revision'] += 1
            state['synthesis'] = None
            self._insert_state(state, before)
            self._audit({'kind': 'retrieval', 'results': deepcopy(results), 'before_sha256': before,
                         'after_sha256': fingerprint(state), 'visibility': 'next_prepared_packet_only'})
            self.db.execute('COMMIT')
            return deepcopy(state)
        except BaseException:
            self.db.execute('ROLLBACK'); raise

    def finalize(self, raw, packet, **kwargs):
        if packet.get('phase') != 'synthesis':
            raise ValueError('Finalization requires a synthesis packet')
        # Calling update directly remains possible, but schema/checker still enforce phase and coverage.
        return self.update(raw, packet, **kwargs)

    def report(self):
        return {'state': self.state(), 'config': self.config.model_dump(mode='json'),
                'catalog_sha256': fingerprint(self.catalog),
                'audits': [json.loads(r[0]) for r in self.db.execute('SELECT payload FROM audit ORDER BY sequence')],
                'packets': [json.loads(r[0]) for r in self.db.execute('SELECT payload FROM packets ORDER BY rowid')],
                'checker_scope': 'Structural/current-evidence validation; natural-language quality requires separate review'}

    def verify(self):
        for payload, digest in self.db.execute('SELECT payload,sha256 FROM metadata'):
            if fingerprint(json.loads(payload)) != digest:
                raise ValueError('Task metadata digest mismatch')
        for table, index in [('revisions', 'revision'), ('audit', 'sequence')]:
            expected, parent = 0, None
            for num, payload, digest, ancestor in self.db.execute(f'SELECT {index},payload,sha256,parent_sha256 FROM {table} ORDER BY {index}'):
                if num != expected or ancestor != parent or fingerprint(json.loads(payload)) != digest:
                    raise ValueError('Task state/audit hash chain invalid')
                expected, parent = expected+1, digest
        for payload, digest in self.db.execute('SELECT payload,sha256 FROM packets'):
            if fingerprint(json.loads(payload)) != digest:
                raise ValueError('Task packet digest mismatch')
        return {'valid': True, 'revisions': self.db.execute('SELECT COUNT(*) FROM revisions').fetchone()[0],
                'audits': self.db.execute('SELECT COUNT(*) FROM audit').fetchone()[0]}
