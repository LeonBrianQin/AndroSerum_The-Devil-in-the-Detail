"""Budgeted, read-only current-APK queries with actual-return and use receipts.

Selectors are data, never SQL or code. An archive is not made model-visible by
opening this service: only records in a returned receipt may be admitted.
"""
from collections import deque
from copy import deepcopy
import json
import sqlite3
from typing import Literal

from pydantic import Field, model_validator
from androserum.facts.identity import canonical_json, fingerprint
from androserum.facts.models import Endpoint, StrictModel
from androserum.facts.store import RefFilter

KINDS = ('record', 'method', 'operation', 'call', 'data_dependency', 'condition', 'event', 'resource')
DATA = ['data_dependency', 'field_dependency', 'array_dependency', 'state_dependency', 'information_flow', 'icc_data',
        'argument_to_parameter', 'return_to_result', 'call_result_assignment']


class CurrentFactQuery(StrictModel):
    query_id: str = Field(min_length=1, max_length=64, pattern=r'^[a-z][a-z0-9_]*$')
    query_type: Literal['record', 'method', 'operation', 'call', 'data_dependency', 'condition', 'event', 'resource']
    apk_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    run_ref: str
    subject_ref: str | None = None
    method_signature: str | None = None
    name: str | None = Field(default=None, max_length=512)
    endpoint: Endpoint | None = None
    direction: Literal['in', 'out'] = 'in'
    context_ref: str | None = None
    binding_ref: str | None = None
    max_hops: int = Field(default=1, ge=1, le=4)
    limit: int = Field(default=8, ge=1, le=64)
    offset: int = Field(default=0, ge=0, le=1000000)
    include_support: bool = True
    reason: str = Field(min_length=1, max_length=3000)

    @model_validator(mode='after')
    def selector_required(self):
        if not any([self.subject_ref, self.method_signature, self.name, self.endpoint]):
            raise ValueError('An explicit selector is required; whole-APK dumping is not a query')
        if self.query_type == 'data_dependency' and self.endpoint is None:
            raise ValueError('Dependency queries require a complete endpoint/slot')
        if self.query_type in {'record', 'condition', 'event'} and not self.subject_ref:
            raise ValueError('This query needs an actual current fact ID')
        if self.query_type in {'method', 'operation', 'call', 'resource'} and not any([self.subject_ref,self.method_signature,self.name]):
            raise ValueError('This query requires a supported record/signature/name selector')
        if self.query_type == 'call' and not any([self.subject_ref,self.method_signature]):
            raise ValueError('A call query needs an existing method/call ID or exact declaration signature')
        if self.query_type == 'resource' and not any([self.subject_ref,self.name]):
            raise ValueError('A resource query requires an existing resource/use ID or literal name')
        return self


class FactQueryBudget(StrictModel):
    max_queries: int = Field(default=8, ge=0, le=1000)
    max_records: int = Field(default=64, ge=0, le=10000)
    max_return_chars: int = Field(default=150000, ge=0, le=5000000)


def query_capabilities():
    return {'protocol': 'current-fact-query.v1', 'implemented_types': list(KINDS),
        'selector_policy': 'Explicit existing IDs, exact DEX method signature, or literal resource/method name; no SQL/code/files',
        'dependency_scope': 'Recorded edges with explicit direction and bounded hops; returned edges are not automatically a feasible balanced path',
        'unsupported': ['new_static_analysis', 'dynamic_execution', 'arbitrary_sql', 'raw_archive_dump', 'other_apk'],
        'missing_results_mean': 'No matching record in this snapshot; does not prove behavior absent'}


def _select_base(view, q):
    """Existing immutable records only; no inference or model-created facts."""
    if q.query_type == 'record':
        result = view.get_records([q.subject_ref], limit=q.limit)
    elif q.query_type == 'data_dependency':
        queue = deque([(q.endpoint, 0)]); seen = set(); records = {}; pending = False
        while queue:
            point, depth = queue.popleft()
            key = canonical_json(point.model_dump(mode='json'))
            if key in seen:
                continue
            seen.add(key)
            result = view.get_relations(point, direction=q.direction, relation_kinds=DATA,
                context=RefFilter(mode='exact', ref=q.context_ref) if q.context_ref else RefFilter(mode='all'),
                binding=RefFilter(mode='exact', ref=q.binding_ref) if q.binding_ref else RefFilter(mode='all'), limit=q.limit)
            pending |= result.truncated
            for edge in result.records:
                if edge.id not in records and len(records) >= q.limit:
                    pending = True
                    continue
                records[edge.id] = edge.model_dump(mode='json')
                if depth + 1 < q.max_hops:
                    nxt = edge.source if q.direction == 'in' else edge.target
                    if nxt:
                        queue.append((nxt, depth + 1))
        return list(records.values()), pending, [], {'max_hops': q.max_hops, 'context_ref': q.context_ref,
            'binding_ref': q.binding_ref, 'path_feasibility_established': False}
    elif q.query_type == 'condition':
        result = view.get_constraints(q.subject_ref, limit=q.limit)
    elif q.query_type == 'event':
        result = view.get_event_context(q.subject_ref, limit=q.limit)
    else:
        # Parameterized reads of the current immutable record table. Every
        # candidate is decoded from the stored contract before it is returned.
        clauses = ['r.run_id=?']; args = [view.run_ref]
        kind = "json_extract(r.payload_json,'$.kind')"
        if q.query_type == 'method':
            clauses.append(kind + "='method'")
            if q.method_signature:
                clauses.append("json_extract(r.payload_json,'$.signature')=?"); args.append(q.method_signature)
            if q.subject_ref:
                clauses.append('r.record_id=?'); args.append(q.subject_ref)
            if q.name:
                clauses.append("instr(COALESCE(json_extract(r.payload_json,'$.signature'),''),?)>0"); args.append(q.name)
        elif q.query_type == 'operation':
            clauses.append('(' + kind + "='instruction' OR " + kind + "='analysis_node')")
            if q.subject_ref:
                clauses.append("(r.record_id=? OR json_extract(r.payload_json,'$.method_ref')=? OR json_extract(r.payload_json,'$.position.method_ref')=?)")
                args.extend([q.subject_ref] * 3)
            if q.method_signature:
                clauses.append("COALESCE(json_extract(r.payload_json,'$.method_ref'),json_extract(r.payload_json,'$.position.method_ref')) IN (SELECT m.record_id FROM records m WHERE m.run_id=r.run_id AND json_extract(m.payload_json,'$.kind')='method' AND json_extract(m.payload_json,'$.signature')=?)")
                args.append(q.method_signature)
            if q.name:
                clauses.append("(json_extract(r.payload_json,'$.operation')=? OR json_extract(r.payload_json,'$.opcode')=?)")
                args.extend([q.name] * 2)
        elif q.query_type == 'call':
            clauses.append("(json_extract(r.payload_json,'$.declared_target') IS NOT NULL OR json_extract(r.payload_json,'$.relation_kind') IN ('declared_call','candidate_call'))")
            if q.method_signature:
                clauses.append("(COALESCE(json_extract(r.payload_json,'$.declared_target.signature'),json_extract(r.payload_json,'$.declared_target'))=? OR EXISTS(SELECT 1 FROM records m WHERE m.run_id=r.run_id AND m.record_id=json_extract(r.payload_json,'$.target.element_ref') AND json_extract(m.payload_json,'$.signature')=?))")
                args.extend([q.method_signature] * 2)
            if q.subject_ref:
                clauses.append("(r.record_id=? OR json_extract(r.payload_json,'$.source.element_ref')=? OR json_extract(r.payload_json,'$.method_ref')=? OR json_extract(r.payload_json,'$.position.method_ref')=? OR EXISTS(SELECT 1 FROM records c WHERE c.run_id=r.run_id AND c.record_id=json_extract(r.payload_json,'$.source.element_ref') AND COALESCE(json_extract(c.payload_json,'$.method_ref'),json_extract(c.payload_json,'$.position.method_ref'))=?))")
                args.extend([q.subject_ref] * 5)
        elif q.query_type == 'resource':
            clauses.append('(' + kind + "='resource' OR json_extract(r.payload_json,'$.relation_kind') IN ('resource_use','resource_reference'))")
            if q.subject_ref:
                clauses.append("(r.record_id=? OR json_extract(r.payload_json,'$.source.element_ref')=? OR json_extract(r.payload_json,'$.target.element_ref')=?)")
                args.extend([q.subject_ref] * 3)
            if q.name:
                clauses.append("instr(r.payload_json,?)>0"); args.append(q.name)
        sql = 'SELECT r.section,r.payload_json FROM records r WHERE ' + ' AND '.join(clauses) + ' ORDER BY r.ordinal LIMIT ? OFFSET ?'
        raw = view._connection.execute(sql, (*args, q.limit + 1, q.offset)).fetchall()
        return [view._decode(r).model_dump(mode='json') for r in raw[:q.limit]], len(raw) > q.limit, [], {'offset': q.offset}
    return [r.model_dump(mode='json') for r in result.records], result.truncated, result.missing_refs, result.filters


def _select(view,q):
    records,truncated,missing,filters=_select_base(view,q)
    if not q.include_support:return records,truncated,missing,filters
    values={r['id']:r for r in records};queue=deque(records);seen=set(values);pending=[]
    # Only explicit structural/evidence references; never consumers, a whole
    # method body or an archive. Every returned support record is budgeted.
    while queue:
        record=queue.popleft();refs=[]
        for field in ('source','target','value_endpoint'):
            point=record.get(field)
            if isinstance(point,dict) and point.get('element_ref'):refs.append(point['element_ref'])
        for point in record.get('endpoints',[]):refs.append(point['element_ref'])
        for field in ('branch_ref','context_ref','method_ref'):
            if record.get(field):refs.append(record[field])
        refs.extend(record.get('binding_refs',[]));refs.extend(record.get('condition_refs',[]))
        refs.extend(record.get('provenance',{}).get('support_refs',[]))
        for ref in dict.fromkeys(refs):
            if ref in seen:continue
            seen.add(ref)
            if len(values)>=q.limit:pending.append(ref);continue
            found=view.get_records([ref],limit=1)
            if found.missing_refs:missing.extend(found.missing_refs);continue
            value=found.records[0].model_dump(mode='json')
            if value['id']!=ref:raise ValueError('Stored query support identity mismatch')
            values[ref]=value;queue.append(value)
    return list(values.values()),truncated or bool(pending),list(dict.fromkeys(missing)),{
        **filters,'support_policy':'bounded explicit reference closure; no automatic consumers',
        'pending_support_refs':pending,'support_closure_complete':not pending and not missing}


def _make_receipt(view,identity,budget,q,previous):
    if q.apk_sha256!=identity['apk_sha256'] or q.run_ref!=identity['run_ref']:
        raise ValueError('Queries are limited to the current APK and analysis run')
    request=q.model_dump(mode='json');digest=fingerprint(request)
    remaining_records = budget.max_records - sum(len(x['records']) for x in previous)
    remaining_chars = budget.max_return_chars - sum(x['returned_chars'] for x in previous)
    exhausted = sum(x['budget_charged'] for x in previous) >= budget.max_queries or remaining_records <= 0 or remaining_chars <= 0
    response = {'protocol': 'current-fact-query-result.v1', 'query': request, 'query_hash': digest,
        'source': deepcopy(identity), 'state': 'budget_exhausted' if exhausted else 'completed',
        'records': [], 'truncated': False, 'missing_refs': [], 'filters': {},
        'budget_charged': not exhausted,
        'coverage': dict(view.manifest.coverage), 'returned_chars': 0,
        'raw_archive_authorized': False, 'no_match_does_not_prove_absence': True}
    if not exhausted:
        try:
            records, truncated, missing, filters = _select(view, q)
            response.update(truncated=truncated, missing_refs=missing, filters=filters)
            for record in records:
                if record.get('run_ref') != view.run_ref: raise ValueError('Stored fact has wrong run')
                chars = len(canonical_json(record))
                if len(response['records']) >= remaining_records or response['returned_chars'] + chars > remaining_chars:
                    response['truncated'] = True; break
                response['records'].append(record); response['returned_chars'] += chars
            if not records: response['state'] = 'ran_no_matching_fact'
            if records and not response['records']: response['state'] = 'budget_exhausted'
        except (ValueError, OSError, sqlite3.Error) as error:
            response.update(state='failed', reason=str(error), records=[], returned_chars=0)
    response['receipt_id'] = 'fact-query:' + fingerprint(response)
    return response


class FactQuerySession:
    """Durable cumulative budgets. Replaying an identical ID returns its receipt."""
    def __init__(self, path, view, budget=None):
        self.view = view
        self.budget = budget or FactQueryBudget()
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute('CREATE TABLE IF NOT EXISTS metadata(identity TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS queries(query_id TEXT PRIMARY KEY, query_hash TEXT NOT NULL, response TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS uses(receipt_id TEXT NOT NULL, request_id TEXT NOT NULL, refs TEXT NOT NULL, PRIMARY KEY(receipt_id,request_id))')
        self.identity = {'apk_sha256': view.manifest.apk_sha256, 'run_ref': view.run_ref,
            'snapshot_id': view.snapshot_id, 'budget': self.budget.model_dump(mode='json')}
        row = self.db.execute('SELECT identity FROM metadata').fetchone()
        if row and json.loads(row[0]) != self.identity:
            self.close()
            raise ValueError('Fact query session cannot change APK/run/snapshot or frozen total budget')
        if not row:
            self.db.execute('INSERT INTO metadata VALUES (?)', (canonical_json(self.identity),))

    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self, *args): self.close()

    def execute(self, value):
        q = CurrentFactQuery.model_validate(value.model_dump(mode='json') if isinstance(value,CurrentFactQuery) else value)
        if q.apk_sha256 != self.view.manifest.apk_sha256 or q.run_ref != self.view.run_ref:
            raise ValueError('Queries are limited to the current APK and analysis run')
        request = q.model_dump(mode='json'); digest = fingerprint(request)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            old = self.db.execute('SELECT query_hash,response FROM queries WHERE query_id=?', (q.query_id,)).fetchone()
            if old:
                if old[0] != digest: raise ValueError('Query ID reused for different content')
                self.db.execute('COMMIT'); return json.loads(old[1])
            previous = [json.loads(x[0]) for x in self.db.execute('SELECT response FROM queries')]
            response = _make_receipt(self.view,self.identity,self.budget,q,previous)
            self.db.execute('INSERT INTO queries VALUES (?,?,?)', (q.query_id, digest, canonical_json(response)))
            self.db.execute('COMMIT'); return response
        except BaseException:
            self.db.execute('ROLLBACK'); raise

    def record_use(self, receipt_id, request_id, record_refs):
        rows = [json.loads(r[0]) for r in self.db.execute('SELECT response FROM queries')]
        receipt = next((r for r in rows if r['receipt_id'] == receipt_id), None)
        if receipt is None or not set(record_refs) <= {r['id'] for r in receipt['records']}:
            raise ValueError('Only actually returned records can be marked used')
        value = canonical_json(sorted(set(record_refs)))
        old = self.db.execute('SELECT refs FROM uses WHERE receipt_id=? AND request_id=?', (receipt_id, request_id)).fetchone()
        if old and old[0] != value: raise ValueError('Use audit cannot be rewritten')
        self.db.execute('INSERT OR IGNORE INTO uses VALUES (?,?,?)', (receipt_id, request_id, value))

    def report(self):
        queries = [json.loads(r[0]) for r in self.db.execute('SELECT response FROM queries ORDER BY rowid')]
        return {'identity': self.identity, 'queries': queries, 'uses': [dict(receipt_id=r[0], request_id=r[1], record_refs=json.loads(r[2]))
            for r in self.db.execute('SELECT receipt_id,request_id,refs FROM uses ORDER BY rowid')],
            'budget_used': {'queries': sum(q['budget_charged'] for q in queries), 'denied_requests':sum(not q['budget_charged'] for q in queries),
                'records': sum(len(q['records']) for q in queries),
                'returned_chars': sum(q['returned_chars'] for q in queries)}}


def verify_query_report(report, view):
    """Replay allowed selection and actual returned bytes without executing SQL from a model."""
    identity=report['identity']
    if (identity['apk_sha256']!=view.manifest.apk_sha256 or identity['run_ref']!=view.run_ref or
            identity['snapshot_id']!=view.snapshot_id):raise ValueError('Query audit belongs to another current snapshot')
    receipts={};charged=0;records=0;chars=0;prior=[];query_ids=set()
    budget=FactQueryBudget.model_validate(identity['budget'])
    for receipt in report['queries']:
        body=deepcopy(receipt);rid=body.pop('receipt_id')
        if rid!='fact-query:'+fingerprint(body):raise ValueError('Query receipt content changed')
        query=CurrentFactQuery.model_validate(receipt['query'])
        if query.query_id in query_ids:raise ValueError('An executed query ID appears twice in the audit')
        query_ids.add(query.query_id)
        if fingerprint(receipt['query'])!=receipt['query_hash'] or receipt['source']!=identity:
            raise ValueError('Query source or selector changed')
        charged+=int(receipt['budget_charged'])
        records+=len(receipt['records']);actual_chars=sum(len(canonical_json(r)) for r in receipt['records']);chars+=actual_chars
        if actual_chars!=receipt['returned_chars']:raise ValueError('Returned fact size differs')
        if receipt != _make_receipt(view,identity,budget,query,prior):
            raise ValueError('Query receipt differs from actual selection, outcome, truncation or cumulative budget')
        prior.append(receipt)
        receipts[rid]=receipt
    budget=FactQueryBudget.model_validate(identity['budget'])
    if charged>budget.max_queries or records>budget.max_records or chars>budget.max_return_chars:
        raise ValueError('Fact query cumulative budget exceeded')
    if report['budget_used']!={'queries':charged,'denied_requests':sum(not r['budget_charged'] for r in prior),
            'records':records,'returned_chars':chars}:raise ValueError('Query budget report differs from actual receipts')
    for use in report['uses']:
        if use['receipt_id'] not in receipts or not set(use['record_refs'])<={r['id'] for r in receipts[use['receipt_id']]['records']}:
            raise ValueError('Use audit cites facts not actually returned')
    return {'valid':True,'queries_run':charged,'records_returned':records,'returned_chars':chars,
        'actual_use_records':len(report['uses'])}
