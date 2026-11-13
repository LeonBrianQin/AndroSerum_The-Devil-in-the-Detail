"""Opt-in query receipts that reuse exact prior records without refunding spend.

Legacy receipts stay byte-identical. A new immutable mining segment may pin
this policy and a nondecreasing budget; original duplicate charges are retained.
"""
from copy import deepcopy
import json
import sqlite3

from .identity import canonical_json, fingerprint
from .queries import CurrentFactQuery, FactQueryBudget, FactQuerySession, _select, verify_query_report

POLICY='exact-record-reuse.v2'


def records_for(receipt,report):
    if not receipt.get('reused_records'):return receipt['records']
    queries=report['queries'];index=next(i for i,r in enumerate(queries) if r['receipt_id']==receipt['receipt_id'])
    return resolved_records(receipt,queries[:index])


def resolved_records(receipt, previous):
    """Expand only exact prior receipt grants, never an archive reference."""
    by_id={r['receipt_id']:r for r in previous}
    result=list(receipt['records']);seen={r['id'] for r in result}
    for reuse in receipt.get('reused_records',[]):
        origin=by_id.get(reuse['receipt_id'])
        if origin is None:raise ValueError('Reused fact lacks a preceding receipt')
        record=next((r for r in origin['records'] if r['id']==reuse['record_ref']),None)
        if record is None or fingerprint(record)!=reuse['record_sha256']:
            raise ValueError('Reused fact differs from its original returned bytes')
        if record['id'] in seen:raise ValueError('Duplicate new/reused fact in one receipt')
        seen.add(record['id']);result.append(record)
    return result


def _make(view,identity,budget,q,previous):
    if (q.apk_sha256,q.run_ref)!=(identity['apk_sha256'],identity['run_ref']):
        raise ValueError('Queries are limited to the current APK and analysis run')
    prior={}
    for receipt in previous:
        for record in receipt['records']:
            if record['id'] in prior and prior[record['id']][1]!=record:
                raise ValueError('Prior receipts disagree on the same fact')
            prior.setdefault(record['id'],(receipt['receipt_id'],record))
    used_records=sum(len(r['records']) for r in previous)
    used_chars=sum(r['returned_chars'] for r in previous)
    exhausted=sum(r['budget_charged'] for r in previous)>=budget.max_queries
    response={'protocol':'current-fact-query-result.v2','query':q.model_dump(mode='json'),
        'query_hash':fingerprint(q.model_dump(mode='json')),'source':deepcopy(identity),
        'state':'budget_exhausted' if exhausted else 'completed','records':[],
        'reused_records':[],'truncated':False,'missing_refs':[],'filters':{},
        'budget_charged':not exhausted,'coverage':dict(view.manifest.coverage),'returned_chars':0,
        'raw_archive_authorized':False,'no_match_does_not_prove_absence':True}
    if not exhausted:
        try:
            records,cut,missing,filters=_select(view,q)
            response.update(truncated=cut,missing_refs=missing,filters=filters)
            omitted=[]
            for record in records:
                if record.get('run_ref')!=identity['run_ref']:raise ValueError('Wrong-run stored fact')
                if record['id'] in prior:
                    origin,old=prior[record['id']]
                    if old!=record:raise ValueError('Cached fact changed in the current snapshot')
                    reference={'receipt_id':origin,'record_ref':record['id'],'record_sha256':fingerprint(record)}
                    chars=len(canonical_json(reference))
                    if used_chars+response['returned_chars']+chars>budget.max_return_chars:
                        omitted.append(record['id']);continue
                    response['reused_records'].append(reference)
                else:
                    chars=len(canonical_json(record))
                    if (used_records+len(response['records'])>=budget.max_records or
                            used_chars+response['returned_chars']+chars>budget.max_return_chars):
                        omitted.append(record['id']);continue
                    response['records'].append(record)
                response['returned_chars']+=chars
            if omitted:
                response['truncated']=True;response['filters']['budget_omitted_record_refs']=omitted
            if not records:response['state']='ran_no_matching_fact'
            elif not response['records'] and not response['reused_records']:response['state']='budget_exhausted'
        except (ValueError,OSError,sqlite3.Error) as error:
            response.update(state='failed',reason=str(error),records=[],reused_records=[],returned_chars=0)
    response['receipt_id']='fact-query:'+fingerprint(response)
    # Immediate admission and replay must see the same field ordering as the
    # durable canonical receipt, including shown_fields derived by adapters.
    return json.loads(canonical_json(response))


class ReusableFactQuerySession(FactQuerySession):
    def __init__(self,path,view,budget=None,*,amendment_reason=None):
        self.view=view;self.budget=budget or FactQueryBudget()
        # Read the copied predecessor before adding any new metadata.
        db=sqlite3.connect(path,isolation_level=None)
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        old_identity=json.loads(db.execute('SELECT identity FROM metadata').fetchone()[0]) if 'metadata' in tables else None
        old_policy=json.loads(db.execute('SELECT payload FROM delivery_policy').fetchone()[0]) if 'delivery_policy' in tables else None
        db.close()
        requested={'apk_sha256':view.manifest.apk_sha256,'run_ref':view.run_ref,
            'snapshot_id':view.snapshot_id,'budget':self.budget.model_dump(mode='json')}
        if old_policy:
            if old_policy['policy']!=POLICY or old_identity!=requested:raise ValueError('Cannot change a pinned reuse session')
            super().__init__(path,view,self.budget);self.policy=old_policy;return
        if old_identity:
            old_budget=FactQueryBudget.model_validate(old_identity['budget'])
            with FactQuerySession(path,view,old_budget) as legacy:prior=legacy.report()
            verify_query_report(prior,view)
            if {k:v for k,v in requested.items() if k!='budget'}!={k:v for k,v in old_identity.items() if k!='budget'}:
                raise ValueError('Continuation cannot change APK/run/snapshot')
            if requested['budget']!=old_identity['budget'] and (not amendment_reason or
                    any(requested['budget'][k]<v for k,v in old_identity['budget'].items())):
                raise ValueError('A budget increase requires an explicit cumulative amendment')
        else:
            with FactQuerySession(path,view,self.budget) as legacy:prior=legacy.report()
        self.policy={'policy':POLICY,'legacy_identity':prior['identity'],'legacy_prefix_count':len(prior['queries']),
            'legacy_budget_used':prior['budget_used'],'legacy_uses':prior['uses'],
            'legacy_report_sha256':fingerprint(prior),'amendment_reason':amendment_reason,
            'historical_charges_refunded':False}
        db=sqlite3.connect(path,isolation_level=None)
        try:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE metadata SET identity=?',(canonical_json(requested),))
            db.execute('CREATE TABLE delivery_policy(payload TEXT NOT NULL)')
            db.execute('INSERT INTO delivery_policy VALUES (?)',(canonical_json(self.policy),))
            db.execute('COMMIT')
        finally:db.close()
        super().__init__(path,view,self.budget)

    def execute(self,value):
        q=CurrentFactQuery.model_validate(value.model_dump(mode='json') if isinstance(value,CurrentFactQuery) else value)
        if (q.apk_sha256,q.run_ref)!=(self.identity['apk_sha256'],self.identity['run_ref']):raise ValueError('Cross-APK query')
        digest=fingerprint(q.model_dump(mode='json'));self.db.execute('BEGIN IMMEDIATE')
        try:
            old=self.db.execute('SELECT query_hash,response FROM queries WHERE query_id=?',(q.query_id,)).fetchone()
            if old:
                if old[0]!=digest:raise ValueError('Query ID reused for different content')
                self.db.execute('COMMIT');return json.loads(old[1])
            previous=[json.loads(r[0]) for r in self.db.execute('SELECT response FROM queries ORDER BY rowid')]
            receipt=_make(self.view,self.identity,self.budget,q,previous)
            self.db.execute('INSERT INTO queries VALUES (?,?,?)',(q.query_id,digest,canonical_json(receipt)))
            self.db.execute('COMMIT');return receipt
        except BaseException:self.db.execute('ROLLBACK');raise

    def record_use(self,receipt_id,request_id,record_refs):
        receipts=[json.loads(r[0]) for r in self.db.execute('SELECT response FROM queries ORDER BY rowid')]
        receipt=next((r for r in receipts if r['receipt_id']==receipt_id),None)
        if receipt is None or not set(record_refs)<={r['id'] for r in resolved_records(receipt,receipts[:receipts.index(receipt)])}:
            raise ValueError('Use is not authorized by returned or reused facts')
        value=canonical_json(sorted(set(record_refs)))
        old=self.db.execute('SELECT refs FROM uses WHERE receipt_id=? AND request_id=?',(receipt_id,request_id)).fetchone()
        if old and old[0]!=value:raise ValueError('Use audit cannot change')
        self.db.execute('INSERT OR IGNORE INTO uses VALUES (?,?,?)',(receipt_id,request_id,value))

    def report(self):return {**super().report(),'delivery_policy':deepcopy(self.policy)}


def verify_reuse_report(report,view):
    policy=report['delivery_policy'];identity=report['identity'];budget=FactQueryBudget.model_validate(identity['budget'])
    if policy['policy']!=POLICY or policy['historical_charges_refunded'] is not False:raise ValueError('Unknown reuse policy')
    n=policy['legacy_prefix_count'];prefix=report['queries'][:n]
    legacy={'identity':policy['legacy_identity'],'queries':prefix,'uses':policy['legacy_uses'],'budget_used':policy['legacy_budget_used']}
    if fingerprint(legacy)!=policy['legacy_report_sha256']:raise ValueError('Historical query audit changed')
    verify_query_report(legacy,view)
    if {k:v for k,v in identity.items() if k!='budget'}!={k:v for k,v in legacy['identity'].items() if k!='budget'}:
        raise ValueError('Query source changed')
    if any(identity['budget'][k]<v for k,v in legacy['identity']['budget'].items()):raise ValueError('Historical budget decreased')
    if identity['budget']!=legacy['identity']['budget'] and not policy['amendment_reason']:raise ValueError('Missing cumulative amendment')
    previous=list(prefix);ids={q['query']['query_id'] for q in prefix}
    for receipt in report['queries'][n:]:
        query=CurrentFactQuery.model_validate(receipt['query'])
        if query.query_id in ids:raise ValueError('Repeated query ID')
        if receipt!=_make(view,identity,budget,query,previous):raise ValueError('Reuse selection/charges/record reference differs')
        resolved_records(receipt,previous);ids.add(query.query_id);previous.append(receipt)
    expected={'queries':sum(r['budget_charged'] for r in previous),'denied_requests':sum(not r['budget_charged'] for r in previous),
        'records':sum(len(r['records']) for r in previous),'returned_chars':sum(r['returned_chars'] for r in previous)}
    if expected!=report['budget_used'] or expected['queries']>budget.max_queries or expected['records']>budget.max_records or expected['returned_chars']>budget.max_return_chars:
        raise ValueError('Cumulative query spend changed or exceeded')
    receipts={r['receipt_id']:r for r in previous}
    for use in report['uses']:
        receipt=receipts.get(use['receipt_id'])
        if receipt is None or not set(use['record_refs'])<={r['id'] for r in resolved_records(receipt,previous[:previous.index(receipt)])}:
            raise ValueError('Forged query use')
    return {'valid':True,'queries_run':expected['queries'],'records_returned':expected['records'],
        'returned_chars':expected['returned_chars'],'actual_use_records':len(report['uses']),
        'reused_record_references':sum(len(r.get('reused_records',[])) for r in previous),'historical_spend_preserved':True}
