"""Attached SQLite batch accounting: reserves atomically with native child calls."""
import json
from pathlib import Path
from androserum.facts.identity import sha256_file, fingerprint, canonical_json


def initialize(root, policy, plan):
    import sqlite3
    root=Path(root)
    db=sqlite3.connect(root/'batch-call-budget.sqlite', isolation_level=None)
    try:
        db.execute('CREATE TABLE IF NOT EXISTS config (payload TEXT NOT NULL)')
        value={'policy':policy,'plan_sha256':fingerprint(plan)}
        old=db.execute('SELECT payload FROM config').fetchone()
        if old and json.loads(old[0])!=value:raise ValueError('Batch budget cannot be replaced or reset')
        if not old:db.execute('INSERT INTO config VALUES (?)',(canonical_json(value),))
        db.execute('CREATE TABLE IF NOT EXISTS calls (call_id TEXT PRIMARY KEY,sample_id TEXT NOT NULL,phase TEXT NOT NULL,pilot INTEGER NOT NULL,chars INTEGER NOT NULL,status TEXT NOT NULL,receipt TEXT)')
    finally:db.close()


def attach(native):
    binding=native.root/'batch-budget-binding.json'
    native.batch_binding=None
    if not binding.is_file():return
    value=json.loads(binding.read_text('utf-8'))
    body={k:v for k,v in value.items() if k!='binding_sha256'}
    if value.get('binding_sha256')!=fingerprint(body):raise ValueError('Batch binding checksum differs')
    root=Path(value['batch_root'])
    for name,digest in value['files'].items():
        if sha256_file(root/name)!=digest:raise ValueError('Batch frozen file changed: '+name)
    if fingerprint(native.config)!=value['child_config_sha256']:raise ValueError('Child config differs from batch binding')
    if not (root/'batch-call-budget.sqlite').is_file():raise ValueError('Missing batch budget; never recreate at dispatch')
    native.db.execute('ATTACH DATABASE ? AS batch_budget',(str(root/'batch-call-budget.sqlite'),))
    stored=json.loads(native.db.execute('SELECT payload FROM batch_budget.config').fetchone()[0])
    policy=json.loads((root/'policy.frozen.json').read_text('utf-8'))
    plan=json.loads((root/'measured-dispatch-plan.json').read_text('utf-8'))
    if stored!={'policy':policy,'plan_sha256':fingerprint(plan)}:raise ValueError('Batch database identity differs')
    native.batch_binding={**value,'policy':policy,'plan':plan}


def reason(native, sample, chars):
    binding=native.batch_binding
    if binding is None:return None
    if sample!=binding['sample_id']:return 'batch_sample_identity_conflict'
    rows=native.db.execute('SELECT sample_id,pilot,chars,status,receipt FROM batch_budget.calls').fetchall()
    policy=binding['policy'];pilot=sample in binding['plan']['pilot_sample_ids']
    for owner,_,_,status,raw in rows:
        if status=='reserved' or not raw:return 'batch_unconfirmed_dispatch_requires_reconciliation'
        receipt=json.loads(raw);usage=receipt.get('usage') or {}
        if owner==sample and receipt.get('service_refusal'):return 'sample_terminal_safety_refusal_no_retry'
        if type(usage.get('input_tokens')) is not int or usage['input_tokens']<0:
            return 'batch_unknown_input_usage_stop'
    if sum(r[0]==sample for r in rows)>=policy['per_apk_call_attempts_cap']:return 'batch_per_apk_call_cap'
    for scope,subset,caps in [('whole_batch',rows,policy['whole_batch_caps']),
                             *([('pilot',[r for r in rows if r[1]],policy['pilot_caps'])] if pilot else [])]:
        if len(subset)>=caps['call_attempts']:return scope+'_call_cap'
        if sum(r[2] for r in subset)+chars>caps['reserved_input_chars']:return scope+'_input_char_cap'
        if sum(json.loads(r[4])['usage']['input_tokens'] for r in subset)>=caps['reported_input_token_stop']:
            return scope+'_reported_token_stop'
    return None


def reserve(native,sample,phase,call_id,chars):
    if native.batch_binding is None:return
    stop=reason(native,sample,chars)
    if stop:raise ValueError('Batch undispatched: '+stop)
    pilot=int(sample in native.batch_binding['plan']['pilot_sample_ids'])
    native.db.execute('INSERT INTO batch_budget.calls VALUES (?,?,?,?,?,?,NULL)',
                     (call_id,sample,phase,pilot,chars,'reserved'))


def finish(native,call_id,receipt):
    if native.batch_binding is None:return
    row=native.db.execute('SELECT status FROM batch_budget.calls WHERE call_id=?',(call_id,)).fetchone()
    if not row:raise ValueError('Receipt has no batch reservation')
    native.db.execute('UPDATE batch_budget.calls SET status=?,receipt=? WHERE call_id=?',
                     (receipt['status'],canonical_json(receipt),call_id))


def report(root):
    import sqlite3
    from datetime import datetime
    db=sqlite3.connect(Path(root)/'batch-call-budget.sqlite')
    try:
        rows=[{'call_id':a,'sample_id':b,'phase':c,'pilot':bool(d),'reserved_input_chars':e,'status':f,
               'receipt':json.loads(g) if g else None}
              for a,b,c,d,e,f,g in db.execute('SELECT * FROM calls ORDER BY rowid')]
        policy=json.loads(db.execute('SELECT payload FROM config').fetchone()[0])['policy']
        def summarize(items):
            usages=[]
            for row in items:
                raw=(row['receipt'] or {}).get('usage')
                usages.append(None if raw is None else {'input_tokens':raw.get('input_tokens'),
                    'output_tokens':raw.get('output_tokens'),
                    'cached_input_tokens':raw.get('cached_input_tokens',(raw.get('input_tokens_details') or {}).get('cached_tokens'))})
            known=[u for u in usages if u is not None and all(type(u.get(k)) is int and u[k]>=0 for k in ['input_tokens','output_tokens','cached_input_tokens'])]
            def subtotal(key):
                values=[u[key] for u in usages if u and type(u.get(key)) is int and u[key]>=0]
                return sum(values) if values or not items else None
            durations=[]
            for item in items:
                receipt=item['receipt'] or {}
                if receipt.get('started_utc') and receipt.get('finished_utc'):
                    durations.append((datetime.fromisoformat(receipt['finished_utc'])-datetime.fromisoformat(receipt['started_utc'])).total_seconds())
            return {'call_attempts':len(items),'usage_known_calls':len(known),'usage_unknown_calls':len(items)-len(known),
                'reported_input_tokens':subtotal('input_tokens'),
                'reported_output_tokens':subtotal('output_tokens'),
                'reported_cached_input_tokens':subtotal('cached_input_tokens'),
                'reserved_input_chars':sum(r['reserved_input_chars'] for r in items),'monetary_cost':None,
                'reported_tokens_are_known_subtotals':True,'missing_usage_is_not_zero_cost':True,
                'provider_duration_seconds_sum':sum(durations),'provider_duration_known_calls':len(durations),
                'duration_scope':'Sum of provider call durations; excludes static work and orchestration wall time',
                'calls':[{'status':r['status'],'usage':usage} for r,usage in zip(items,usages)]}
        return {'policy':policy,'calls':rows,'whole_batch':summarize(rows),
                'pilot':summarize([r for r in rows if r['pilot']]),
                'phases':{s:summarize([r for r in rows if r['phase']==s]) for s in ['mining','matching','task']},
                'samples':{s:summarize([r for r in rows if r['sample_id']==s]) for s in {r['sample_id'] for r in rows}}}
    finally:db.close()
