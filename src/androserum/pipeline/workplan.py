"""Complete discovered work inventory; selection and completion are separate.

All known physical anchors, roots, contexts, BUs, blocks and accepted BCs have
stable identities. Resource caps leave explicit pending work, not false APK
completion. Ledger segments and spent budgets are append-only across resumes.
"""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

from androserum.facts.identity import canonical_json, fingerprint, filesystem_path
from androserum.inference.provider import write
from androserum.mining.evidence import EvidenceCatalog

STATES = {'not_selected', 'pending', 'running', 'failed', 'truncated', 'completed', 'superseded'}


def discover_plan(prepared, matches, collection, mining_config, *, packing_profile=None):
    source = {k:prepared[k] for k in ('apk_sha256', 'source_run_ref')}
    source['snapshot'] = prepared['snapshot']
    snapshot_manifest=filesystem_path(prepared['snapshot'])/'manifest.json'
    manifest=json.loads(snapshot_manifest.read_text('utf-8')) if snapshot_manifest.exists() else None
    source['source_snapshot_id']=manifest['snapshot_id'] if manifest else (collection or {}).get('source_snapshot_id')
    source['extraction_run_ref']=(collection or {}).get('extraction_run_ref')
    if collection and manifest and (collection['source_snapshot_id']!=manifest['snapshot_id'] or
            collection['source_run_ref']!=source['source_run_ref'] or collection['apk_sha256']!=source['apk_sha256']):
        raise ValueError('Candidate plan BU package does not match the actual prepared snapshot')
    items = {}
    def add(kind, key, payload, state='pending', reason=None):
        item_id = kind + ':' + fingerprint(key)[:24]
        row = {'item_id':item_id, 'kind':kind, 'payload':deepcopy(payload), 'initial_state':state, 'reason':reason}
        if item_id in items and items[item_id] != row: raise ValueError('Conflicting discovered candidate identity')
        items[item_id] = row
        return item_id
    selected = set(prepared.get('selected_roots', []))
    method_refs={r['signature']:r['method_ref'] for r in prepared.get('root_discovery',[]) or []}
    if collection:
        for unit in collection['units']:
            method_refs.update({r['signature']:r['id'] for r in unit['model_visible']['records'] if r.get('kind')=='method'})
    for signature in prepared.get('available_sapi_roots', []):
        add('root', signature, {'signature':signature,'method_ref':method_refs.get(signature), 'selected_for_materialization':signature in selected},
            reason=None if signature in selected else 'Root materialization budget; context discovery still pending')
    physical = {}
    for match in matches.get('matches', []):
        key = match['callsite_ref']
        physical.setdefault(key, {'callsite_ref':key, 'method_ref':match['method_ref'], 'matches':[]})['matches'].append(match)
    for key, row in physical.items(): add('physical_anchor', key, row)
    if collection:
        for row in collection.get('anchor_context_table', []):
            add('anchor_context', row, row)
        for row in collection.get('selection', {}).get('pending_anchors', []):
            add('anchor_context', row, row, reason='Discovered context awaiting BU materialization')
        for ref, failure in collection.get('selection', {}).get('graph_failures', {}).items():
            add('context_failure', ref, {'root_method_ref':ref, **failure}, 'failed', failure.get('reason'))
        for ref in collection.get('selection', {}).get('pending_roots', []):
            add('context_pending', ref, {'root_method_ref':ref}, reason='Context graph budget')
        for unit in collection['units']:
            add('bu', unit['bu_id'], {'bu_id':unit['bu_id'], 'anchor':unit['anchor'],
                'extraction_status':unit['extraction_status']})
        # A scheduling cap must not erase the remainder of the block plan.
        if packing_profile is None:
            catalog = EvidenceCatalog(collection, [u['bu_id'] for u in collection['units']])
        else:
            from androserum.mining_catalog import catalog_for
            catalog = catalog_for(collection, [u['bu_id'] for u in collection['units']],
                                  packing_profile=packing_profile)
        full_config = mining_config.model_copy(update={'max_chunks':max(10000,mining_config.max_chunks)})
        chunks, pending = catalog.chunks(full_config)
        for chunk in chunks:
            cid = 'chunk_' + fingerprint(chunk)[:16]
            add('block', cid, {'chunk_id':cid, 'chunk':chunk})
        for row in pending:
            add('unpackable_evidence', row, row, 'truncated', row['reason'])
    values = list(items.values())
    result={'schema_version':'apk-complete-candidate-plan.v1', 'source':source,
        'scope':'All anchors discovered in the current fact export; unresolved/unmaterialized contexts remain explicit pending work',
        'discovered_physical_anchors':len(physical), 'items':values, 'plan_id':fingerprint([source,values]),
        'selected_bu_subset_is_not_apk_completion':True, 'semantic_completeness_claimed':False}
    if packing_profile is not None:
        result['packing_profile']=packing_profile
        result['packing_rule_sha256']=catalog.identity['packing_rule_sha256'] if collection else None
    return result


class CandidatePlan:
    def __init__(self, directory, plan=None, *, budget=None):
        self.root = filesystem_path(directory); self.root.mkdir(parents=True, exist_ok=True)
        if plan is not None:
            binding = {'plan':plan, 'budget':budget}
            if (self.root/'plan.json').exists():
                if json.loads((self.root/'plan.json').read_text('utf-8')) != binding:
                    raise ValueError('Cannot change complete candidate plan or cumulative budget on resume')
            else: write(self.root/'plan.json', binding)
        binding = json.loads((self.root/'plan.json').read_text('utf-8'))
        self.plan = binding['plan']; self.budget = binding['budget']
        if not isinstance(self.budget, dict) or set(self.budget) != {'max_model_calls','max_input_chars','max_reported_input_tokens'}:
            raise ValueError('Freeze explicit cumulative call and input budgets before processing')
        if any(type(v) is not int or v < 0 for v in self.budget.values()): raise ValueError('Invalid cumulative budget')
        self.db = sqlite3.connect(self.root/'progress.sqlite', isolation_level=None)
        self.db.executescript('''CREATE TABLE IF NOT EXISTS items(id TEXT PRIMARY KEY,kind TEXT,payload TEXT,state TEXT,reason TEXT);
            CREATE TABLE IF NOT EXISTS events(n INTEGER PRIMARY KEY,previous_hash TEXT,payload TEXT,hash TEXT UNIQUE);
            CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,payload TEXT,chars INTEGER,tokens INTEGER);
            CREATE TABLE IF NOT EXISTS reservations(request_id TEXT PRIMARY KEY,chars INTEGER NOT NULL,tokens INTEGER NOT NULL,status TEXT NOT NULL,receipt_hash TEXT);
            CREATE TABLE IF NOT EXISTS segments(id TEXT PRIMARY KEY,hash TEXT,report TEXT);''')
        for row in self.plan['items']:
            self.db.execute('INSERT OR IGNORE INTO items VALUES (?,?,?,?,?)',
                (row['item_id'],row['kind'],canonical_json(row['payload']),row['initial_state'],row['reason']))

    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self,*args): self.close()

    def _event(self, value):
        old = self.db.execute('SELECT hash FROM events ORDER BY n DESC LIMIT 1').fetchone()
        parent = old[0] if old else self.plan['plan_id']
        digest = fingerprint([parent,value])
        self.db.execute('INSERT INTO events(previous_hash,payload,hash) VALUES (?,?,?)', (parent,canonical_json(value),digest))

    def transition(self, item_id, state, reason):
        if state not in STATES or not str(reason).strip(): raise ValueError('Explicit work state and grounds required')
        old = self.db.execute('SELECT state FROM items WHERE id=?',(item_id,)).fetchone()
        if not old: raise ValueError('Undiscovered work item')
        if old[0] == state: return
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('UPDATE items SET state=?,reason=? WHERE id=?',(state,reason,item_id))
            self._event({'item_id':item_id,'before':old[0],'after':state,'reason':reason})
            self.db.execute('COMMIT')
        except BaseException: self.db.execute('ROLLBACK'); raise

    def remaining(self):
        calls, chars, tokens = self.db.execute('SELECT COUNT(*),COALESCE(SUM(chars),0),COALESCE(SUM(tokens),0) FROM reservations').fetchone()
        return {'max_model_calls':self.budget['max_model_calls']-calls,
            'max_input_chars':self.budget['max_input_chars']-chars,
            'max_reported_input_tokens':self.budget['max_reported_input_tokens']-tokens}

    def record_mining_finalization(self, item_id, payload, state, reason):
        """Append bounded final-review work without changing the original plan."""
        if not item_id.startswith('mining_finalization:') or state not in STATES or not reason:
            raise ValueError('Explicit finalization identity/state/reason required')
        value=(canonical_json(payload),state,reason)
        old=self.db.execute('SELECT payload,state,reason FROM items WHERE id=?',(item_id,)).fetchone()
        if old==value:return
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT INTO items VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,state=excluded.state,reason=excluded.reason',
                (item_id,'mining_finalization',*value))
            self._event({'item_id':item_id,'kind':'mining_finalization','before':old[1] if old else None,
                         'after':state,'reason':reason,'payload_sha256':fingerprint(payload)})
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise

    def reserve(self,request_id,chars):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            if self.db.execute('SELECT 1 FROM reservations WHERE request_id=?',(request_id,)).fetchone():
                raise ValueError('Already reserved dispatch must be reconciled, never invoked twice')
            remaining=self.remaining()
            reason=('complete_plan_cumulative_call_budget' if remaining['max_model_calls']<=0 else
                'complete_plan_cumulative_input_budget' if chars>remaining['max_input_chars'] else
                'complete_plan_reported_input_token_stop' if remaining['max_reported_input_tokens']<=0 else None)
            if reason:self.db.execute('ROLLBACK');return reason
            self.db.execute('INSERT INTO reservations VALUES (?,?,0,?,NULL)',(request_id,chars,'reserved_dispatch_not_confirmed'))
            self._event({'request_id':request_id,'action':'reserve_before_dispatch','input_chars_reserved':chars,
                'unconfirmed_cost_is_unknown':True})
            self.db.execute('COMMIT');return None
        except BaseException:self.db.execute('ROLLBACK');raise

    def settle(self,request_id,receipt):
        digest=fingerprint(receipt)
        row=self.db.execute('SELECT chars,status,receipt_hash FROM reservations WHERE request_id=?',(request_id,)).fetchone()
        if not row:raise ValueError('Dispatch receipt has no durable reservation')
        if row[2]:
            if row[2]!=digest:raise ValueError('Dispatch receipt cannot change')
            return
        chars=receipt.get('application_context_chars',row[0]);tokens=(receipt.get('usage') or {}).get('input_tokens',0)
        if chars>row[0]:raise ValueError('Actual dispatch input exceeds reserved input')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('UPDATE reservations SET chars=?,tokens=?,status=?,receipt_hash=? WHERE request_id=?',
                (chars,tokens,'receipt_retained',digest,request_id))
            self._event({'request_id':request_id,'action':'settle_actual_receipt','receipt_sha256':digest})
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise

    def sync_mining(self, segment, report):
        if json.loads((filesystem_path(segment)/'report.json').read_text('utf-8')) != report:
            raise ValueError('Plan update must use the actual immutable mining segment report')
        if any(report['identity']['source'].get(k)!=self.plan['source'].get(k) for k in
                ('apk_sha256','source_run_ref','source_snapshot_id','extraction_run_ref')):
            raise ValueError('Mining segment belongs to another candidate-plan APK/run')
        sid = report['segment_ref']; digest = fingerprint(report)
        previous = self.db.execute('SELECT hash FROM segments WHERE id=?',(sid,)).fetchone()
        if previous:
            if previous[0] != digest: raise ValueError('A retained segment cannot be rewritten')
            return
        known = {json.loads(r[1])['chunk_id']:r[0] for r in self.db.execute("SELECT id,payload FROM items WHERE kind='block'")}
        for row in report['chunk_progress']:
            if row['chunk_id'] not in known and not row.get('work_amendment'):
                raise ValueError('Segment block absent from the complete frozen plan')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            for attempt in report['attempts']:
                old = self.db.execute('SELECT payload FROM attempts WHERE id=?',(attempt['attempt_id'],)).fetchone()
                serialized = canonical_json(attempt)
                if old:
                    if old[0] != serialized: raise ValueError('Prior attempt audit changed during continuation')
                    continue
                receipt = attempt['provider']; chars = receipt.get('application_context_chars',0)
                tokens = (receipt.get('usage') or {}).get('input_tokens',0)
                remaining = self.remaining()
                reserved=self.db.execute('SELECT 1 FROM reservations WHERE request_id=?',(attempt['request_id'],)).fetchone()
                if not reserved:
                    if remaining['max_model_calls']<1 or chars>remaining['max_input_chars'] or remaining['max_reported_input_tokens']<=0:
                        raise ValueError('Actual segment exceeds frozen cumulative plan budget')
                    self.db.execute('INSERT INTO reservations VALUES (?,?,?,?,?)',(attempt['request_id'],chars,tokens,
                        'receipt_retained',fingerprint(receipt)))
                self.db.execute('INSERT INTO attempts VALUES (?,?,?,?)',(attempt['attempt_id'],serialized,chars,tokens))
            for row in report['chunk_progress']:
                if row['chunk_id'] not in known: continue  # Explicit separately audited closure amendment.
                state = 'completed' if row['state']=='accepted' else 'failed' if row['state']=='rejected' else 'truncated' if row['state']=='blocked' else 'pending'
                iid = known[row['chunk_id']]
                old = self.db.execute('SELECT state FROM items WHERE id=?',(iid,)).fetchone()[0]
                self.db.execute('UPDATE items SET state=?,reason=? WHERE id=?',(state,canonical_json(row.get('reason')),iid))
                self._event({'item_id':iid,'before':old,'after':state,'segment_ref':sid})
            for bid,bc in report['accepted_state']['bcs'].items():
                iid = 'qualified_bc:'+fingerprint([report['identity'],bid])[:24]
                self.db.execute('INSERT INTO items VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,state=excluded.state,reason=excluded.reason',
                    (iid,'qualified_bc',canonical_json({'bc_id':bid,'model_bc':bc,'ledger_revision':report['accepted_state']['revision']}),'completed',
                     'Accepted by program checker; semantic assessment separate; downstream processing pending'))
                for stage in ('bc_encoding','bc_matching','bc_task'):
                    self.db.execute('INSERT OR IGNORE INTO items VALUES (?,?,?,?,?)',
                        (stage+':'+fingerprint([report['identity'],bid,report['accepted_state']['revision']])[:24],stage,
                         canonical_json({'bc_id':bid,'ledger_revision':report['accepted_state']['revision']}),'pending',
                         'All current program-qualified BCs enter the downstream plan; no semantic approval gate'))
            for iid,payload in self.db.execute("SELECT id,payload FROM items WHERE kind='qualified_bc'").fetchall():
                if json.loads(payload)['bc_id'] not in report['accepted_state']['bcs']:
                    self.db.execute("UPDATE items SET state='superseded',reason='Removed by later accepted native model update' WHERE id=?",(iid,))
            for iid,payload,state in self.db.execute("SELECT id,payload,state FROM items WHERE kind IN ('bc_encoding','bc_matching','bc_task')").fetchall():
                item=json.loads(payload)
                if item['bc_id'] not in report['accepted_state']['bcs'] or item['ledger_revision']!=report['accepted_state']['revision']:
                    self.db.execute("UPDATE items SET state='superseded',reason='Replaced by later accepted ledger revision; old work and outputs retained' WHERE id=?",(iid,))
                    if state!='superseded':self._event({'item_id':iid,'before':state,'after':'superseded','segment_ref':sid})
            blocks=[(json.loads(p),s) for p,s in self.db.execute("SELECT payload,state FROM items WHERE kind='block'")]
            bu_states={}
            for iid,payload in self.db.execute("SELECT id,payload FROM items WHERE kind='bu'").fetchall():
                unit=json.loads(payload);states=[s for b,s in blocks if unit['bu_id'] in b['chunk']['bu_ids']]
                state=('completed' if states and all(s=='completed' for s in states) else
                    'failed' if any(s=='failed' for s in states) else 'truncated' if any(s=='truncated' for s in states) else 'pending')
                bu_states[unit['bu_id']]=state
                self.db.execute('UPDATE items SET state=?,reason=? WHERE id=?',(state,'Aggregate of all discovered block states; extraction coverage retained separately',iid))
            for kind in ('anchor_context','physical_anchor','root'):
                for iid,payload in self.db.execute('SELECT id,payload FROM items WHERE kind=?',(kind,)).fetchall():
                    item=json.loads(payload)
                    units=[json.loads(p) for p, in self.db.execute("SELECT payload FROM items WHERE kind='bu'")]
                    related=[u for u in units if (kind=='anchor_context' and u['bu_id']==item.get('bu_id')) or
                        (kind=='physical_anchor' and u['anchor'].get('callsite_ref')==item.get('callsite_ref')) or
                        (kind=='root' and u['anchor'].get('root_method_ref')==item.get('method_ref'))]
                    states=[bu_states[u['bu_id']] for u in related]
                    if states and all(s=='completed' for s in states):
                        self.db.execute("UPDATE items SET state='completed',reason='All materialized associated BU blocks completed; pending contexts remain separate plan items' WHERE id=?",(iid,))
            self.db.execute('INSERT INTO segments VALUES (?,?,?)',(sid,digest,canonical_json({'path':str(segment),'report':report})))
            self._event({'segment_ref':sid,'report_sha256':digest,'attempts_cumulative':len(report['attempts'])})
            self.db.execute('COMMIT')
        except BaseException: self.db.execute('ROLLBACK'); raise

    def report(self):
        rows = [dict(item_id=r[0],kind=r[1],payload=json.loads(r[2]),state=r[3],reason=r[4])
                for r in self.db.execute('SELECT id,kind,payload,state,reason FROM items ORDER BY id')]
        previous = self.plan['plan_id']; events=[]
        for _,parent,payload,digest in self.db.execute('SELECT * FROM events ORDER BY n'):
            value = json.loads(payload)
            if parent != previous or digest != fingerprint([parent,value]): raise ValueError('Work-plan audit chain broken')
            events.append(value); previous=digest
        return {'plan_id':self.plan['plan_id'],'source':self.plan['source'],'items':rows,
            'counts':dict(Counter(r['state'] for r in rows)), 'by_kind':{kind:dict(Counter(r['state'] for r in rows if r['kind']==kind))
                for kind in sorted({r['kind'] for r in rows})}, 'remaining_budget':self.remaining(),
            'events':events,'audit_head':previous,'apk_all_discovered_work_completed':all(r['state'] in {'completed','superseded'} for r in rows),
            'semantic_completeness_claimed':False, 'pending_work_is_resumable':True,
            'dispatch_reservations':[dict(request_id=r[0],input_chars=r[1],reported_input_tokens=r[2],status=r[3],receipt_sha256=r[4])
                for r in self.db.execute('SELECT * FROM reservations ORDER BY rowid')],
            'reported_token_budget_is_stop_before_next_call_one_inflight_may_cross':True}

    def sync_downstream(self,entries,*,encoding=None,recalls=(),matches=(),task_runs=()):
        """Record actual downstream coverage for every qualified current BC."""
        versions={e['bc']['bc_id']:e['ledger_revision'] for e in entries}
        by_ref={e['qualified_ref']:e['bc']['bc_id'] for e in entries}
        def dynamic(kind,key,payload,state,reason):
            iid=kind+':'+fingerprint(key)[:24]
            old=self.db.execute('SELECT payload,state,reason FROM items WHERE id=?',(iid,)).fetchone()
            value=(canonical_json(payload),state,reason)
            if old==value:return
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO items VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,state=excluded.state,reason=excluded.reason',
                    (iid,kind,*value))
                self._event({'item_id':iid,'before':old[1] if old else None,'after':state,'actual_downstream_basis':payload})
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
        def aggregate(stage,bid,state,reason):
            for iid,payload in self.db.execute('SELECT id,payload FROM items WHERE kind=?',(stage,)).fetchall():
                item=json.loads(payload)
                if item['bc_id']==bid and item['ledger_revision']==versions[bid]:self.transition(iid,state,reason)
        if encoding:
            manifest=filesystem_path(encoding)/'manifest.json'
            from androserum.facts.identity import sha256_file
            for bid in versions:aggregate('bc_encoding',bid,'completed','Actual verified encoding manifest '+sha256_file(manifest))
        for recall in recalls:
            bid=recall.get('bc_id',by_ref.get(recall.get('query_ref')))
            if bid not in versions:raise ValueError('Recall is absent from the qualified BC plan')
            candidates=recall.get('ranked_candidates',[])
            states=[]
            for candidate in candidates:
                ref=candidate['instance_ref']
                result=next((m for m in matches if m['bc_id']==bid and m['reference_ref']==ref),None)
                state='completed' if result and result.get('accepted') else 'failed' if result and result.get('attempts') else 'pending'
                dynamic('reference_candidate',[bid,versions[bid],ref],{'bc_id':bid,'ledger_revision':versions[bid],
                    'reference_ref':ref,'cosine':candidate.get('cosine'),'actual_result':deepcopy(result)},state,
                    'Recall membership is not a support-match judgment')
                states.append(state)
            aggregate('bc_matching',bid,'completed' if all(s=='completed' for s in states) else
                'failed' if any(s=='failed' for s in states) else 'pending',
                'All actual top-K candidate decisions recorded' if all(s=='completed' for s in states) else 'Some recalled candidates failed or await frozen budget')
        for task in task_runs:
            result=task['result'];state=result.get('state',{});seen=set(state.get('seen_bc_ids',[]))
            for bid,revision in versions.items():
                dynamic('task_bc',[task['task_id'],bid,revision],{'task_id':task['task_id'],'kind':task['kind'],
                    'bc_id':bid,'ledger_revision':revision,'task_directory':task['directory']},
                    'completed' if bid in seen else 'pending',
                    'Accepted incremental task stage' if bid in seen else 'Task not yet processed or definition blocked')
            dynamic('task_synthesis',[task['task_id'],versions],{'task_id':task['task_id'],'kind':task['kind'],
                'task_directory':task['directory'],'native_status':result['status']},
                'completed' if state.get('synthesis') is not None or state.get('empty_result') is not None else 'pending',
                'Actual final synthesis or explicit empty result; definition blocks are not analyses')
        if task_runs:
            for bid in versions:
                done=all(bid in r['result'].get('state',{}).get('seen_bc_ids',[]) for r in task_runs)
                aggregate('bc_task',bid,'completed' if done else 'pending','Every configured task processed this BC' if done else 'Task stage or task definition remains pending')


class PlannedProvider:
    """Preflight against the same cumulative budget before another model call.

    The underlying PipelineProvider also performs atomic global reservations.
    This adapter never raises the cap or resets the source ledger on resume.
    """
    def __init__(self, provider, plan):
        self.provider=provider;self.plan=plan;self.description=provider.description;self.is_real=provider.is_real
        self.reservation=None

    def preflight(self, packet, config):
        if hasattr(self.provider,'preflight'):
            reason=self.provider.preflight(packet,config)
            if reason:return reason
        from androserum.inference.compact import compact_packet,COMPACT_INSTRUCTIONS
        from androserum.inference.provider import strict_schema
        from androserum.mining.models import CurrentProposal
        from .provider import mining_prompt
        envelope,_=compact_packet(packet)
        chars=(len('REQUEST_JSON\n'+json.dumps(envelope,ensure_ascii=False,separators=(',',':')))
            +len(mining_prompt(packet.get('fact_query_protocol','v1'))+'\n'+COMPACT_INSTRUCTIONS)
            +len(canonical_json(strict_schema(CurrentProposal.model_json_schema()))))
        reason=self.plan.reserve(packet['request_id'],chars)
        if reason:return reason
        self.reservation=chars
        return None

    def generate(self, packet, directory, config):
        chars=self.reservation
        if chars is None:raise ValueError('Complete plan dispatch needs budget preflight')
        self.reservation=None
        raw,meta=self.provider.generate(packet,directory,config)
        self.plan.settle(packet['request_id'],meta)
        return raw,meta


def _no_automatic_work_remaining(out, prepared, plan, previous):
    """A completed fixed pass must not publish another zero-call segment.

    Terminal failures stay failures. New residual issues outside the frozen
    one-pass frontier stay in the native plan; neither causes implicit retries.
    This is a scheduling no-op, not a semantic completeness assertion.
    """
    if not previous:return False
    if not previous.get('mining_run'):
        if (previous.get('status')!='no_materialized_bu' or previous.get('actual_llm_calls')!=0
                or previous.get('apk_sha256')!=prepared['apk_sha256']
                or any(r['kind'] in {'physical_anchor','anchor_context','bu','block','context_pending','context_failure','unpackable_evidence'} for r in plan['items'])):
            return False
        from .approval import read
        from androserum.facts.identity import sha256_file
        snapshot=filesystem_path(prepared['snapshot']);manifest=read(snapshot/'manifest.json')
        if sha256_file(snapshot/'facts.sqlite')!=manifest['database_sha256'] or sha256_file(prepared['input_apk'])!=prepared['apk_sha256']:
            raise ValueError('Completed empty-scope source identity changed')
        return True
    from .approval import read,verify_files
    from .mining_completion import LOADED_ORCHESTRATION_SHA
    from androserum.mining.ledger import Ledger
    from androserum.facts.identity import sha256_file
    run=filesystem_path(previous['mining_run']);report=read(run/'report.json')
    original=[r for r in report.get('chunk_progress',[]) if not r.get('work_amendment')]
    if not original or any(r['state'] not in {'accepted','rejected','blocked'} for r in original):return False
    if report.get('coverage',{}).get('unscheduled'):return False
    completion_file=out/'mining-completion/state.json'
    if not completion_file.is_file():return False
    state=read(completion_file);frontier=state.get('frontier')
    if frontier is None:return False
    if (state['binding']['plan_id']!=plan['plan_id'] or
            state['binding']['orchestration_sha256']!=LOADED_ORCHESTRATION_SHA):return False
    if any(state['items'][key]['state'] not in {'completed','superseded','failed','truncated'} for key in frontier):return False
    verify_files(run)
    with Ledger(run/'ledger.sqlite',readonly=True) as ledger:
        ledger.verify()
        if ledger.state()!=report['accepted_state']:raise ValueError('Completed native state differs from its report')
    snapshot=filesystem_path(prepared['snapshot']);manifest=read(snapshot/'manifest.json')
    if sha256_file(snapshot/'facts.sqlite')!=manifest['database_sha256']:
        raise ValueError('Completed source fact snapshot changed')
    if sha256_file(prepared['input_apk'])!=prepared['apk_sha256']:
        raise ValueError('Completed source APK changed')
    if prepared.get('bu_package'):verify_files(prepared['bu_package'])
    return True


def mine_complete_prepared(round_root, sample_id, *, call_limit=None, resume=False):
    """General current-facts mining entry with one logical ledger for all BUs."""
    from androserum.facts.store import FactView
    from androserum.mining.models import CurrentMiningConfig
    from androserum.mining.runner import load_catalog,run_mining
    from .provider import PipelineProvider
    from .runner import sample_path,read
    root=filesystem_path(round_root);out=sample_path(root,sample_id)
    frozen=read(root/'experiment-config.json');prepared=read(out/'prepared.json')
    source_config=read(out/'config.json')
    config=CurrentMiningConfig.model_validate(frozen.get('effective_mining_policy',source_config['mining']))
    policy_binding={'source_preparation_config_sha256':prepared['config_sha256'],
        'source_preparation_mining_config':source_config['mining'],
        'effective_frozen_mining_config':config.model_dump(mode='json'),
        'static_snapshot_unchanged':True,'mining_policy_does_not_rerun_static_analysis':True}
    binding_file=out/'effective-mining-policy.json'
    if binding_file.exists() and read(binding_file)!=policy_binding:raise ValueError('Effective mining policy changed after initialization')
    if not binding_file.exists():write(binding_file,policy_binding)
    if config.max_model_calls>frozen['per_sample_mining_call_limit']:
        raise ValueError('Mining config exceeds frozen sample call budget')
    result_file=out/'mining-result.json'
    previous=read(result_file) if result_file.exists() else None
    if previous and not resume:return previous
    collection=read(filesystem_path(prepared['bu_package'])/'collection.json') if prepared.get('bu_package') else None
    packing_profile=frozen.get('mining_packing_profile')
    plan=discover_plan(prepared,read(out/'sapi-matches.json'),collection,config,packing_profile=packing_profile)
    if frozen.get('workload_budget'):
        from androserum.facts.identity import sha256_file
        scope_file=root/'workload-scope.json';scope=read(scope_file)
        if (sha256_file(scope_file)!=frozen['workload_budget']['scope_sha256'] or
                scope['plan_id']!=plan['plan_id'] or
                scope['packing_rule_sha256']!=plan.get('packing_rule_sha256') or
                scope['complete_block_count']!=sum(r['kind']=='block' for r in plan['items'])):
            raise ValueError('Actual complete scope/packing differs from the pre-dispatch workload measurement')
    total={'max_model_calls':config.max_model_calls,'max_input_chars':frozen['aggregate_input_char_limit'],
           'max_reported_input_tokens':frozen['reported_input_token_stop']}
    with CandidatePlan(out/'complete-plan',plan,budget=total) as progress:
        if resume and _no_automatic_work_remaining(out,prepared,plan,previous):
            return previous
        if not collection or not collection['units']:
            result={'mining_run':None,'apk_sha256':prepared['apk_sha256'],'actions':0,'bcs':0,
                'status':'no_materialized_bu','full_behavior_coverage_claimed':False,'actual_llm_calls':0}
        else:
            provider=PipelineProvider(root,sample_id,frozen)
            try:
                with FactView(prepared['snapshot']) as view:
                    catalog=load_catalog(prepared['bu_package'],view,[u['bu_id'] for u in collection['units']],
                                         **({'packing_profile':packing_profile} if packing_profile else {}))
                    planned=PlannedProvider(provider,progress)
                    def checkpoint(run,report,completion=None):
                        value={'mining_run':str(run),'apk_sha256':prepared['apk_sha256'],
                            'actions':len(report['accepted_state']['actions']),'bcs':len(report['accepted_state']['bcs']),
                            'budgets':report['budgets'],'coverage':report['coverage'],
                            'status':'program_checked_candidates_with_explicit_pending_scope',
                            'full_behavior_coverage_claimed':False,'semantic_review_required':False,
                            'native_dispatch_segment_size':1}
                        if completion is not None:value['automatic_finalization']=completion
                        if result_file.exists():
                            old=read(result_file)
                            if old!=value:write(out/'mining-result-history'/(fingerprint(old)+'.json'),old)
                        # Each published native segment becomes the durable
                        # continuation pointer before another dispatch begins.
                        temporary=out/'mining-result.json.tmp';write(temporary,value);temporary.replace(result_file)
                        write(out/'complete-plan/progress.json',progress.report())
                        return value
                    run=previous.get('mining_run') if previous else None
                    report=read(filesystem_path(run)/'report.json') if run else None
                    remaining=config.max_model_calls if call_limit is None else call_limit
                    workload=frozen.get('workload_budget')
                    def ordinary_room():
                        if workload is None:return remaining
                        prefix=sample_id+':'
                        used=provider.budget.db.execute(
                            "SELECT COUNT(*) FROM workload_reservations WHERE stage='ordinary_mining' AND substr(call_id,1,?)=?",
                            (len(prefix),prefix)).fetchone()[0]
                        return max(0,workload['ordinary_mining_call_cap']-used)
                    while remaining>0 and ordinary_room()>0:
                        run,report=run_mining(catalog,view,out/'mining',planned,config,
                            resume_from=run,call_limit=1)
                        progress.sync_mining(run,report);checkpoint(run,report)
                        consumed=report['budgets'].get('segment_model_calls',0)
                        remaining-=consumed
                        if not consumed or report.get('stop_reason')!='segment_call_limit':break
                    from .mining_completion import finalize_mining
                    if report is None:raise ValueError('Zero-call mining has no retained source segment')
                    if workload is not None:
                        original=[r for r in report.get('chunk_progress',[]) if not r.get('work_amendment')]
                        ready=bool(original) and all(r['state'] in {'accepted','rejected','blocked'} for r in original)
                        ready=ready and not report.get('coverage',{}).get('unscheduled')
                        authorization=root/'stage-authorizations'/(sample_id+'.final_mining.json')
                        if ready and not authorization.exists():
                            from androserum.facts.identity import sha256_file
                            frontier={k:v for k,v in report['accepted_state']['unresolved'].items() if v['status']=='open'}
                            needed=3*len(frontier)
                            cap=min(needed,workload['reserved_final_mining_calls'])
                            body={'schema_version':'workload-stage-authorization.v1',
                                'budget_id':workload['budget_id'],'sample_id':sample_id,'channel':'final_mining',
                                'stage_call_caps':{'final_mining':cap},'actual_open_issue_ids':sorted(frontier),
                                'all_original_blocks_terminal':True,'full_frontier_call_estimate':needed,
                                'insufficient_reserve_is_pending':needed>cap,
                                'frozen_inputs':[{'path':str(filesystem_path(run)/'manifest.json'),
                                    'sha256':sha256_file(filesystem_path(run)/'manifest.json')},
                                    {'path':str(out/'complete-plan/plan.json'),'sha256':sha256_file(out/'complete-plan/plan.json')}]}
                            write(authorization,{**body,'authorization_sha256':fingerprint(body)})
                    run,report,completion=finalize_mining(catalog,view,out/'mining',planned,
                        config,progress,run,report,remaining_segment_calls=max(0,remaining),
                        checkpoint=checkpoint)
                    result=checkpoint(run,report,completion)
            finally:provider.close()
        write(out/'complete-plan/progress.json',progress.report())
        if previous:
            write(out/'mining-result-history'/(fingerprint(previous)+'.json'),previous)
        if not result_file.exists() or read(result_file)!=result:
            temporary=out/'mining-result.json.tmp';write(temporary,result);temporary.replace(result_file)
        return result
