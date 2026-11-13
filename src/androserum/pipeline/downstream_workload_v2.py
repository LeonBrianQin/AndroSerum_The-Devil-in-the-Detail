"""Opt-in actual-candidate checks under existing native cumulative caps.

The v1 round/provider contracts remain unchanged. This sidecar narrows allowed
dispatch and supplies an actual-work authorization within those original caps.
"""
from copy import deepcopy
import json
from pathlib import Path

from androserum.facts.identity import fingerprint, filesystem_path, sha256_file, canonical_json
from androserum.inference.provider import write, strict_schema
from androserum.inference.compact import compact_packet, COMPACT_INSTRUCTIONS
from .remaining_workload import plan_remaining_workload


PROFILE = 'actual-candidate-shared-repairs.v2'


def read(path):
    return json.loads(filesystem_path(path).read_text('utf-8'))


def _path(root, sample):
    if Path(sample).name != sample or sample in {'.', '..'}:
        raise ValueError('Invalid sample identity')
    return filesystem_path(root) / 'stage-policies' / (sample + '.downstream-v2.json')


def _rules():
    base=Path(__file__).parent
    return {name:sha256_file(base/name) for name in
            ('analyze.py','downstream_workload_v2.py','remaining_workload.py')}


def freeze_downstream_policy(root, sample, freeze, history, *, matching_repair_pool,
                             task_repair_pool, per_call_input_chars,
                             per_call_reported_input_tokens):
    """Write a new explicit policy; return its exact byte SHA for analyze_apk.

    Per-call input allowances are declared planning bounds, not observed usage.
    The proxy refuses a request larger than its character allowance. Actual
    reported-token stop semantics and all native caps remain unchanged.
    """
    root=filesystem_path(root);config=read(root/'experiment-config.json')
    if not config.get('workload_budget'):
        raise ValueError('v2 requires the existing frozen workload contract')
    from .tasks import load_task_definition
    definitions=config.get('task_definitions',[])
    if len(definitions)!=1 or load_task_definition(definitions[0]).blocked_reasons():
        raise ValueError('v2 first release supports exactly one runnable defined task')
    if config['defined_task_config']['max_attempts_per_stage']!=2:
        raise ValueError('v2 requires initial plus at most one repair per proposal')
    if config['workload_budget']['task_synthesis_reserved_calls']<2:
        raise ValueError('Existing task budget has no initial-plus-one-repair synthesis reserve')
    for key,value in {'matching_repair_pool':matching_repair_pool,'task_repair_pool':task_repair_pool,
                      'per_call_input_chars':per_call_input_chars,
                      'per_call_reported_input_tokens':per_call_reported_input_tokens}.items():
        if type(value) is not int or value<0 or ('per_call' in key and not value):
            raise ValueError('Invalid finite downstream allowance: '+key)
    if per_call_input_chars>config['max_compact_request_chars']:
        raise ValueError('Planning allowance exceeds the original request hard limit')
    body={'schema_version':PROFILE,'sample_id':sample,'round_config_sha256':fingerprint(config),
        'matching_repair_pool':matching_repair_pool,'task_repair_pool':task_repair_pool,
        'synthesis_initial_and_repair_reserved':2,'max_repairs_per_proposal':1,
        'per_call_input_chars':per_call_input_chars,'per_call_reported_input_tokens':per_call_reported_input_tokens,
        'input_tokens_are_declared_estimate_not_billing_guarantee':True,
        'frozen_inputs':[{'path':str(filesystem_path(path)/'manifest.json'),
            'sha256':sha256_file(filesystem_path(path)/'manifest.json')} for path in (freeze,history)],
        'implementation_sha256':_rules(),'native_limits_unchanged':True}
    value={**body,'policy_id':fingerprint(body)};path=_path(root,sample)
    if path.exists():
        if read(path)!=value:raise ValueError('Existing v2 policy cannot be changed; use an explicit new recovery round')
    else:write(path,value)
    return {'path':str(path),'sha256':sha256_file(path),'policy_id':value['policy_id']}


def load_downstream_policy(root,sample,config,freeze,history,expected_sha256):
    path=_path(root,sample)
    if expected_sha256 is None:
        if path.exists():raise ValueError('Existing v2 sidecar requires explicit downstream_policy_sha256')
        return None
    if sha256_file(path)!=expected_sha256:raise ValueError('Downstream v2 sidecar byte hash differs')
    value=read(path);body={k:v for k,v in value.items() if k!='policy_id'}
    if (value.get('schema_version')!=PROFILE or value.get('policy_id')!=fingerprint(body)
            or value.get('round_config_sha256')!=fingerprint(config) or value.get('sample_id')!=sample
            or value.get('implementation_sha256')!=_rules()):
        raise ValueError('Downstream v2 policy/config/implementation binding differs')
    actual=[{'path':str(filesystem_path(p)/'manifest.json'),'sha256':sha256_file(filesystem_path(p)/'manifest.json')}
            for p in (freeze,history)]
    if value['frozen_inputs']!=actual:raise ValueError('Downstream v2 freeze/history binding differs')
    return value


class DownstreamWorkloadGuard:
    """Provider proxy: no new provider, model, ledger, or budget reset."""
    def __init__(self,provider,root,sample,config,policy,output,entries,recalls,catalog,scope_status):
        self.provider=provider;self.root=filesystem_path(root);self.sample_id=sample
        self.config=config;self.policy=policy;self.output=filesystem_path(output)
        self.budget=provider.budget;self.is_real=getattr(provider,'is_real',False)
        self.entries=entries;self.recalls=recalls;self.catalog=catalog;self.scope_status=scope_status
        self.bids=[entry['bc']['bc_id'] for entry in entries]
        self.definition=config['task_definitions'][0]
        self.task_id=self.definition['task_id']
        self.task_directory=self.output/'defined-tasks'/fingerprint(self.definition)[:20]
        self.pairs=[]
        for index,(bid,returned) in enumerate(zip(self.bids,recalls)):
            for rank,candidate in enumerate(returned['ranked_candidates']):
                self.pairs.append((bid,candidate['instance_ref'],'bc-'+str(index)+'-rank-'+str(rank)))
        self.last_plan=None;self.allowed_calls=set();self.last_report=None
        self.check_root=self.output/'remaining-workload-v2';self.check_root.mkdir(parents=True,exist_ok=True)
        prior=sorted(self.check_root.glob('check-*.json'))
        if prior:self.last_plan=read(prior[-1])['plan']
        self.frontier={'bc_ids':self.bids,'pairs':self.pairs,'policy_id':policy['policy_id']}
        path=self.output/'actual-downstream-frontier-v2.json'
        if path.exists() and read(path)!=self.frontier:raise ValueError('Frozen actual candidate frontier changed; retain this run and create a new recovery round')
        if not path.exists():write(path,self.frontier)

    def __getattr__(self,name):
        return getattr(self.provider,name)

    def _usage(self):
        db=self.budget.db
        rows=[{'call_id':a,'phase':b,'status':c,'receipt':json.loads(d) if d else None,'chars':e or 0}
              for a,b,c,d,e in db.execute('SELECT c.call_id,c.phase,c.status,c.receipt,i.chars FROM calls c LEFT JOIN input_reservations i ON i.call_id=c.call_id')]
        def measured(items,max_calls,max_chars,max_tokens):
            tokens=[(row.get('receipt') or {}).get('usage',{}).get('input_tokens') for row in items]
            return {'max_calls':max_calls,'spent_calls':len(items),'max_input_chars':max_chars,
                'spent_input_chars':sum(row['chars'] for row in items),'max_reported_input_tokens':max_tokens,
                'spent_reported_input_tokens':sum(tokens) if all(type(n)is int and n>=0 for n in tokens) else None}
        own=[row for row in rows if row['call_id'].startswith(self.sample_id+':')]
        scopes={'round':measured(rows,sum(self.config['call_limits'].values()),self.config['aggregate_input_char_limit'],self.config['reported_input_token_stop'])}
        binding=getattr(self.budget,'batch_binding',None)
        if binding:
            batch=[{'call_id':a,'sample_id':b,'pilot':bool(c),'chars':d,'status':e,'receipt':json.loads(f) if f else None}
                   for a,b,c,d,e,f in db.execute('SELECT call_id,sample_id,pilot,chars,status,receipt FROM batch_budget.calls')]
            policy=binding['policy'];caps=policy['whole_batch_caps']
            scopes['batch']=measured(batch,caps['call_attempts'],caps['reserved_input_chars'],caps['reported_input_token_stop'])
            selected=[row for row in batch if row['sample_id']==self.sample_id]
            scopes['batch_sample']=measured(selected,policy['per_apk_call_attempts_cap'],caps['reserved_input_chars'],caps['reported_input_token_stop'])
            if self.sample_id in binding['plan']['pilot_sample_ids']:
                caps=policy['pilot_caps'];scopes['pilot']=measured([row for row in batch if row['pilot']],caps['call_attempts'],caps['reserved_input_chars'],caps['reported_input_token_stop'])
        stages={stage:0 for stage in ('matching','task_incremental','task_synthesis')}
        for stage,count in db.execute('SELECT stage,COUNT(*) FROM workload_reservations WHERE substr(call_id,1,?)=? GROUP BY stage',
                                      (len(self.sample_id)+1,self.sample_id+':')):
            if stage in stages:stages[stage]=count
        return rows,own,scopes,stages

    def _task_progress(self):
        if not (self.task_directory/'task-ledger.sqlite').exists():return {},False
        from .tasks import DefinitionTaskLedger,DefinedTaskConfig
        identity={key:self.catalog['bcs'][self.bids[0]]['origin'][key] for key in ()}  # actual identity comes from frozen run below
        frozen=read(self.task_directory/'run-config.json')
        if frozen['definition']!=self.definition or frozen['catalog_sha256']!=fingerprint(self.catalog):
            raise ValueError('Retained task frontier differs from current frozen sources')
        with DefinitionTaskLedger(self.task_directory/'task-ledger.sqlite',self.definition,
                config=DefinedTaskConfig.model_validate(frozen['config']),source_catalog=self.catalog,
                scope_status=frozen['scope_status']) as ledger:
            ledger.verify();events=ledger.report()['audits'];progress={}
            for key,request,result in ledger.db.execute('SELECT stage_key,request_id,result FROM defined_stages'):
                proposals=[event for event in events if event.get('kind')=='proposal' and event.get('request_id')==request]
                progress[key]={'accepted':bool(proposals and proposals[-1]['check']['valid']),
                    'attempts':len(proposals),'terminal':result is not None}
            return progress,ledger.state()['synthesis'] is not None

    def check(self):
        rows,own,scopes,used=self._usage();calls={row['call_id'].removeprefix(self.sample_id+':'):row for row in own}
        matching_spent_repairs=sum(row['phase']=='matching' and row['call_id'].endswith(':1') for row in own)
        task_spent_repairs=sum(row['phase']=='task' and ':incremental-' in row['call_id'] and row['call_id'].endswith(':1') for row in own)
        match_pool=max(0,self.policy['matching_repair_pool']-matching_spent_repairs)
        task_pool=max(0,self.policy['task_repair_pool']-task_spent_repairs)
        pending_matches={};repair_matches=[];allowed=set();blockers=[]
        for bid,ref,key in self.pairs:
            if key+':0' not in calls:
                pending_matches.setdefault(bid,[]).append(ref);allowed.add(key+':0')
            elif key+':1' not in calls and match_pool:
                check=self.output/'matching'/key/'check-0.json'
                # Native analyze rechecks retained responses before using them;
                # a missing check conservatively reserves the possible repair.
                if not check.exists() or not read(check)['check']['valid']:
                    repair_matches.append(key);allowed.add(key+':1');match_pool-=1
        task_progress,synth_done=self._task_progress();pending_tasks=[];repair_tasks=[]
        for index,bid in enumerate(self.bids):
            key='incremental-'+str(index);state=task_progress.get(key,{})
            if state.get('accepted'):continue
            first=self.task_id+':'+key+':0';second=self.task_id+':'+key+':1'
            if first not in calls:
                pending_tasks.append(bid);allowed.add(first)
            elif second not in calls and state.get('attempts',0)<2:
                repair_tasks.append(bid)
                if task_pool:allowed.add(second);task_pool-=1
                else:blockers.append('shared_task_repair_pool_exhausted')
            else:blockers.append('terminal_task_rejection_prevents_synthesis')
        synth_first=self.task_id+':synthesis:0';synth_repair=self.task_id+':synthesis:1'
        synthesis='complete' if synth_done else 'needs_repair' if synth_first in calls else 'not_started'
        if synthesis=='needs_repair' and synth_repair in calls:blockers.append('terminal_synthesis_rejection')
        if not synth_done:allowed.add(synth_repair if synthesis=='needs_repair' else synth_first)
        if synthesis=='needs_repair' and (pending_tasks or repair_tasks):blockers.append('task_updates_pending_after_synthesis');synthesis='not_started'
        pools={'matching_repairs':min(match_pool,sum(map(len,pending_matches.values()))),
               'task_repairs':min(task_pool,len(pending_tasks))}
        demand=sum(map(len,pending_matches.values()))+len(repair_matches)+len(pending_tasks)+len(repair_tasks)+sum(pools.values())+(0 if synth_done else 1 if synthesis=='needs_repair' else 2)
        caps=self.config['workload_budget'];master=caps['per_sample_call_caps']
        stage_limits={'matching':{'max_calls':master['matching'],'spent_calls':used['matching']},
            'task_updates':{'max_calls':master['task']-caps['task_synthesis_reserved_calls'],'spent_calls':used['task_incremental']},
            'synthesis':{'max_calls':caps['task_synthesis_reserved_calls'],'spent_calls':used['task_synthesis']}}
        plan=plan_remaining_workload(source_identity={'sample_id':self.sample_id,'policy_id':self.policy['policy_id']},
            pending_review_ids=[],frozen_bc_ids=self.bids,pending_candidates_by_bc=pending_matches,
            pending_task_bc_ids=pending_tasks,synthesis_status=synthesis,budget_scopes=scopes,
            extra_call_pools=pools,pending_repair_items={'matching':repair_matches,'task_updates':repair_tasks},
            stage_call_budgets=stage_limits,projected_input={'input_chars':demand*self.policy['per_call_input_chars'],
                'reported_input_tokens':demand*self.policy['per_call_reported_input_tokens']},
            frontier_frozen=True,previous_plan=self.last_plan)
        for phase,required in [('matching',plan['stages']['matching']['declared_calls']),
            ('task',plan['stages']['task_updates']['declared_calls']+plan['stages']['synthesis']['declared_calls'])]:
            if required>self.config['call_limits'][phase]-sum(row['phase']==phase for row in rows):
                blockers.append('round_'+phase+'_phase_call_budget')
        report={'schema_version':'actual-downstream-budget-check.v2','policy_id':self.policy['policy_id'],
            'frontier_sha256':fingerprint(self.frontier),'plan':plan,'runtime_blockers':blockers,
            'can_dispatch':plan['can_dispatch'] and not blockers,'old_spend_retained':True,
            'allowed_next_call_ids':sorted(allowed),'original_caps_unchanged':True}
        digest=fingerprint(report);path=self.check_root/('check-'+str(plan['plan_version']).zfill(6)+'-'+digest+'.json')
        if not path.exists():write(path,report)
        self.last_plan=plan;self.last_report=report;self.allowed_calls=allowed
        return report

    def authorize(self):
        report=self.check()
        if not report['can_dispatch']:return report
        master=self.config['workload_budget']['per_sample_call_caps']
        # Authorization is fixed for this actual full frontier. Runtime proxy
        # enforces the shared pools; native provider enforces original caps.
        stages={'matching':min(master['matching'],len(self.pairs)+self.policy['matching_repair_pool']),
            'task_incremental':min(master['task']-self.config['workload_budget']['task_synthesis_reserved_calls'],len(self.bids)+self.policy['task_repair_pool']),
            'task_synthesis':2}
        body={'schema_version':'workload-stage-authorization.v2','budget_id':self.config['workload_budget']['budget_id'],
            'sample_id':self.sample_id,'channel':'downstream','stage_call_caps':stages,
            'actual_bc_ids':self.bids,'actual_candidate_count':len(self.pairs),'policy_id':self.policy['policy_id'],
            'frozen_inputs':[*self.policy['frozen_inputs'],
                {'path':str(_path(self.root,self.sample_id)),'sha256':sha256_file(_path(self.root,self.sample_id))},
                {'path':str(self.output/'actual-downstream-frontier-v2.json'),'sha256':sha256_file(self.output/'actual-downstream-frontier-v2.json')}]}
        value={**body,'authorization_sha256':fingerprint(body)}
        path=self.root/'stage-authorizations'/(self.sample_id+'.downstream.json')
        if path.exists() and read(path)!=value:raise ValueError('Never replace a prior v1/v2 stage authorization; use a new recovery round')
        if not path.exists():write(path,value)
        return report

    def preflight_invocation(self,packet,schema,instructions,*,phase,call_id):
        report=self.check()
        if call_id not in self.allowed_calls:
            if phase=='matching' and call_id.endswith(':1'):return 'shared_matching_repair_pool_exhausted_or_terminal'
            return 'call_not_in_actual_remaining_frontier'
        if not report['can_dispatch']:return 'actual_remaining_workload_budget_pending'
        envelope,_=compact_packet(packet)
        chars=len('REQUEST_JSON\n'+json.dumps(envelope,ensure_ascii=False,separators=(',',':')))+len(instructions+'\n'+COMPACT_INSTRUCTIONS)+len(canonical_json(strict_schema(schema)))
        if chars>self.policy['per_call_input_chars']:return 'actual_request_exceeds_frozen_planning_input_allowance'
        return self.provider.preflight_invocation(packet,schema,instructions,phase=phase,call_id=call_id)

    def invoke(self,packet,schema,instructions,directory,*,phase,call_id,**kwargs):
        reason=self.preflight_invocation(packet,schema,instructions,phase=phase,call_id=call_id)
        if reason:raise ValueError('Undispatched: '+reason)
        return self.provider.invoke(packet,schema,instructions,directory,phase=phase,call_id=call_id,**kwargs)
