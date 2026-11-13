"""One bounded lossless compact transport reused by mining, matching and tasks."""
from pathlib import Path
import json
from androserum.facts.identity import fingerprint,canonical_json
from androserum.inference.provider import RealProvider,CallBudget,write
from androserum.inference.compact import compact_packet,expand_compact,COMPACT_INSTRUCTIONS
from androserum.mining.models import Proposal, CurrentProposal
from androserum.inference.provider import strict_schema


def workload_stage(packet, phase):
    if phase == 'mining':
        task = (packet.get('work_context') or {}).get('review_task') or {}
        return 'final_mining' if task.get('amendment_id', '').startswith('auto-final:') else 'ordinary_mining'
    if phase == 'task':
        return 'task_synthesis' if packet.get('task_request', {}).get('phase') == 'synthesis' else 'task_incremental'
    return phase


def workload_allowance(root, config, sample, stage):
    """Read a frozen stage allowance; never increase the round's phase cap."""
    policy = config.get('workload_budget')
    if policy is None: return None
    caps = {'ordinary_mining': policy['ordinary_mining_call_cap'],
            'final_mining': policy['reserved_final_mining_calls'],
            'matching': policy['per_sample_call_caps']['matching'],
            'task_incremental': policy['per_sample_call_caps']['task'] - policy['task_synthesis_reserved_calls'],
            'task_synthesis': policy['task_synthesis_reserved_calls']}
    if stage not in caps: raise ValueError('Unsupported workload stage')
    if stage == 'ordinary_mining': return caps[stage]
    channel = 'final_mining' if stage == 'final_mining' else 'downstream'
    filename = Path(root) / 'stage-authorizations' / (sample + '.' + channel + '.json')
    if not filename.is_file(): return 0
    auth = json.loads(filename.read_text('utf-8'))
    body = {k:v for k,v in auth.items() if k != 'authorization_sha256'}
    if (auth.get('authorization_sha256') != fingerprint(body) or auth.get('budget_id') != policy['budget_id']
            or auth.get('sample_id') != sample or auth.get('channel') != channel):
        raise ValueError('Workload stage authorization is not bound to this frozen round/sample')
    if not isinstance(auth.get('frozen_inputs'),list) or not auth['frozen_inputs']:
        raise ValueError('Workload stage needs an actual frozen input manifest')
    from androserum.facts.identity import sha256_file
    for item in auth['frozen_inputs']:
        if sha256_file(item['path']) != item['sha256']:
            raise ValueError('Workload stage input changed after its authorization')
    allowance = auth['stage_call_caps'].get(stage, 0)
    if type(allowance) is not int or not 0 <= allowance <= caps[stage]:
        raise ValueError('Stage allowance exceeds the frozen workload reserve')
    return allowance


def mining_prompt(protocol='v1'):
    prompt=(Path(__file__).parents[1]/'mining/prompt.txt').read_text('utf-8')
    if protocol == 'current_facts.v1':
        prompt += ('\nCurrent-fact queries use the supplied structured selector contract, current APK/run identity, '
                   'and declared budget. Request only facts needed to resolve a recorded open question. '
                   'No returned record is evidence until it is actually supplied in a later request. '
                   'No matching fact does not prove absence. Never query another APK or request SQL/code.')
    elif protocol != 'v1':raise ValueError('Unsupported mining protocol')
    return prompt


def effective_budget(round_root,base):
    amended=dict(base);path=Path(round_root)/'budget-amendment.json'
    if base.get('workload_budget') and any((Path(round_root)/name).exists() for name in
            ('budget-amendment.json','budget-amendment-v2.json')):
        raise ValueError('Frozen stability workload forbids budget amendments; preserve pending work for an explicit new stage')
    if not path.is_file():return amended,None
    value=json.loads(path.read_text('utf-8'))
    change=value.get('changes',{}).get('aggregate_input_char_limit',{})
    if (value.get('base_config_sha256')!=fingerprint(base)
        or set(value.get('changes',{}))!={'aggregate_input_char_limit'}
        or change.get('old')!=base['aggregate_input_char_limit']
        or type(change.get('new')) is not int or not change['old']<change['new']<=2*change['old']
        or value.get('call_limits_unchanged')!=base['call_limits']
        or value.get('reported_input_token_stop_unchanged')!=base['reported_input_token_stop']):
        raise ValueError('Budget amendment is not bound to the original finite policy')
    amended['aggregate_input_char_limit']=change['new']
    audit={'path':str(path),'sha256':fingerprint(value),'original_config_sha256':fingerprint(base)}
    second=Path(round_root)/'budget-amendment-v2.json'
    if second.is_file():
        follow=json.loads(second.read_text('utf-8'))
        if (follow.get('base_config_sha256')!=fingerprint(base) or follow.get('parent_amendment_sha256')!=fingerprint(value)
            or follow.get('call_limits_unchanged')!=base['call_limits']
            or set(follow.get('changes',{}))!={'aggregate_input_char_limit','reported_input_token_stop'}):
            raise ValueError('Second finite budget revision is not bound to its retained predecessor')
        for key,delta in follow['changes'].items():
            if delta.get('old')!=amended[key] or type(delta.get('new')) is not int or not delta['old']<delta['new']<=2*delta['old']:
                raise ValueError('Finite budget revision is not a bounded monotonic increase')
            amended[key]=delta['new']
        audit={'path':str(second),'sha256':fingerprint(follow),'parent':audit,'original_config_sha256':fingerprint(base)}
    return amended,audit


class PipelineBudget(CallBudget):
    """Atomic global/phase/sample reservations, including in-flight input."""
    def __init__(self,path,config):
        super().__init__(path,config['call_limits']);self.config=config;self.pending=None
        self.root=Path(path).parent
        if config.get('workload_budget'):
            self.db.execute('CREATE TABLE IF NOT EXISTS workload_reservations(call_id TEXT PRIMARY KEY,stage TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS input_reservations(call_id TEXT PRIMARY KEY,chars INTEGER NOT NULL)')
        # Older completed validation calls still consume this round's budget.
        self.db.execute('INSERT OR IGNORE INTO input_reservations SELECT call_id,COALESCE(json_extract(receipt,\'$.application_context_chars\'),0) FROM calls WHERE receipt IS NOT NULL')
        from .batch_budget import attach
        attach(self)

    def stage(self,sample_id,chars,work_stage=None):self.pending=(sample_id,chars,work_stage)

    def reserve(self,phase,call_id):
        if self.pending is None:raise ValueError('Inference reservation requires exact wire character count')
        sample,chars,work_stage=self.pending;self.db.execute('BEGIN IMMEDIATE')
        try:
            if not call_id.startswith(sample+':'):raise ValueError('Call reservation sample identity differs')
            if self.db.execute('SELECT 1 FROM calls WHERE call_id=?',(call_id,)).fetchone():raise ValueError('Invocation already reserved; retained output must be replayed')
            count=self.db.execute('SELECT COUNT(*) FROM calls WHERE phase=?',(phase,)).fetchone()[0]
            if phase not in self.limits or count>=self.limits[phase]:raise ValueError('Persistent phase call budget exhausted')
            cap=self.config.get('per_sample_'+phase+'_call_limit',self.limits[phase]);prefix=sample+':'
            count=self.db.execute('SELECT COUNT(*) FROM calls WHERE phase=? AND substr(call_id,1,?)=?',
                                  (phase,len(prefix),prefix)).fetchone()[0]
            if count>=cap:raise ValueError('Persistent per-sample call budget exhausted')
            if self.config.get('workload_budget'):
                allowance=workload_allowance(self.root,self.config,sample,work_stage)
                count=self.db.execute('SELECT COUNT(*) FROM workload_reservations WHERE stage=? AND substr(call_id,1,?)=?',
                    (work_stage,len(prefix),prefix)).fetchone()[0]
                if count>=allowance:raise ValueError('Frozen workload stage/reserve exhausted or not yet authorized')
            used=self.db.execute('SELECT COALESCE(SUM(chars),0) FROM input_reservations').fetchone()[0]
            if used+chars>self.config['aggregate_input_char_limit']:raise ValueError('Aggregate input reservation budget exhausted')
            tokens=self.db.execute("SELECT COALESCE(SUM(COALESCE(json_extract(receipt,'$.usage.input_tokens'),0)),0) FROM calls").fetchone()[0]
            if tokens>=self.config['reported_input_token_stop']:raise ValueError('Reported token stop reached')
            from .batch_budget import reserve
            reserve(self,sample,phase,call_id,chars)
            self.db.execute('INSERT INTO calls VALUES (?,?,?,NULL)',(call_id,phase,'reserved'))
            self.db.execute('INSERT INTO input_reservations VALUES (?,?)',(call_id,chars))
            if work_stage is not None:
                self.db.execute('INSERT INTO workload_reservations VALUES (?,?)',(call_id,work_stage))
            self.db.execute('COMMIT')
        except BaseException:self.db.execute('ROLLBACK');raise

    def finish(self,call_id,receipt):
        from .batch_budget import finish
        self.db.execute('BEGIN IMMEDIATE')
        try:
            super().finish(call_id,receipt)
            finish(self,call_id,receipt)
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise


class PipelineProvider:
    is_real=True
    def __init__(self,round_root,sample_id,config):
        self.root=Path(str(round_root).removeprefix('\\\\?\\')).resolve();self.sample_id=sample_id
        original_config=config;self.config,self.amendment=effective_budget(self.root,config);config=self.config
        if config.get('compact_instructions_sha256')!=fingerprint(COMPACT_INSTRUCTIONS):
            raise ValueError('Compact instructions differ from the frozen round')
        if (self.root/'round-manifest.json').is_file():
            from .rounds import verify_round
            verify_round(self.root)
        self.budget=PipelineBudget(self.root/'real-call-budget.sqlite',config)
        self.provider=RealProvider(config['model_options'])
        self.description={**self.provider.description,'real_model':True,'compact_transport':'androserum.compact-json.v1',
                          'round_config_sha256':fingerprint(original_config)}

    def preflight_invocation(self,packet,schema,instructions,*,phase,call_id):
        envelope,_=compact_packet(packet)
        chars=(len('REQUEST_JSON\n'+json.dumps(envelope,ensure_ascii=False,separators=(',',':')))
            +len(instructions+'\n'+COMPACT_INSTRUCTIONS)+len(canonical_json(strict_schema(schema))))
        calls=self.budget.report()['calls'];sample_prefix=self.sample_id+':'
        if any(c['call_id']==sample_prefix+call_id for c in calls):return 'invocation_already_reserved_replay_required'
        if sum(c['phase']==phase for c in calls)>=self.config['call_limits'][phase]:return 'round_'+phase+'_call_budget'
        if sum(c['phase']==phase and c['call_id'].startswith(sample_prefix) for c in calls)>=self.config.get('per_sample_'+phase+'_call_limit',self.config['call_limits'][phase]):
            return 'sample_'+phase+'_call_budget'
        if self.config.get('workload_budget'):
            stage=workload_stage(packet,phase)
            allowance=workload_allowance(self.root,self.config,self.sample_id,stage)
            count=self.budget.db.execute('SELECT COUNT(*) FROM workload_reservations WHERE stage=? AND substr(call_id,1,?)=?',
                (stage,len(sample_prefix),sample_prefix)).fetchone()[0]
            if count>=allowance:return 'workload_'+stage+'_reserve_or_authorization'
        from .batch_budget import reason
        stop=reason(self.budget,self.sample_id,chars)
        if stop:return stop
        used=self.budget.db.execute('SELECT COALESCE(SUM(chars),0) FROM input_reservations').fetchone()[0]
        if used+chars>self.config['aggregate_input_char_limit']:return 'round_cumulative_input_character_budget'
        tokens=sum(((c.get('receipt') or {}).get('usage') or {}).get('input_tokens',0) for c in calls)
        if tokens>=self.config['reported_input_token_stop']:return 'round_reported_input_token_stop'
        if chars>self.config['max_compact_request_chars']:return 'compact_request_context_budget'
        return None

    def preflight(self,packet,config):
        model=CurrentProposal if packet.get('fact_query_protocol')=='current_facts.v1' else Proposal
        return self.preflight_invocation(packet,model.model_json_schema(),mining_prompt(packet.get('fact_query_protocol','v1')),
            phase='mining',call_id=packet['request_id'])

    def invoke(self,packet,schema,instructions,directory,*,phase,call_id,timeout_seconds=None,max_response_chars=None):
        stop=self.preflight_invocation(packet,schema,instructions,phase=phase,call_id=call_id)
        if stop:raise ValueError('Undispatched: '+stop)
        envelope,metrics=compact_packet(packet)
        if expand_compact(envelope)!=packet:raise ValueError('Lossless compact materialization differs')
        augmented=instructions+'\n'+COMPACT_INSTRUCTIONS
        measured=len(canonical_json(envelope))+len(augmented)+len(canonical_json(schema))
        usage=self.budget.report()['calls']
        spent=sum((c['receipt'] or {}).get('application_context_chars',0) for c in usage)
        token_spent=sum(((c['receipt'] or {}).get('usage') or {}).get('input_tokens',0) for c in usage)
        if spent+measured>self.config['aggregate_input_char_limit']:
            raise ValueError('Round aggregate compact input character budget exhausted')
        if token_spent>=self.config['reported_input_token_stop']:
            raise ValueError('Round reported input token stop reached; no further inference')
        directory=Path(str(directory).removeprefix('\\\\?\\'))
        exact_chars=(len('REQUEST_JSON\n'+json.dumps(envelope,ensure_ascii=False,separators=(',',':')))
                     +len(augmented)+len(canonical_json(strict_schema(schema))))
        self.budget.stage(self.sample_id,exact_chars,workload_stage(packet,phase) if self.config.get('workload_budget') else None)
        raw,receipt=self.provider.generate(envelope,schema,augmented,directory,
            budget=self.budget,phase=phase,call_id=self.sample_id+':'+call_id,
            timeout_seconds=min(timeout_seconds or self.config['timeout_seconds'],self.config['timeout_seconds']),max_request_chars=self.config['max_compact_request_chars'],
            max_response_chars=min(max_response_chars or self.config['max_response_chars'],self.config['max_response_chars']))
        write(directory/'transport-audit.json',{'original_packet_sha256':fingerprint(packet),
            'lossless_roundtrip':True,'original_request':packet,'metrics':metrics,
            'budget_amendment':self.amendment,
            'compaction_is_not_evidence_summarization':True})
        return raw,{**receipt,'real_model':True,'compact_metrics':metrics,'original_packet_sha256':fingerprint(packet)}

    def generate(self,packet,directory,config):
        prompt=mining_prompt(packet.get('fact_query_protocol','v1'))
        model = CurrentProposal if packet.get('fact_query_protocol') == 'current_facts.v1' else Proposal
        return self.invoke(packet,model.model_json_schema(),prompt,Path(directory)/'inference',
                           phase='mining',call_id=packet['request_id'],timeout_seconds=config.model_timeout_seconds,
                           max_response_chars=config.max_response_chars)

    def close(self):self.budget.close()
