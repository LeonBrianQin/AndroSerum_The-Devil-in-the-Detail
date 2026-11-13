"""Structured program-evidence checks, not a natural-language truth oracle."""
from copy import deepcopy
from collections import defaultdict, deque
import json
import re

from pydantic import ValidationError
from androserum.facts.identity import fingerprint
from androserum.facts.io import strict_json_syntax
from androserum.mining.models import Proposal, CurrentProposal

DATA = {'data_dependency','field_dependency','array_dependency'}


def invalidates_existing_bcs(new,old):
    """Monotonic supporting detail preserves already checked program links."""
    if new['function']!=old['function']:return True
    for key in ['operation_refs','condition_refs','effect_refs']:
        if set(new[key])!=set(old[key]):return True
    for key in ['objects','inputs','outputs']:
        if new[key]['availability']!=old[key]['availability'] or not set(old[key]['endpoint_refs'])<=set(new[key]['endpoint_refs']):return True
    for key in ['support_relation_refs','support_fact_refs']:
        if not set(old.get(key,[]))<=set(new.get(key,[])):return True
    return False


def proposal_handles(value):
    """All request-local evidence handles a model attempts to cite."""
    result=set()
    def walk(v):
        if isinstance(v,dict):
            for x in v.values():walk(x)
        elif isinstance(v,list):
            for x in v:walk(x)
        elif isinstance(v,str) and re.fullmatch(r'(op|ep|rel|cond|bind|effect|fact)_[0-9a-f]{12}',v):
            result.add(v)
    walk(value);return result


def check_proposal(raw, packet, old_state, config):
    errors=[]
    def fail(code,message,subject=None):errors.append({'code':code,'message':message,'subject':subject})
    try:
        if len(raw)>config.max_response_chars:raise ValueError('Response length budget exceeded')
        strict_json_syntax(raw)
        model = CurrentProposal if packet.get('fact_query_protocol') == 'current_facts.v1' else Proposal
        proposal=model.model_validate_json(raw).model_dump(mode='json')
    except (ValueError,ValidationError) as error:
        return {'valid':False,'errors':[{'code':'schema','message':str(error),'subject':None}]},None
    if proposal['request_id']!=packet['request_id']:fail('request_identity','Proposal must name the current request')
    if packet['identity']!=old_state['identity']:fail('source_identity','Request and ledger belong to different source identities')
    if proposal['base_revision']!=old_state['revision'] or packet['base_revision']!=old_state['revision']:
        fail('stale_revision','Proposal or request is based on an old ledger revision')
    registry=packet['evidence']
    if packet['manifest']['evidence_sha256']!=fingerprint(registry):fail('visibility_manifest','Actually shown evidence differs from the request manifest')
    for h,e in registry.items():
        if e['category']=='fact' and e['record'].get('run_ref')!=packet['identity']['source']['source_run_ref']:
            fail('source_ownership','Visible evidence belongs to a different APK/run',h)
    for h in proposal_handles(proposal):
        if h not in registry:fail('not_visible','Evidence was not actually shown in this request',h)
    state=deepcopy(old_state)
    shown_actions=set(packet['ledger_context']['actions'])
    shown_bcs=set(packet['ledger_context']['bcs'])
    for key in proposal['delete_action_ids']:
        if key not in shown_actions:fail('ledger_not_visible','Deleted action was not shown in this request',key)
    for key in proposal['delete_bc_ids']:
        if key not in shown_bcs:fail('ledger_not_visible','Deleted BC was not shown in this request',key)
    for values,key in [(proposal['upsert_actions'],'action_id'),(proposal['upsert_bcs'],'bc_id'),(proposal['unresolved_updates'],'issue_id')]:
        ids=[v[key] for v in values]
        if len(ids)!=len(set(ids)):fail('duplicate_update','Duplicate IDs within one update kind')
    def entry(h,category):
        value=registry.get(h)
        if value is None:return None
        if value['category']!=category:
            fail('evidence_category','Wrong category of evidence handle',h);return None
        return value
    def method_result_check(ep,ops,subject):
        try:
            node=entry(ep['method_result_proof_ref'],'fact')['record']
            relation=entry(ep['method_return_relation_ref'],'fact')['record']
            binding=entry(ep['method_return_binding_ref'],'fact')['record']
            row=json.loads(node['text']);op=entry(ep['owner_operation_ref'],'operation')
            valid=(node['kind']=='analysis_node' and node['node_kind']=='mapping'
                and node['provenance']['tool_ref']=='tool:method-outputs'
                and node['provenance']['rule_ref']=='rule:method-outputs-v1'
                and row['schema_version']=='method-output-projection.v1' and row['normal_return'] is True
                and row['normal_completion_required'] is True and row['execution_established'] is False
                and row['return_type']!='V' and row['owner_projection_ref']==op['record_ref']
                and row['context_ref']==op['context_ref']==ep['context_ref']
                and row['root_ref']==op['root_ref']==ep['root_ref']
                and row['output_endpoint']==ep['endpoint'] and node['id']==ep['endpoint']['element_ref']
                and relation['id']==row['relation_ref'] and relation['relation_kind']=='data_dependency'
                and relation['source']==row['source_endpoint'] and relation['target']==row['output_endpoint']
                and relation['context_ref']==row['context_ref'] and relation['binding_refs']==[binding['id']]
                and relation['condition_refs']==binding['condition_refs']==row['condition_refs']
                and binding['id']==row['binding_ref'] and binding['binding_kind']=='value'
                and binding['context_ref']==row['context_ref']
                and binding['endpoints']==[row['source_endpoint'],row['output_endpoint']])
            if not valid:fail('method_result_support','Method result lacks its exact normal-return/frame/transfer proof',subject)
        except (KeyError,TypeError,ValueError):
            fail('method_result_support','Method result proof is absent, malformed or invisible',subject)
    def field_check(field,ops,subject,field_name):
        if field['availability']=='not_applicable' and field['endpoint_refs']:
            fail('not_applicable_endpoint','Not-applicable fields cannot claim endpoints',subject)
        if field['availability']=='supported' and not field['endpoint_refs']:
            fail('unsupported_field','Supported semantic fields need program endpoints',subject)
        for h in field['endpoint_refs']:
            ep=entry(h,'endpoint')
            if ep and ep['owner_operation_ref'] not in ops:
                fail('endpoint_owner','Semantic endpoint does not belong to selected action operations',h)
            if ep and ep.get('boundary_role')=='explicit_normal_method_result':
                if field_name!='outputs':fail('method_result_role','A method result is an output of its recorded return, not an input/object alias',h)
                method_result_check(ep,ops,h)
    def connected(nodes,edges):
        if len(nodes)<2:return True
        adj=defaultdict(set)
        for a,b in edges:adj[a].add(b);adj[b].add(a)
        seen=set();q=deque([next(iter(nodes))])
        while q:
            n=q.popleft()
            if n in seen:continue
            seen.add(n);q.extend(adj[n]-seen)
        return nodes<=seen
    for action in proposal['upsert_actions']:
        key=action['action_id'];ops=set(action['operation_refs']);op_entries=[entry(h,'operation') for h in ops]
        if key in old_state['actions'] and key not in shown_actions:fail('ledger_not_visible','Existing action must be shown before replacement',key)
        op_entries=[e for e in op_entries if e]
        if len({e['root_ref'] for e in op_entries})>1:fail('action_context','One action cannot merge incompatible analysis roots',key)
        known_conditions={c for e in op_entries for c in e['condition_refs']}
        if set(action['condition_refs'])!=known_conditions:fail('action_conditions','Retain exactly the known local conditions for selected operations',key)
        expected_status='recorded_local' if known_conditions else 'unknown'
        if action['condition_status']!=expected_status:fail('condition_absence','No recorded condition is not proof of unconditional execution',key)
        for c in action['condition_refs']:entry(c,'condition')
        for field in ['objects','inputs','outputs']:field_check(action[field],ops,key,field)
        for h in action['support_fact_refs']:entry(h,'fact')
        for h in action['effect_refs']:
            effect=entry(h,'effect')
            if effect and effect['root_ref'] not in {e['root_ref'] for e in op_entries}:fail('effect_context','State effect belongs to a different analysis root',h)
            if effect and effect['record_ref'] not in {e['record_ref'] for e in op_entries}:
                # Finite models may use a separate effect node; its original
                # support must explicitly reference the selected operation.
                fact=next((v['record'] for v in registry.values() if v['category']=='fact' and v['record_ref']==effect['record_ref']),{})
                if not set(fact.get('provenance',{}).get('support_refs',[])) & {r for e in op_entries for r in e['fact_refs']}:
                    fail('effect_support','State effect has no supported selected operation',h)
        edges=[]
        for h in action['support_relation_refs']:
            e=entry(h,'relation')
            if e:
                a=entry(e['source_endpoint_ref'],'endpoint');b=entry(e['target_endpoint_ref'],'endpoint')
                if e['root_ref'] not in {op['root_ref'] for op in op_entries} or any(
                    endpoint and endpoint['root_ref']!=e['root_ref'] for endpoint in [a,b]):
                    fail('action_support_context','Action support crosses incompatible analysis roots',h)
                if e['kind'] not in DATA|{'information_flow','state_dependency','icc_data'}:
                    fail('action_support_type','Shared control/entry/target alone cannot group a local function',h)
                for binding in e['binding_refs']:entry(binding,'binding')
                for condition in e['condition_refs']:entry(condition,'condition')
                if e['unresolved_condition_refs']:
                    fail('action_support_conditions','Action grouping support has unexposed conditions',h)
                if a and b and a['owner_operation_ref'] and b['owner_operation_ref']:edges.append((a['owner_operation_ref'],b['owner_operation_ref']))
        if not connected(ops,edges):fail('action_grouping','Multiple operations need explicit connecting evidence',key)
        sources=set(b for e in op_entries for b in e['bu_ids'])
        previous=state['actions'].get(key)
        if previous:sources.update(previous.get('source_bu_refs',[]))
        state['actions'][key]={**action,'source_bu_refs':sorted(sources),'evidence_request_id':packet['request_id'],
            'source_limits':packet['source_limits'],'evidence_handles':sorted(proposal_handles(action))}
    for key in proposal['delete_bc_ids']:state['bcs'].pop(key,None)
    for key in proposal['delete_action_ids']:state['actions'].pop(key,None)
    # An accepted BC is checked against a specific action structure. Replacing
    # an action must not silently invalidate that BC's old program endpoints.
    changed_actions={a['action_id'] for a in proposal['upsert_actions'] if a['action_id'] in old_state['actions']
        and invalidates_existing_bcs(a,old_state['actions'][a['action_id']])}
    explicitly_revised_bcs=set(proposal['delete_bc_ids'])|{b['bc_id'] for b in proposal['upsert_bcs']}
    for key,bc in old_state['bcs'].items():
        if changed_actions & set(bc['action_ids']) and key not in explicitly_revised_bcs:
            fail('dependent_bc_update','Changed actions require dependent BC revalidation or deletion in the same transaction',key)
    for bc in proposal['upsert_bcs']:
        key=bc['bc_id'];action_ids=set(bc['action_ids']);links=[];internal=set()
        if key in old_state['bcs'] and key not in shown_bcs:fail('ledger_not_visible','Existing BC must be shown before replacement',key)
        if len(action_ids)!=len(bc['action_ids']):fail('duplicate_action','BC action IDs must be unique',key)
        if not action_ids<=set(state['actions']):fail('missing_action','BC references missing actions',key)
        if not action_ids<=shown_actions|{x['action_id'] for x in proposal['upsert_actions']}:
            fail('ledger_not_visible','Changed BC references an old action whose support was not shown',key)
        for link in bc['relations']:
            subject=key+'/'+link['link_id']
            if link['from_action'] not in action_ids or link['to_action'] not in action_ids:
                fail('link_action','Relation endpoints must be actions in this BC',subject);continue
            a=state['actions'].get(link['from_action']);b=state['actions'].get(link['to_action'])
            source=entry(link['source_endpoint_ref'],'endpoint');target=entry(link['target_endpoint_ref'],'endpoint')
            if source and a and source['owner_operation_ref'] not in a['operation_refs']:fail('link_endpoint','Source program endpoint does not correspond to its action',subject)
            if target and b and target['owner_operation_ref'] not in b['operation_refs']:fail('link_endpoint','Target program endpoint does not correspond to its action',subject)
            path=[entry(h,'relation') for h in link['support_path']];path=[x for x in path if x]
            if not path:continue
            if path[0]['source_endpoint_ref']!=link['source_endpoint_ref'] or path[-1]['target_endpoint_ref']!=link['target_endpoint_ref']:
                fail('path_endpoints','Support path endpoints do not match the claimed endpoints',subject)
            for left,right in zip(path,path[1:]):
                if left['target_endpoint_ref']!=right['source_endpoint_ref']:fail('path_disconnected','Support path is not continuous',subject)
            roots={p['root_ref'] for p in path}
            if source:roots.add(source['root_ref'])
            if target:roots.add(target['root_ref'])
            if len(roots)>1:fail('path_context','Path combines different analysis roots',subject)
            kinds={p['kind'] for p in path};summary='information_flow' in kinds or any(p['role']=='information_flow_summary' for p in path)
            modeled=any(p['provenance_kind']=='model_assisted' for p in path)
            if summary:required_kind,required_strength='information_flow','information_flow_summary'
            elif kinds<=DATA:required_kind,required_strength='data_transfer','recorded_dependency_path'
            elif kinds<=DATA|{'state_dependency'}:required_kind,required_strength='state_transfer','model_assisted_relation'
            elif kinds<=DATA|{'icc_data'}:required_kind,required_strength='icc_data','model_assisted_relation'
            elif len(path)==1 and kinds=={'control_dependency'}:required_kind,required_strength='control_constraint','model_assisted_relation'
            elif len(path)==1 and kinds=={'event_trigger'}:required_kind,required_strength='event_context','model_assisted_relation'
            elif len(path)==1 and kinds=={'icc_target'}:required_kind,required_strength='component_target','model_assisted_relation'
            else:
                fail('relation_mix','Unsupported relation-type composition',subject);continue
            if modeled and required_strength=='recorded_dependency_path':required_strength='model_assisted_relation'
            if link['relation_kind']!=required_kind or link['evidence_strength']!=required_strength:
                fail('relation_type','Relation kind/strength differs from actual support; summaries cannot become fine paths',subject)
            expected_bindings={h for p in path for h in p['binding_refs']}
            if set(link['binding_refs'])!=expected_bindings:fail('binding','Claimed object/state bindings differ from support',subject)
            for h in expected_bindings:entry(h,'binding')
            expected_conditions={h for p in path for h in p['condition_refs']}
            if set(link['condition_refs'])!=expected_conditions or any(p['unresolved_condition_refs'] for p in path):
                fail('relation_conditions','Relation condition scope differs or is not visible',subject)
            if required_kind in {'data_transfer','information_flow','state_transfer','icc_data'}:
                internal.update([link['source_endpoint_ref'],link['target_endpoint_ref']])
            links.append((link['from_action'],link['to_action']))
        if not connected(action_ids,links):fail('bc_grouping','Shared source/BU/entry is insufficient; BC needs supported action links',key)
        actions=[state['actions'][x] for x in action_ids if x in state['actions']]
        inputs={ep for a in actions for f in ['objects','inputs'] for ep in a[f]['endpoint_refs']}
        outputs={ep for a in actions for ep in a['outputs']['endpoint_refs']}
        for field,allowed in [('inputs',inputs),('outputs',outputs)]:
            chosen=set(bc['boundary'][field]['endpoint_refs'])
            if not chosen<=allowed:fail('bc_boundary','Overall boundary must summarize selected actions',key)
            if chosen&internal:fail('internal_boundary','Internal transfers cannot be listed as overall inputs/outputs',key)
            if field=='outputs':
                for endpoint in chosen:
                    ep=registry.get(endpoint,{})
                    if ep.get('boundary_role')=='explicit_normal_method_result' and ep.get('method_parent_context_ref'):
                        frames={registry[o]['context_ref'] for a in actions for o in a['operation_refs'] if o in registry}
                        if frames!={ep['context_ref']}:
                            fail('internal_method_result','Nested-frame result cannot be an outward BC output after crossing into another frame',key)
            if bc['boundary'][field]['availability']=='not_applicable' and chosen:fail('bc_boundary','Not applicable cannot have endpoints',key)
        common=set.intersection(*(set(a['condition_refs']) for a in actions)) if actions else set()
        if not set(bc['boundary']['condition_refs'])<=common:fail('condition_scope','Local conditions cannot be promoted to the entire BC',key)
        state['bcs'][key]={**bc,'source_bu_refs':sorted({u for a in actions for u in a['source_bu_refs']}),
            'source_limits':packet['source_limits'],'evidence_request_id':packet['request_id'],
            'evidence_handles':sorted(proposal_handles(bc))}
    for item in proposal['unresolved_updates']:
        if item['issue_id'] in old_state['unresolved'] and item['issue_id'] not in packet['ledger_context']['unresolved']:
            fail('ledger_not_visible','Existing unresolved item must be shown before replacement',item['issue_id'])
        if not set(item['subject_ids'])<=set(state['actions'])|set(state['bcs']):fail('unresolved_subject','Unresolved item references a missing subject',item['issue_id'])
        if item['status']=='resolved' and not item['evidence_refs']:fail('unresolved_resolution','Resolving an uncertainty requires currently visible evidence',item['issue_id'])
        state['unresolved'][item['issue_id']]={**item,'evidence_request_id':packet['request_id']}
    for bc in state['bcs'].values():
        if not set(bc['action_ids'])<=set(state['actions']):fail('dangling_action','Delete/merge/split left an accepted BC dangling',bc['bc_id'])
    for item in state['unresolved'].values():
        if not set(item['subject_ids'])<=set(state['actions'])|set(state['bcs']):fail('dangling_issue','Update left unresolved-item references dangling',item['issue_id'])
    if len(state['actions'])>config.max_actions or len(state['bcs'])>config.max_bcs:fail('ledger_budget','Action/BC budget exceeded')
    if len(proposal['fact_queries'])>config.max_queries_per_proposal:fail('query_budget','Too many supplemental queries')
    if packet.get('fact_query_protocol')=='current_facts.v1':
        for query in proposal['fact_queries']:
            if (query['apk_sha256']!=packet['identity']['source']['apk_sha256'] or
                    query['run_ref']!=packet['identity']['source']['source_run_ref']):
                fail('query_ownership','Fact query must target this APK and fact run',query['query_id'])
    state['revision']=old_state['revision']+1
    return {'valid':not errors,'errors':errors,'checker_scope':'Structured evidence/visibility/context checks; natural-language correctness is not guaranteed',
            'proposal_sha256':fingerprint(proposal)},state if not errors else None
