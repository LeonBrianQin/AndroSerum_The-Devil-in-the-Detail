"""Structural match checking; does not decide arbitrary natural-language meaning."""
from collections import defaultdict,deque
from androserum.facts.identity import fingerprint
from androserum.facts.io import strict_json_syntax
from .models import MatchProposal,MatchProposalV2,MatchProposalV3,MatchConfig
from .decisions import decision_kind,is_supported

DATA={'data_dependency','field_dependency','array_dependency'}


def known_boolean_truth(condition):
    """Unknown or non-boolean model values cannot establish predicate truth."""
    expected=condition.get('expected_value')
    if not isinstance(expected,dict) or expected.get('status')!='known' or type(expected.get('value')) is not bool:
        return None
    return expected['value']


def _path_profile(registry,handles):
    edges=[registry[h] for h in handles]
    if not edges:raise ValueError('Empty support path')
    if any(a['target_endpoint_ref']!=b['source_endpoint_ref'] for a,b in zip(edges,edges[1:])):raise ValueError('Disconnected path')
    source=edges[0]['source_endpoint_ref'];target=edges[-1]['target_endpoint_ref']
    endpoints=[registry[h] for e in edges for h in [e['source_endpoint_ref'],e['target_endpoint_ref']]]
    if len({e['root_ref'] for e in [*edges,*endpoints]})!=1:raise ValueError('Path joins different analysis roots')
    if any(e['unresolved_condition_refs'] for e in edges):raise ValueError('Path has undisplayed conditions')
    kinds={e['kind'] for e in edges};modeled=any(e['provenance_kind']=='model_assisted' for e in edges)
    if 'information_flow' in kinds or any(e['role']=='information_flow_summary' for e in edges):
        if not kinds<=DATA|{'information_flow'}:raise ValueError('Coarse flow cannot absorb control/event/state relationships')
        kind,strength='information_flow','information_flow_summary'
    elif kinds<=DATA:kind,strength='data_transfer','model_assisted_relation' if modeled else 'recorded_dependency_path'
    elif kinds<=DATA|{'state_dependency'}:kind,strength='state_transfer','model_assisted_relation'
    elif kinds<=DATA|{'icc_data'}:kind,strength='icc_data','model_assisted_relation'
    elif len(edges)==1 and kinds=={'control_dependency'}:kind,strength='control_constraint','model_assisted_relation'
    elif len(edges)==1 and kinds=={'event_trigger'}:kind,strength='event_context','model_assisted_relation'
    elif len(edges)==1 and kinds=={'icc_target'}:kind,strength='component_target','model_assisted_relation'
    else:raise ValueError('Unsupported mixed relation path')
    return {'support_path':handles,'source_endpoint':source,'target_endpoint':target,
        'binding_refs':sorted({h for e in edges for h in e['binding_refs']}),
        'context_refs':sorted({e['context_ref'] for e in [*edges,*endpoints] if e.get('context_ref')}),
        'condition_refs':sorted({h for e in edges for h in e['condition_refs']})},kind,strength


def path_metadata(side,link_ids):
    """Frozen v1 BC-link interpretation; raw relation handles are not link IDs."""
    links={x['link_id']:x for x in side['bc']['relations']}
    selected=[links[x] for x in link_ids];handles=[h for link in selected for h in link['support_path']]
    actual,kind,strength=_path_profile(side['registry'],handles)
    return {'link_ids':link_ids,**actual},kind,strength


def path_metadata_v2(side,selection):
    """Resolve one explicit v2 native path; never infer or concatenate path kinds."""
    common={'support_path','source_endpoint','target_endpoint','binding_refs','context_refs','condition_refs'}
    kind=selection.get('path_kind');registry=side['registry']
    if kind=='bc_links':
        if set(selection)!=(common|{'path_kind','link_ids'}):raise ValueError('BC-link path cannot contain an internal action selector')
        if len(selection['link_ids'])!=len(set(selection['link_ids'])):raise ValueError('Repeated BC links are outside v2 path scope')
        actual,profile,strength=path_metadata(side,selection['link_ids'])
        return {'path_kind':'bc_links',**actual},profile,strength
    if kind!='action_internal':raise ValueError('Unknown v2 native path kind')
    if set(selection)!=(common|{'path_kind','action_id'}):raise ValueError('Action-internal path cannot contain BC link IDs')
    action=side['actions'].get(selection['action_id'])
    if action is None:raise ValueError('Internal path action is absent from this side')
    handles=selection['support_path']
    if not handles or len(handles)!=len(set(handles)):raise ValueError('Internal path must contain distinct recorded support relations')
    if not set(handles)<=set(action['support_relation_refs']):raise ValueError('Internal path relation is outside selected action support_relation_refs')
    allowed=DATA|{'state_dependency','information_flow','icc_data'}
    for handle in handles:
        edge=registry.get(handle)
        if not edge or edge.get('category')!='relation' or edge.get('kind') not in allowed:
            raise ValueError('Internal path requires a supported recorded data/state/summary relationship')
        for key in ['source_endpoint_ref','target_endpoint_ref']:
            endpoint=registry.get(edge[key])
            if not endpoint or endpoint.get('category')!='endpoint':raise ValueError('Internal path endpoint is absent or has the wrong role')
            owner=endpoint.get('owner_operation_ref')
            if owner is not None and owner not in action['operation_refs']:
                raise ValueError('Internal path crosses an operation outside its selected action')
        for binding in edge['binding_refs']:
            if registry.get(binding,{}).get('category')!='binding':raise ValueError('Internal path binding is absent or has the wrong role')
        for condition in edge['condition_refs']:
            if registry.get(condition,{}).get('category')!='condition':raise ValueError('Internal path condition is absent or has the wrong role')
    actual,profile,strength=_path_profile(registry,handles)
    operations=set(action['operation_refs'])
    if any(registry[actual[key]]['owner_operation_ref'] not in operations for key in ['source_endpoint','target_endpoint']):
        raise ValueError('Internal path endpoints must belong to selected action operations')
    return {'path_kind':'action_internal','action_id':selection['action_id'],**actual},profile,strength


def check_match(raw,request,config=None):
    """Explicit request-version dispatch; v1 never gains internal-path semantics."""
    version=request.get('schema_version','behavior-match-request.v1')
    if version not in {'behavior-match-request.v1','behavior-match-request.v2','behavior-match-request.v3'}:
        return {'valid':False,'errors':[{'code':'request_protocol','message':'Unknown matching request protocol'}],'accepted':None}
    return _check_match(raw,request,config,v2=version!='behavior-match-request.v1',v3=version=='behavior-match-request.v3')


def check_match_v2(raw,request,config=None):
    if request.get('schema_version')!='behavior-match-request.v2':
        return {'valid':False,'errors':[{'code':'request_protocol','message':'Typed internal paths require explicit matching request v2'}],'accepted':None}
    return _check_match(raw,request,config,v2=True)


def _check_match(raw,request,config=None,*,v2=False,v3=False):
    config=config or MatchConfig();errors=[]
    def fail(code,message):errors.append({'code':code,'message':message})
    try:
        if len(raw)>config.max_response_chars:raise ValueError('Response budget exceeded')
        strict_json_syntax(raw);proposal=(MatchProposalV3 if v3 else MatchProposalV2 if v2 else MatchProposal).model_validate_json(raw).model_dump(mode='json')
    except ValueError as error:return {'valid':False,'errors':[{'code':'schema','message':str(error)}],'accepted':None}
    if proposal['request_id']!=request['request_id'] or proposal['pair_sha256']!=request['pair_sha256']:fail('pair_identity','Response is for a different request/pair')
    if fingerprint(request['sides'])!=request['pair_sha256']:fail('visible_pair_digest','Actually provided sides changed')
    sides=request['sides'];groups={};used={'query':set(),'reference':set()};selected_links={'query':set(),'reference':set()}
    for mapping in proposal['action_mappings']:
        key=mapping['mapping_id']
        if key in groups:fail('duplicate_mapping','Duplicate action group ID')
        groups[key]=mapping
        for side in ['query','reference']:
            ids=mapping[side+'_actions']
            if len(ids)!=len(set(ids)) or used[side]&set(ids):fail('overlap_mapping','An action is duplicated across correspondence groups')
            if not set(ids)<=set(sides[side]['actions']):fail('action_ref','Action is absent from the indicated side')
            used[side].update(ids)
    def citation(ref):
        side=sides[ref['side']];kind=ref['kind'];key=ref['ref']
        if kind=='action':valid=key in side['actions']
        elif kind=='link':valid=key in {x['link_id'] for x in side['bc']['relations']}
        else:valid=key in side['registry'] and (kind!='condition' or side['registry'][key]['category']=='condition')
        if not valid:fail('citation_visibility','Difference cites an absent/wrong-side record')
    for difference in proposal['differences']:
        for c in difference['citations']:citation(c)
    relation_ids=set();adj=defaultdict(set)
    selected_conditions={'query':set(),'reference':set()};condition_scopes=defaultdict(set)
    for side in sides:
        for mapping_id,group in groups.items():
            for key in group[side+'_actions']:
                if key in sides[side]['actions']:
                    conditions=sides[side]['actions'][key]['condition_refs'];selected_conditions[side].update(conditions)
                    for c in conditions:condition_scopes[side,c].add(mapping_id)
    for relation in proposal['relation_mappings']:
        if relation['mapping_id'] in relation_ids or relation['mapping_id'] in groups:fail('duplicate_mapping','Relation ID collides')
        relation_ids.add(relation['mapping_id'])
        source_group=groups.get(relation['from_mapping']);target_group=groups.get(relation['to_mapping'])
        if source_group is None or target_group is None:fail('relation_groups','Path references absent action correspondence');continue
        profiles={}
        for side in ['query','reference']:
            supplied=relation[side];selected_links[side].update(supplied.get('link_ids',[]))
            if v2 and supplied.get('path_kind')=='action_internal' and not all(
                supplied['action_id'] in group[side+'_actions'] for group in [source_group,target_group]):
                fail('internal_action_scope','Internal path action must belong to both endpoint correspondence groups')
            try:actual,kind,strength=path_metadata_v2(sides[side],supplied) if v2 else path_metadata(sides[side],supplied['link_ids'])
            except (ValueError,KeyError) as error:fail('support_path',str(error));continue
            unordered={'binding_refs','context_refs','condition_refs'}
            if any((len(supplied[k])!=len(set(supplied[k])) or set(supplied[k])!=set(actual[k])) if k in unordered else supplied[k]!=actual[k] for k in actual):
                fail('path_metadata','Path endpoints/conditions/contexts/bindings differ from recorded evidence')
            profiles[side]=(kind,strength);selected_conditions[side].update(actual['condition_refs'])
            for c in actual['condition_refs']:condition_scopes[side,c].add(relation['mapping_id'])
            registry=sides[side]['registry'];a=registry[actual['source_endpoint']]['owner_operation_ref'];b=registry[actual['target_endpoint']]['owner_operation_ref']
            sg,tg=source_group,target_group
            if side=='reference' and relation['direction']=='reversed':sg,tg=tg,sg
            source_ops={op for key in sg[side+'_actions'] if key in sides[side]['actions'] for op in sides[side]['actions'][key]['operation_refs']}
            target_ops={op for key in tg[side+'_actions'] if key in sides[side]['actions'] for op in sides[side]['actions'][key]['operation_refs']}
            if a not in source_ops or b not in target_ops:fail('direction_endpoint_binding','Recorded directed endpoints do not correspond to the mapped action groups')
        if len(profiles)==2:
            q,r=relation['query'],relation['reference']
            expected={('source',q['source_endpoint'],r['source_endpoint'] if relation['direction']=='aligned' else r['target_endpoint']),
                ('target',q['target_endpoint'],r['target_endpoint'] if relation['direction']=='aligned' else r['source_endpoint'])}
            supplied={(c['query_role'],c['query_endpoint'],c['reference_endpoint']) for c in relation['endpoint_correspondence']}
            if supplied!=expected:fail('endpoint_correspondence','Cross-side endpoint pairs do not follow the declared directed action correspondence')
            if profiles['query']!=profiles['reference'] or profiles['query']!=(relation['relation_kind'],relation['evidence_strength']):fail('relation_type','Data/control/event/state/summary roles cannot substitute for each other')
            if relation['claims_complete_fine_path'] and any(p!=('data_transfer','recorded_dependency_path') for p in profiles.values()):fail('summary_upgrade','Summary or modeled relationship cannot become a complete fine-grained path')
        if is_supported(proposal['decision']) and relation['direction']!='aligned':fail('direction_conflict','Reversed direction blocks support for this selected relationship')
        adj[relation['from_mapping']].add(relation['to_mapping']);adj[relation['to_mapping']].add(relation['from_mapping'])
    # Full correspondence includes the BC boundary. Its conditions apply to
    # the complete selected correspondence, not only to an arbitrary action.
    # Partial correspondence does not automatically claim that whole boundary.
    if proposal['scope']=='full':
        for side in ['query','reference']:
            for h in sides[side]['bc']['boundary']['condition_refs']:
                if sides[side]['registry'].get(h,{}).get('category')!='condition':
                    fail('condition_visibility','BC boundary condition is not visible on the indicated side');continue
                selected_conditions[side].add(h)
                condition_scopes[side,h].update(set(groups)|relation_ids)
    condition_seen={'query':set(),'reference':set()};condition_ids=set();condition_conflict=False
    for mapping in proposal['condition_mappings']:
        if mapping['query_condition'] is None and mapping['reference_condition'] is None:fail('empty_condition','Condition correspondence has no side record')
        if mapping['mapping_id'] in condition_ids|relation_ids|set(groups):fail('duplicate_mapping','Condition ID collides')
        condition_ids.add(mapping['mapping_id'])
        if not set(mapping['affected_mappings'])<=set(groups)|relation_ids:fail('condition_scope','Condition scope references absent correspondence')
        info={}
        actual_scope=set()
        for side in ['query','reference']:
            h=mapping[side+'_condition']
            if h is None:continue
            if h not in selected_conditions[side]:fail('condition_scope','Condition is outside the selected action/path scope');continue
            condition_seen[side].add(h);info[side]=sides[side]['condition_semantics'].get(h,{})
            actual_scope.update(condition_scopes[side,h])
        if set(mapping['affected_mappings'])!=actual_scope:fail('condition_scope','Condition correspondence changed its actual action/relationship scope')
        if len(info)==2:
            a,b=info['query'],info['reference'];known=a.get('predicate_key') and a.get('predicate_key')==b.get('predicate_key')
            same_scope=a.get('scope')==b.get('scope')
            qa,rb=known_boolean_truth(a),known_boolean_truth(b)
            truth_known=qa is not None and rb is not None
            equivalent=known and same_scope and truth_known and qa==rb
            if mapping['comparison'] in {'equivalent','compatible_with_limits'} and not (a.get('predicate_key') and b.get('predicate_key')):
                fail('condition_semantics','Unnormalized predicate correspondence remains unknown')
            if mapping['comparison']=='equivalent' and not equivalent:fail('condition_equivalence','Equivalence requires the same normalized predicate/scope and known equal Boolean requirements')
            # This version has no finite implication/overlap solver. The only
            # certified compatibility rule is identity of the known predicate
            # requirement; prose or merely nonempty predicate keys do not
            # establish compatibility between different conditions.
            if mapping['comparison']=='compatible_with_limits' and not equivalent:
                fail('condition_compatibility','No finite compatibility rule supports these predicate requirements; preserve unknown instead')
            if known and same_scope and truth_known and qa!=rb:
                condition_conflict=True
                if mapping['comparison']!='conflict':fail('condition_conflict','Known opposite condition truth was concealed')
            if mapping['comparison']=='conflict' and not (known and same_scope and truth_known and qa!=rb):
                fail('condition_conflict','Conflict is not established by known opposite requirements for the same normalized predicate/scope')
        elif mapping['comparison'] in {'equivalent','compatible_with_limits','conflict'}:fail('condition_equivalence','A missing-side condition cannot be declared equal, compatible or conflicting')
        if mapping['comparison']=='conflict':condition_conflict=True
        if mapping['comparison']=='unknown' and is_supported(proposal['decision']):fail('condition_unknown','Selected predicate correspondence is unresolved; it cannot support that scope')
    if condition_seen!=selected_conditions:fail('condition_coverage','All selected action/path conditions need explicit correspondence or unknown records')
    for group in groups.values():
        for side in ['query','reference']:
            ids=set(group[side+'_actions'])
            if len(ids)<2:continue
            inside=defaultdict(set)
            for link in sides[side]['bc']['relations']:
                if link['link_id'] in selected_links[side] and {link['from_action'],link['to_action']}<=ids:
                    inside[link['from_action']].add(link['to_action']);inside[link['to_action']].add(link['from_action'])
            seen=set();queue=deque([next(iter(ids))])
            while queue:
                node=queue.popleft()
                if node not in seen:seen.add(node);queue.extend(inside[node]-seen)
            if seen!=ids:fail('group_support','Grouping several actions needs recorded connecting paths within the selected correspondence')
    for side in ['query','reference']:
        actions=set(sides[side]['actions']);links={x['link_id'] for x in sides[side]['bc']['relations']}
        if set(proposal['unmapped'][side+'_actions'])!=actions-used[side] or set(proposal['unmapped'][side+'_links'])!=links-selected_links[side]:fail('coverage','Unmapped scope must exactly list records outside the declared correspondences')
        if proposal['scope']=='full' and (actions!=used[side] or links!=selected_links[side]):fail('full_scope','Full matching cannot leave actions or links outside scope')
    if is_supported(proposal['decision']):
        if proposal['scope']=='none' or not groups:fail('empty_support','Support requires a nonempty matched scope')
        if condition_conflict or any(d['impact']=='blocks_selected_scope' for d in proposal['differences']):fail('blocking_difference','Blocking differences cannot be accepted as support for this scope')
        if not proposal['limitations']:fail('missing_limits','Static/partial/unknown limits must remain explicit')
        if len(groups)>1:
            seen=set();queue=deque([next(iter(groups))])
            while queue:
                n=queue.popleft()
                if n not in seen:seen.add(n);queue.extend(adj[n]-seen)
            if seen!=set(groups):fail('unsupported_grouping','Mapped functions lack supported connecting relationships')
    elif decision_kind(proposal['decision'])=='different_behavior':
        if not any(d['impact']=='blocks_selected_scope' and {c['side'] for c in d['citations']}=={'query','reference'} for d in proposal['differences']):fail('difference_basis','A difference verdict needs a blocking contrast citing both sides')
    else:
        if not proposal['unresolved'] or not any(d['kind']=='evidence' for d in proposal['differences']):fail('insufficient_basis','Insufficient evidence requires explicit gaps and unresolved scope')
    # Known, bounded purpose annotations are engineering controls, never new
    # natural-language types imposed on native BCs.
    for group in groups.values():
        q={sides['query']['purpose_claims'][k] for k in group['query_actions'] if k in sides['query']['purpose_claims']}
        r={sides['reference']['purpose_claims'][k] for k in group['reference_actions'] if k in sides['reference']['purpose_claims']}
        if q and r and q!=r and is_supported(proposal['decision']):fail('purpose_conflict','Explicit scoped purpose differs within the claimed support')
    return {'valid':not errors,'errors':errors,'proposal_sha256':fingerprint(proposal),
        'accepted':proposal if not errors else None,
        'source_limit_refs':['request.json#/sides/query/source_limits','request.json#/sides/reference/source_limits'],
        'checker_scope':('Explicit v2 BC-link/action-internal paths, action ownership, shown references, directed native support, types, contexts, bindings and scoped conditions; natural-language meaning is not certified' if v2 else
                         'Shown references, directed recorded paths, types, contexts, bindings and scoped condition models; natural-language meaning is not certified')}
