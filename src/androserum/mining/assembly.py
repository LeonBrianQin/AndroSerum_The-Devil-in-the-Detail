"""Bounded requests with an exact registry manifest and explicit ledger context."""
from copy import deepcopy
from androserum.facts.identity import fingerprint
from androserum.mining.checker import proposal_handles
from androserum.mining.evidence import size
from androserum.mining.models import Action,BehaviorChain


def update_closures(state):
    """Connected update components, including reverse references and issues.

    A shown action is editable only when *all* of its dependents are shown.
    Co-members and issue subjects must themselves bring their reverse closure;
    otherwise deleting/merging them would recreate the same hidden dependency.
    """
    records={(kind,key):value for kind in ('actions','bcs','unresolved') for key,value in state[kind].items()}
    graph={key:set() for key in records}
    names={key:(kind,key) for kind,key in records if kind!='unresolved'}
    for node,item in records.items():
        refs=item['action_ids'] if node[0]=='bcs' else item['subject_ids'] if node[0]=='unresolved' else []
        for ref in refs:
            if ref not in names:raise ValueError('Accepted ledger has a dangling dependency: '+ref)
            other=names[ref];graph[node].add(other);graph[other].add(node)
    seen=set();groups=[]
    for node in sorted(records):
        if node in seen:continue
        todo=[node];group=set()
        while todo:
            current=todo.pop()
            if current in group:continue
            group.add(current);todo.extend(graph[current]-group)
        seen.update(group);groups.append(sorted(group))
    return groups


def make_packet(catalog,chunk,state,config,request_id,*,extra_handles=(),repair=None,required_ledger_ids=()):
    bus=set(chunk['bu_ids']);handles=set(chunk['handles'])|set(extra_handles)
    packed=hasattr(catalog,'bundle_size')
    initial_registry=catalog.render(handles,bus) if packed else None
    initial_bus=set(bus)
    context={'actions':{},'bcs':{},'unresolved':{}}
    deferred=[]
    groups=update_closures(state);initial=set(catalog.closure(handles))
    refs=lambda kind,key:set(state[kind][key].get('evidence_handles',[]))|proposal_handles(state[kind][key])
    required_ids=set(required_ledger_ids)
    available_ids={key for kind in context for key in state[kind]}
    if required_ids-available_ids:raise ValueError('Required review subject is absent from the accepted ledger')
    groups.sort(key=lambda group:(not any(i in required_ids for k,i in group),
        not any(refs(k,i)&initial for k,i in group),group))
    context_cost=0;included=[]
    for group in groups:
        if required_ids and not any(key in required_ids for kind,key in group):
            deferred.append({'kind':'update_closure','members':[{'kind':k,'id':i} for k,i in group],
                'reason':'outside_target_review_scope','editable':False})
            continue
        addition={'actions':{},'bcs':{},'unresolved':{}};required=set();new_bus=set(bus)
        for kind,key in group:
            item=state[kind][key];fields=Action.model_fields if kind=='actions' else BehaviorChain.model_fields if kind=='bcs' else item
            addition[kind][key]=deepcopy({k:item[k] for k in fields})
            required.update(refs(kind,key));new_bus.update(item.get('source_bu_refs',[]))
        # Charge the transitive evidence closure, not just explicitly cited
        # handles. Include the whole component or none of it.
        expanded=catalog.render(handles|required,new_bus);previous=catalog.render(handles,bus)
        cost=size(addition)+size({h:v for h,v in expanded.items() if h not in previous or previous[h]!=v})
        candidate_cost=context_cost+cost
        if packed:
            candidate={k:{**context[k],**addition[k]} for k in context}
            delta={h:v for h,v in expanded.items() if h not in initial_registry or initial_registry[h]!=v}
            candidate_cost=catalog.bundle_size({'ledger_context':candidate,'evidence_expansion':delta,
                'additional_source_limits':[catalog.statuses[b] for b in sorted(new_bus-initial_bus)]})
            cost=candidate_cost-context_cost
        if candidate_cost>config.max_ledger_context_chars:
            deferred.append({'kind':'update_closure','members':[{'kind':k,'id':i} for k,i in group],
                'reason':'ledger_context_budget','required_chars':cost,'editable':False});continue
        for kind in context:context[kind].update(addition[kind])
        handles.update(required);bus=new_bus;context_cost=candidate_cost
        included.append({'members':[{'kind':k,'id':i} for k,i in group],'charged_chars':cost})
    if required_ids-{key for kind in context for key in context[kind]}:
        raise ValueError('Required review closure exceeds ledger context budget; no noneditable review dispatch')
    registry=catalog.render(handles,bus)
    packet={'schema_version':'behavior-request.v1','request_id':request_id,'base_revision':state['revision'],
        'identity':state['identity'],'source_limits':[catalog.statuses[b] for b in sorted(bus)],
        'evidence':registry,'ledger_context':context,'ledger_context_deferred':deferred,
        'ledger_update_closures':included,'ledger_context_chars':context_cost,
        'manifest':{'handles':sorted(registry),'evidence_sha256':fingerprint(registry),
            'source_bu_refs':sorted(bus),'program_text_is_data':True,'archive_files_included':False,
            'fact_refs':sorted({r for e in registry.values() for r in e.get('fact_refs',[])})},
        'repair':repair,'budgets':{'fact_queries':'explicit referenced record IDs only','max_queries':config.max_queries_per_proposal}}
    if packed:
        packet['schema_version']='behavior-request.v2'
        packet['packing_profile']=catalog.identity['packing_profile']
        packet['budget_accounting']='same-bundle lossless transport characters; materialized fields are complete'
    packet['detail_queries_available']=[{'record_ref':e['record_ref'],'handle':h,
        'missing_fields':e['detail_fields_available']} for h,e in registry.items()
        if e['category']=='fact' and e.get('detail_fields_available')]
    if getattr(config, 'fact_query_protocol', None) == 'current_facts.v1':
        from androserum.facts.queries import query_capabilities
        packet['fact_query_protocol'] = 'current_facts.v1'
        packet['fact_query_capabilities'] = query_capabilities()
        packet['budgets']['fact_queries'] = 'Structured queries against existing facts of the current APK/run only'
        packet['budgets']['max_returned_records'] = config.max_supplement_records
        packet['budgets']['max_query_return_chars'] = config.max_query_return_chars
    if (catalog.bundle_size(packet) if packed else size(packet))>config.max_request_chars:
        raise ValueError('Request exceeds hard context budget; no silent evidence or ledger truncation')
    return packet
