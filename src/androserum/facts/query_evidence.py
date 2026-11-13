"""Admit returned current facts as typed evidence only in verified existing frames.

This is an adapter over the accepted BU graph, not another analysis or archive
loader. Missing program support is returned as a further-query frontier.
"""
from copy import deepcopy
from collections import deque

from .identity import fingerprint
from .models import Endpoint
from .bu import BUConfig, _Graph, _Unit
from androserum.mining.evidence import EvidenceCatalog


STRUCTURAL = {'element_ref','method_ref','class_ref','dex_ref','parent_ref','context_ref',
              'branch_ref','binding_refs','condition_refs','callsite_ref','callsite_refs','source_refs'}


def _references(value):
    if isinstance(value,dict):
        for key,item in value.items():
            if key in STRUCTURAL:
                for ref in item if isinstance(item,list) else [item]:
                    if isinstance(ref,str):yield ref
            if key not in {'provenance','text','value','description'}:
                yield from _references(item)
    elif isinstance(value,list):
        for item in value:yield from _references(item)


def adapt_query_evidence(catalog,view,returned_records,bu_ids,*,query_id='current_query_evidence'):
    """Return typed deltas, per-record decisions, and missing support IDs.

    Supported: existing ContextHeap operation projections and its recorded
    scalar/heap/modeled/summary edges in selected BU roots. Both endpoint owners,
    concrete frame records, bindings and conditions must be returned or already
    visible. Original DEX alone never grants an unseen projected operation.
    """
    if (catalog.identity['source_run_ref']!=view.run_ref or catalog.identity['source_snapshot_id']!=view.snapshot_id
            or catalog.identity['apk_sha256']!=view.manifest.apk_sha256):
        raise ValueError('Query evidence adapter requires the exact current APK/run/snapshot')
    bu_ids=sorted(set(bu_ids))
    if not set(bu_ids)<=set(catalog.units):raise ValueError('Query evidence cannot create a new BU scope')
    facts=view.export_bundle()
    records={r.id:r.model_dump(mode='json') for group in [facts.elements,facts.relations,facts.contexts,facts.bindings,facts.statuses] for r in group}
    old_entries=deepcopy(catalog.entries);staged=deepcopy(catalog)
    returned={};decisions=[];needed=set()
    for value in returned_records:
        raw=value.model_dump(mode='json') if hasattr(value,'model_dump') else deepcopy(value)
        ref=raw.get('id')
        if raw.get('run_ref')!=view.run_ref or ref not in records or raw!=records[ref]:
            decisions.append({'record_ref':ref,'state':'rejected','reason':'not_an_exact_returned_current_snapshot_record'});continue
        # Receipts are canonical JSON in SQLite. Rehydrate the verified current
        # contract order before supplement() records shown_fields, so replay
        # cannot depend on caller/JSON object key insertion order.
        raw=deepcopy(records[ref])
        if ref in returned and returned[ref]!=raw:raise ValueError('Conflicting returned fact identity')
        returned[ref]=raw
        staged.supplement(raw,query_id,bu_ids)
    graphs={}
    for bu in bu_ids:
        unit=catalog.units[bu];root=unit['anchor']['root_method_ref']
        if root not in graphs:graphs[root]=_Graph(view,facts,root)
        g=graphs[root]
        if g.report.state!='complete' or unit['anchor']['projection_context_ref'] not in g.frames:
            decisions.extend({'record_ref':r,'bu_id':bu,'state':'unsupported','reason':'current_BU_has_no_complete_verified_context_projection'} for r in returned)
            continue
        existing={e['record_ref'] for e in catalog.entries.values() if e['category']=='fact' and bu in e['bu_ids']}
        authorized=existing|set(returned)
        candidates={e['record_ref']:records[e['record_ref']] for e in staged.entries.values()
                    if e['category']=='fact' and e.get('supplement_query_id') and bu in e['bu_ids'] and e['record_ref'] in records}
        required=set();new_ops={};new_controls=[];new_relations={};method_outputs={}
        model_conditions={}
        def closure(seeds):
            result={r for r in seeds if r in records};queue=deque(result)
            while queue:
                ref=queue.popleft()
                for target in _references(records[ref]):
                    if target in records and target not in result:result.add(target);queue.append(target)
            return result
        def missing(seeds):return sorted(closure(seeds)-authorized)
        def operation(meta):
            if meta is None or meta.node_ref not in g.nodes or not meta.origin_ref:
                return None,{'reason':'endpoint_has_no_verified_operation_owner'}
            probe=_Unit(view,facts,BUConfig(),unit['anchor'],g,g.frames[unit['anchor']['projection_context_ref']],catalog.identity['extraction_run_ref'])
            probe.add_operation(meta,purpose='current_query_admission')
            seeds=set(probe.selected)|{meta.node_ref,meta.origin_ref,meta.origin_method_ref,meta.frame_ref}
            for call in g.frames[meta.frame_ref].call_path:
                seeds.update([call.callsite_ref,call.callee_ref,call.context_ref])
                seeds.update(r.id for r in facts.relations if r.relation_kind=='candidate_call' and
                    r.callsite_ref==call.callsite_ref and r.context_ref==call.context_ref and r.target and r.target.element_ref==call.callee_ref)
            required_refs=closure(seeds)
            absent=sorted(required_refs-authorized)
            if absent:return None,{'reason':'operation_support_not_returned_or_visible','required_record_refs':absent}
            return {'probe':probe,'required':required_refs},None
        def include_op(meta,accepted):
            probe=accepted['probe'];required.update(accepted['required'])
            new_ops.update(probe.ops)
            for row in probe.controls:
                if row not in new_controls:new_controls.append(row)
            for key,row in probe.relations.items():new_relations[key]=row
            for key in probe.ops:
                if key in g.method_output_rows:
                    row=g.method_output_rows[key];method_outputs[row['relation_ref']]=row
        def decision(ref,state,reason,**extra):
            row={'record_ref':ref,'bu_id':bu,'root_ref':root,'state':state,'reason':reason,**extra}
            decisions.append(row);needed.update(row.get('required_record_refs',[]))
        # Authorize operations only by concrete projection identity. A returned
        # raw call can locate an already-visible projection, but cannot create it.
        for ref,raw in candidates.items():
            if raw.get('kind') not in {'instruction','analysis_node'}:continue
            metas=[]
            if ref in g.nodes:metas=[g.nodes[ref]]
            elif raw.get('kind')=='instruction':
                matches=[m for m in g.nodes.values() if ref in g.raw_for_origin.get(m.origin_ref,[]) and m.role not in {'exception_effect','exit'}]
                metas=[m for m in matches if m.node_ref in authorized]
                if not metas and matches:
                    decision(ref,'needs_support','concrete_projected_operation_not_returned',required_record_refs=sorted({m.node_ref for m in matches}));continue
            for meta in metas:
                accepted,error=operation(meta)
                if error:decision(ref,'needs_support' if error.get('required_record_refs') else 'unsupported',**error)
                else:
                    include_op(meta,accepted)
                    decision(ref,'admitted_typed','verified_existing_projection_operation',operation_ref=meta.node_ref,
                             context_ref=meta.frame_ref,support_record_refs=sorted(accepted['required']))
        for ref,raw in candidates.items():
            if 'relation_kind' not in raw:continue
            item=g.edges.get(ref)
            if item is None:
                decision(ref,'unsupported','relation_not_in_supported_current_BU_graph');continue
            edge=item['record']
            owners=[g.meta(item['source']),g.meta(item['target'])]
            if any(owner is None for owner in owners):
                decision(ref,'unsupported','relation_endpoint_owner_unmapped');continue
            accepted_ops=[];errors=[]
            for meta in owners:
                accepted,error=operation(meta)
                if error:errors.append(error)
                else:accepted_ops.append((meta,accepted))
            seeds={ref,edge.source.element_ref,edge.target.element_ref,*edge.binding_refs,*edge.condition_refs}
            if edge.context_ref:seeds.add(edge.context_ref)
            if item['modeled']:seeds.update(edge.provenance.support_refs)
            absent=sorted(set(missing(seeds))|{r for e in errors for r in e.get('required_record_refs',[])})
            if absent:
                decision(ref,'needs_support','relation_endpoint_binding_condition_or_operation_support_missing',required_record_refs=absent);continue
            if errors:
                decision(ref,'unsupported','relation_operation_mapping_unsupported',mapping_errors=errors);continue
            for meta,accepted in accepted_ops:include_op(meta,accepted)
            required.update(closure(seeds))
            row={'record_ref':ref,'traversal_source':item['source'].model_dump(mode='json'),
                 'traversal_target':item['target'].model_dump(mode='json'),'modeled':item['modeled'],
                 'binding':deepcopy(item['binding']),'root_method_ref':root,
                 'evidence_role':'information_flow_summary' if item['summary'] else 'program_dependency',
                 'fine_grained_path_claimed':False if item['summary'] else None}
            if item['summary']:row['flow_summary']=deepcopy(item['summary'])
            new_relations[ref]=row
            decision(ref,'admitted_typed','verified_existing_graph_relation',context_ref=edge.context_ref,
                     evidence_role=row['evidence_role'],fine_grained_path_claimed=False,
                     support_record_refs=sorted(closure(seeds)|set().union(*(a['required'] for _,a in accepted_ops))))
        for ref in required:
            record=records[ref]
            if record.get('kind')=='condition' and record.get('provenance',{}).get('kind')=='model_assisted':
                meta=g.nodes.get(record['branch_ref'])
                if meta:model_conditions[ref]={'condition_ref':ref,'context_ref':meta.frame_ref,
                    'scope':'model_relation_precondition_not_execution_guard'}
        # Reuse the established serializer/checker contract over exactly the
        # authorized support set, never the rest of the available fact graph.
        visible=deepcopy(unit['model_visible'])
        visible['records']=[records[r] for r in sorted(existing|required)]
        visible['allowed_citation_refs']=sorted(existing|required)
        for key,rows in [('operation_records',list(new_ops.values())),('control_records',new_controls),
                         ('relation_records',list(new_relations.values())),('method_output_records',list(method_outputs.values())),
                         ('model_conditions',list(model_conditions.values()))]:
            prior=visible.get(key,[])
            if rows:visible[key]=prior+[row for row in rows if row not in prior]
        synthetic={**deepcopy(unit),'model_visible':visible}
        serialized=EvidenceCatalog({**catalog.identity,'units':[synthetic]},[bu])
        for h,entry in serialized.entries.items():
            if entry['category']=='fact':continue
            if h in staged.entries and entry['category']=='condition':
                entry=deepcopy(entry)
                entry['source_collection_by_bu'].update(staged.entries[h]['source_collection_by_bu'])
                entry['constant_operands']=staged.entries[h]['constant_operands']
            if h not in staged.entries:entry={**entry,'supplement_query_id':query_id}
            # Attribution is an admission audit, not a changed program fact.
            elif 'supplement_query_id' in staged.entries[h]:entry={**entry,'supplement_query_id':staged.entries[h]['supplement_query_id']}
            staged.add(entry,bu)
    decided={row['record_ref'] for row in decisions}
    decisions.extend({'record_ref':ref,'state':'raw_fact_only','reason':'no_new_supported_graph_role_requested_or_mapped'} for ref in returned if ref not in decided)
    changed=sorted(h for h,e in staged.entries.items() if h not in old_entries or e!=old_entries[h])
    catalog.entries,catalog.facts=staged.entries,staged.facts
    return {'schema_version':'current-query-typed-admission.v1','added_handles':changed,'decisions':decisions,
            'required_record_refs':sorted(needed),'only_returned_or_previously_visible_facts_authorized':True,
            'archive_evidence_added':False,'new_static_analysis_performed':False,
            'supported_scope':'Existing verified selected-root ContextHeap projections and their recorded graph edges; no new frame or consumer expansion'}
