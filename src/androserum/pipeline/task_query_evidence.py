"""Typed current-fact query deltas over frozen task BC evidence.

Only source identity metadata is read from a mining package. BU archives never
grant evidence. Program-role admission delegates to the same verified graph
adapter as mining, over actually returned or completely displayed records.
"""
from copy import deepcopy
import json
from pathlib import Path

from androserum.facts.bu import _Graph
from androserum.facts.identity import filesystem_path, fingerprint, sha256_file
from androserum.facts.query_evidence import adapt_query_evidence
from androserum.mining.evidence import EvidenceCatalog


def _basis(side, view, allow_synthetic):
    origin=side['origin']
    if allow_synthetic and origin.get('evidence_kind')=='synthetic_protocol' and origin.get('query_context_basis'):
        value=deepcopy(origin['query_context_basis'])
        audit={'role':'explicit_protocol_source_identity_metadata','identity_sha256':fingerprint(value)}
    else:
        if not isinstance(origin.get('ledger_ref'),(str,Path)) or not str(origin['ledger_ref']).strip():
            raise ValueError('No verified mining identity metadata; raw attributes remain usable without typed graph authority')
        root=filesystem_path(origin['ledger_ref']);run=root/'run.json';manifest=root/'manifest.json'
        package=json.loads(manifest.read_text('utf-8'));metadata=json.loads(run.read_text('utf-8'))
        item=package['files']['run.json'];expected=item['sha256'] if isinstance(item,dict) else item
        if sha256_file(run)!=expected or metadata['identity']!=package['identity']:
            raise ValueError('Mining source identity metadata differs from its manifest')
        value=metadata['identity']['source']
        audit={'role':'source_identity_only_no_archive_grant','run_json':str(run),'run_json_sha256':sha256_file(run),
            'manifest_sha256':sha256_file(manifest)}
    if (value['apk_sha256']!=view.manifest.apk_sha256 or value['source_run_ref']!=view.run_ref or
            value['source_snapshot_id']!=view.snapshot_id or not value.get('extraction_run_ref')):
        raise ValueError('Typed task query basis differs from exact APK/run/snapshot')
    return value,audit


def adapt_task_query_evidence(view,catalog,previous_grants,returned_records,visible_bc_ids,*,query_id,
                              requested_bc_ids=(),allow_synthetic_protocol=False):
    """Return a checked typed delta; no action or frozen BC is rewritten."""
    visible=set(visible_bc_ids)
    if not visible<=set(catalog['bcs']):raise ValueError('Typed query scope contains an unseen BC')
    selected=visible & set(requested_bc_ids) if requested_bc_ids else visible
    groups={};decisions=[];basis_audits=[]
    for bid in sorted(selected):
        side=catalog['bcs'][bid]
        try:
            identity,audit=_basis(side,view,allow_synthetic_protocol)
        except (OSError,KeyError,ValueError) as error:
            decisions.append({'bc_id':bid,'state':'unsupported','reason':'verified_source_identity_metadata_unavailable',
                'detail':str(error)});continue
        key=identity['extraction_run_ref'];group=groups.setdefault(key,{'identity':identity,'bcs':[]})
        if group['identity']!=identity:raise ValueError('One BU extraction identity names conflicting sources')
        group['bcs'].append(bid);basis_audits.append({'bc_id':bid,**audit})
    facts=view.export_bundle()
    records={r.id:r.model_dump(mode='json') for part in [facts.elements,facts.relations,facts.contexts,facts.bindings,facts.statuses] for r in part}
    visible_entries={}
    for bid in sorted(visible):
        for h,e in catalog['bcs'][bid]['registry'].items():
            if h in visible_entries and visible_entries[h]!=e:
                old=deepcopy(visible_entries[h]);new=deepcopy(e)
                # Existing callers coordinate full payloads; only BU membership
                # may differ in this read-only task facade.
                memberships=sorted(set(old.pop('bu_ids',[]))|set(new.pop('bu_ids',[])))
                if old!=new:raise ValueError('Conflicting frozen BC evidence payload')
                visible_entries[h]['bu_ids']=memberships
            else:visible_entries[h]=deepcopy(e)
    current={**deepcopy(visible_entries),**deepcopy(previous_grants)}
    result_entries={};admissions=[];graphs={}
    for group in groups.values():
        selected_entries={h:e for bid in group['bcs'] for h,e in catalog['bcs'][bid]['registry'].items()}
        bu_ids=sorted({bu for e in selected_entries.values() if e['category']=='operation' for bu in e.get('bu_ids',[])})
        facade=object.__new__(EvidenceCatalog);facade.identity=deepcopy(group['identity'])
        facade.entries={};facade.facts={};facade.units={};facade.atoms=[];facade.statuses={};facade.frontier=set()
        # A partial record hash is not permission to use its hidden fields.
        for h,entry in current.items():
            value=deepcopy(entry)
            if value['category']=='fact':
                ref=value.get('record_ref')
                if ref not in records or value.get('record')!=records[ref]:continue
                facade.facts[ref]=deepcopy(records[ref])
                if h in previous_grants:value.setdefault('supplement_query_id','prior_actual_task_query')
            if h in previous_grants and not value.get('bu_ids'):
                value['bu_ids']=bu_ids
            facade.entries[h]=value
        for bu in bu_ids:
            ops=[e for e in selected_entries.values() if e['category']=='operation' and bu in e.get('bu_ids',[])]
            roots={e['root_ref'] for e in ops}
            if len(roots)!=1:
                decisions.append({'bu_id':bu,'state':'unsupported','reason':'frozen_task_scope_has_no_unique_existing_root'});continue
            root=next(iter(roots))
            if root not in graphs:graphs[root]=_Graph(view,facts,root)
            graph=graphs[root]
            valid=[]
            for op in ops:
                meta=graph.nodes.get(op['record_ref'])
                if meta and meta.frame_ref==op['context_ref'] and meta.origin_ref==op.get('original_ref'):
                    valid.append((op,meta))
            if len(valid)!=len(ops) or not valid:
                decisions.append({'bu_id':bu,'state':'rejected','reason':'existing_operation_root_frame_or_origin_not_verified'});continue
            op,meta=min(valid,key=lambda x:(len(x[0].get('call_path',[])),x[0]['record_ref']))
            visible_records=[deepcopy(e['record']) for e in facade.entries.values() if e['category']=='fact' and bu in e['bu_ids']]
            by_ref={r['id']:r for r in visible_records}
            anchor={'root_method_ref':root,'projection_context_ref':meta.frame_ref,'callsite_ref':meta.origin_ref,
                'method_ref':meta.origin_method_ref,'match_id':'task_scope:'+fingerprint([bu,root,meta.frame_ref])[:24],
                'routes':[],'scope_role':'existing_frozen_BC_projection_only_not_a_new_SAPI_BU'}
            facade.units[bu]={'bu_id':bu,'anchor':anchor,'extraction_status':{'state':'partial'},
                'model_visible':{'records':list(by_ref.values()),'allowed_citation_refs':sorted(by_ref),
                    'operation_records':[],'relation_records':[],'control_records':[],'condition_sources':[],
                    'event_records':[],'issues':[{'state':'partial','code':'task_query_scope','reason':'Frozen current BC roles and actual query returns only'}],
                    'raw_files':[],'all_archive_support_visible':False}}
        actual_bus=sorted(facade.units)
        if not actual_bus:continue
        # The shared adapter mutates this isolated facade only after it has
        # checked concrete endpoint/frame/binding/condition support.
        admission=adapt_query_evidence(facade,view,returned_records,actual_bus,query_id=query_id)
        admission['task_bc_ids']=group['bcs'];admission['existing_scope_bu_ids']=actual_bus
        admissions.append(admission)
        for h,e in facade.entries.items():
            if h not in current or current[h]!=e:
                if e['category']=='fact' and e.get('record_ref') not in {r['id'] for r in returned_records} and h not in previous_grants:
                    # Source serialization must not expand an originally partial
                    # fact unless that exact record was actually returned.
                    continue
                result_entries[h]=deepcopy(e)
    return {'schema_version':'task-query-typed-delta.v1','query_id':query_id,'entries':result_entries,
        'admissions':admissions,'decisions':decisions,'source_identity_metadata':basis_audits,
        'required_record_refs':sorted({r for a in admissions for r in a['required_record_refs']}),
        'frozen_BCs_or_actions_modified':False,'archive_evidence_added':False,'new_static_analysis_performed':False}
