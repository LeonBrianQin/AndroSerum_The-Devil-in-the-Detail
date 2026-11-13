"""Explicit projection/chunking of BU model_visible; archive files stay closed."""
from copy import deepcopy
from collections import defaultdict, deque
import json

from androserum.facts.identity import canonical_json, fingerprint
from androserum.facts.models import Endpoint


def handle(kind, value):
    return kind + '_' + fingerprint(value)[:12]


def size(value):
    return len(canonical_json(value))


class EvidenceCatalog:
    def __init__(self, collection, bu_ids):
        self.identity = {k:collection[k] for k in ['apk_sha256','source_run_ref','source_snapshot_id','extraction_run_ref']}
        selected = {u['bu_id']:u for u in collection['units'] if u['bu_id'] in bu_ids}
        if set(bu_ids) != set(selected): raise ValueError('Selected BU absent from this package')
        self.units = selected
        self.entries, self.facts, self.atoms = {}, {}, []
        self.statuses = {key:{'bu_id':key,'status':deepcopy(u['extraction_status']),
            'issues':deepcopy(u['model_visible']['issues'])} for key,u in selected.items()}
        self.frontier = set()
        self._build()

    def add(self, entry, bu):
        h = entry['handle']
        if h in self.entries:
            old = self.entries[h]
            dynamic = {'endpoint_refs','condition_refs'} if entry['category']=='operation' else set()
            if entry['category']=='condition':dynamic={'source_collection_by_bu'}
            if {k:v for k,v in old.items() if k not in {'bu_ids',*dynamic}} != {k:v for k,v in entry.items() if k not in {'bu_ids',*dynamic}}:
                raise ValueError('Same evidence handle has different payloads')
            for key in dynamic:
                if key=='source_collection_by_bu':old[key].update(entry[key])
                else:old[key]=list(dict.fromkeys([*old[key],*entry[key]]))
            if bu not in old['bu_ids']: old['bu_ids'].append(bu); old['bu_ids'].sort()
        else:
            self.entries[h] = {**entry,'bu_ids':[bu]}
        return h

    def _build(self):
        for bu,u in self.units.items():
            visible = u['model_visible']
            if visible.get('raw_files') or visible.get('all_archive_support_visible'):
                raise ValueError('Raw archive is not a model-visible evidence source')
            records = {r['id']:r for r in visible['records']}
            if set(visible['allowed_citation_refs']) != set(records): raise ValueError('Visible citation inventory mismatch')
            for ref,r in records.items():
                if r.get('run_ref') != self.identity['source_run_ref']: raise ValueError('Cross-APK/run visible fact')
                if ref in self.facts and self.facts[ref] != r: raise ValueError('Same fact differs between BUs')
                self.facts[ref] = deepcopy(r)
                self.frontier.update(r.get('provenance',{}).get('support_refs',[]))
                shown = {k:r[k] for k in ['id','run_ref','kind','method_ref','node_kind','text','position','operation','opcode',
                    'declared_target','slots','signature','body_status','branch_ref','branch_label','value_endpoint','expected_value',
                    'binding_kind','endpoints','context_ref','condition_refs','relation_kind','source','target','resolution','unresolved_reason','provenance'] if k in r}
                if r.get('provenance',{}).get('tool_ref')=='tool:method-outputs':
                    # The boundary proof explicitly verifies this value binding;
                    # do not infer an unshown raw relation field from its name.
                    shown.update({k:r[k] for k in ['binding_refs','source_selector'] if k in r})
                self.add({'handle':handle('fact',ref),'category':'fact','record_ref':ref,'record_sha256':fingerprint(r),
                    'shown_fields':list(shown),'record':shown,'fact_refs':[ref],
                    'detail_fields_available':[k for k in r if k not in shown]},bu)
            ops = visible['operation_records']; op_by_ref = {}
            for op in ops:
                h = handle('op',[op['operation_ref'],op['context_ref'],u['anchor']['root_method_ref']])
                op_by_ref[op['operation_ref']] = h
                fact = records[op['operation_ref']]
                method = records.get(op['method_ref'],{})
                proof = [op['operation_ref'],op['origin_ref'],*op['raw_operation_refs']]
                proof = [x for x in proof if x in records]
                self.add({'handle':h,'category':'operation','record_ref':op['operation_ref'],'original_ref':op['origin_ref'],
                    'root_ref':u['anchor']['root_method_ref'],'context_ref':op['context_ref'],'method_ref':op['method_ref'],
                    'method_signature':method.get('signature'),'call_path':op['call_path'],'operation':op['operation'],
                    'text':fact.get('text'),'slots':op['slots'],'fact_refs':proof,'endpoint_refs':[],'condition_refs':[]},bu)
            root_context = u['anchor']['root_method_ref']
            method_outputs = {row['output_endpoint']['element_ref']:row for row in visible.get('method_output_records',[])}
            def owner(ref):
                if ref in op_by_ref: return op_by_ref[ref]
                r = records.get(ref,{})
                candidates = {op_by_ref[x] for x in r.get('provenance',{}).get('support_refs',[]) if x in op_by_ref}
                return next(iter(candidates)) if len(candidates) == 1 else None
            def point(value):
                p = Endpoint.model_validate(value).model_dump(mode='json')
                own = owner(p['element_ref'])
                output = method_outputs.get(p['element_ref'])
                if output:
                    own = op_by_ref.get(output['owner_projection_ref'])
                context = self.entries[own]['context_ref'] if own else None
                h = handle('ep',[self.identity['source_run_ref'],root_context,context,p])
                self.add({'handle':h,'category':'endpoint','endpoint':p,'root_ref':root_context,
                    'context_ref':context,'owner_operation_ref':own,
                    **({'boundary_role':'explicit_normal_method_result',
                        'method_result_proof_ref':handle('fact',p['element_ref']),
                        'method_return_relation_ref':handle('fact',output['relation_ref']),
                        'method_return_binding_ref':handle('fact',output['binding_ref']),
                        'method_parent_context_ref':output['parent_context_ref']} if output else {}),
                    'fact_refs':([p['element_ref'],output['relation_ref'],output['binding_ref']] if output else
                        [p['element_ref']] if p['element_ref'] in records else [])},bu)
                if output and own and h not in self.entries[own]['endpoint_refs']:
                    self.entries[own]['endpoint_refs'].append(h)
                return h
            for op in ops:
                h = op_by_ref[op['operation_ref']]
                for slot in op['slots']:
                    p = {'element_ref':op['operation_ref'],'position_label':records[op['operation_ref']]['position']['position_label'],
                         'slot_kind':slot['slot_kind'],'slot_index':slot.get('slot_index'),'slot_label':slot.get('slot_label')}
                    ep = point(p)
                    if ep not in self.entries[h]['endpoint_refs']: self.entries[h]['endpoint_refs'].append(ep)
            cond_lookup = {}
            for row in visible['control_records']:
                op_h = op_by_ref.get(row['operation_ref'])
                if not op_h: continue
                for ref in row['conditions']:
                    h = handle('cond',[ref,row['context_ref'],root_context]); cond_lookup[ref] = h
                    record = records[ref]
                    sources = [g for g in visible.get('condition_sources',[]) if g['condition_ref']==ref and g['context_ref']==row['context_ref']]
                    source_state = sources[0]['source_collection_state'] if sources else 'unknown'
                    proof = [ref,record['branch_ref']]
                    self.add({'handle':h,'category':'condition','record_ref':ref,'root_ref':root_context,
                        'context_ref':row['context_ref'],'expected_value':record['expected_value'],
                        'branch_ref':record['branch_ref'],'scope':'local_operation_only','source_collection_by_bu':{bu:source_state},
                        'constant_operands':sources[0]['constant_operands'] if sources else [],
                        'fact_refs':[x for x in proof if x in records]},bu)
                    if h not in self.entries[op_h]['condition_refs']: self.entries[op_h]['condition_refs'].append(h)
            for row in visible.get('model_conditions',[]):
                ref=row['condition_ref'];record=records[ref]
                if record.get('provenance',{}).get('kind')!='model_assisted':raise ValueError('Model precondition requires explicit model provenance')
                h=handle('cond',[ref,row['context_ref'],root_context]);cond_lookup[ref]=h
                self.add({'handle':h,'category':'condition','record_ref':ref,'root_ref':root_context,
                    'context_ref':row['context_ref'],'expected_value':record['expected_value'],'branch_ref':record['branch_ref'],
                    'scope':row['scope'],'source_collection_by_bu':{bu:'unknown_model_precondition'},'constant_operands':[],
                    'fact_refs':[ref,record['branch_ref']]},bu)
            for r in records.values():
                if 'binding_kind' in r:
                    self.add({'handle':handle('bind',r['id']),'category':'binding','record_ref':r['id'],
                        'binding_kind':r['binding_kind'],'context_ref':r.get('context_ref'),
                        'endpoints':r['endpoints'],'condition_refs':r['condition_refs'],'fact_refs':[r['id']]},bu)
                if r.get('node_kind') == 'state' and r.get('provenance',{}).get('kind') == 'model_assisted':
                    self.add({'handle':handle('effect',[r['id'],root_context]),'category':'effect','record_ref':r['id'],
                        'effect_kind':'model_assisted','root_ref':root_context,'normal_completion_required':True,'slots':r.get('slots',[]),
                        'fact_refs':[r['id']]},bu)
            for edge in visible['relation_records']:
                raw = records[edge['record_ref']]
                a,b = point(edge['traversal_source']),point(edge['traversal_target'])
                h = handle('rel',[edge['record_ref'],a,b,root_context])
                self.add({'handle':h,'category':'relation','record_ref':edge['record_ref'],'root_ref':root_context,
                    'kind':raw['relation_kind'],'source_endpoint_ref':a,'target_endpoint_ref':b,
                    'context_ref':raw.get('context_ref'),'binding_refs':[handle('bind',x) for x in raw.get('binding_refs',[])],
                    'condition_refs':[cond_lookup[x] for x in raw.get('condition_refs',[]) if x in cond_lookup],
                    'unresolved_condition_refs':[x for x in raw.get('condition_refs',[]) if x not in cond_lookup],
                    'role':edge.get('evidence_role','program_dependency'),'resolution':raw['resolution'],
                    'provenance_kind':raw['provenance']['kind'],'fine_grained_path_claimed':False,
                    'summary_limits':{k:edge['flow_summary'][k] for k in ['context_scope','path_mapping_complete','unmapped_intermediate_nodes',
                        'path_feasibility_checked','intermediate_path_expansion_performed']} if edge.get('flow_summary') else None,
                    'fact_refs':[raw['id']]},bu)
            # Field writes themselves are supported potential state effects.
            for op in ops:
                if op['operation'] in {'field_write','array_write'}:
                    h = handle('effect',[op['operation_ref'],root_context])
                    self.add({'handle':h,'category':'effect','record_ref':op['operation_ref'],
                        'effect_kind':op['operation'],'root_ref':root_context,'normal_completion_required':True,
                        'slots':op['slots'],'fact_refs':[op['operation_ref']]},bu)
            # Relation bundles precede standalone operations, so a bounded run
            # can see a useful mechanism before less relevant scalar plumbing.
            relations = [h for h,e in self.entries.items() if e['category']=='relation' and bu in e['bu_ids']]
            relations.sort(key=lambda h:(self.entries[h]['kind'] != 'information_flow', h))
            covered = set()
            for h in relations:
                e = self.entries[h]
                owners = [self.entries[e[k]].get('owner_operation_ref') for k in ['source_endpoint_ref','target_endpoint_ref']]
                owners = [x for x in owners if x]
                if not owners: continue
                covered.update(owners)
                self.atoms.append({'bu_id':bu,'handles':[h,*owners],'priority':0 if e['kind']=='information_flow' else 1})
            for h in sorted(op_by_ref.values()):
                if h not in covered: self.atoms.append({'bu_id':bu,'handles':[h],'priority':2})
        for bu in self.units:
            planned=self.closure(h for a in self.atoms if a['bu_id']==bu for h in a['handles'])
            for h,e in self.entries.items():
                if bu in e['bu_ids'] and h not in planned:
                    self.atoms.append({'bu_id':bu,'handles':[h],'priority':3})
        self.atoms.sort(key=lambda a:(a['bu_id'],a['priority']))

    def closure(self, handles):
        queue=deque(handles);seen=set()
        while queue:
            h=queue.popleft()
            if h in seen or h not in self.entries: continue
            seen.add(h);e=self.entries[h]
            for key in ['endpoint_refs','condition_refs','binding_refs']:
                queue.extend(e.get(key,[]))
            for key in ['source_endpoint_ref','target_endpoint_ref']:
                if e.get(key): queue.append(e[key])
            # Endpoint ownership is identity metadata; do not recursively pull
            # every consumer operation or all facts of the owning method.
            queue.extend(handle('fact',r) for r in e.get('fact_refs',[]))
        return sorted(seen)

    def render(self, handles, bu_ids):
        result={}
        for h in self.closure(handles):
            entry=deepcopy(self.entries[h]);entry['bu_ids']=[b for b in entry['bu_ids'] if b in bu_ids]
            if entry['category']=='condition':
                entry['source_collection_by_bu']={b:s for b,s in entry['source_collection_by_bu'].items() if b in bu_ids}
            if entry['bu_ids']: result[h]=entry
        for e in result.values():
            if e['category']=='operation':e['condition_refs']=[h for h in e['condition_refs'] if h in result]
        return result

    def chunks(self, config):
        chunks=[];pending=[];current=[];handles=[];bus=set()
        for atom in self.atoms:
            if current and atom['bu_id'] not in bus:
                chunks.append({'atom_ids':current,'handles':handles,'bu_ids':sorted(bus)})
                current=[];handles=[];bus=set()
            test_handles=list(dict.fromkeys([*handles,*atom['handles']]));test_bus=bus|{atom['bu_id']}
            data=self.render(test_handles,test_bus)
            if size(data)>config.max_chunk_chars and current:
                chunks.append({'atom_ids':current,'handles':handles,'bu_ids':sorted(bus)})
                current=[];handles=[];bus=set();data=self.render(atom['handles'],{atom['bu_id']})
            if size(data)>config.max_chunk_chars:
                pending.append({'atom':atom,'reason':'indivisible_evidence_atom_exceeds_chunk_budget'});continue
            current.append(handle('fact',atom));handles=list(dict.fromkeys([*handles,*atom['handles']]));bus.add(atom['bu_id'])
        if current: chunks.append({'atom_ids':current,'handles':handles,'bu_ids':sorted(bus)})
        grouped=defaultdict(deque)
        for c in chunks:grouped[c['bu_ids'][0]].append(c)
        chunks=[]
        while any(grouped.values()):
            for bu in self.units:
                if grouped[bu]:chunks.append(grouped[bu].popleft())
        if len(chunks)>config.max_chunks:
            pending.extend({'chunk':c,'reason':'chunk_count_budget'} for c in chunks[config.max_chunks:]);chunks=chunks[:config.max_chunks]
        return chunks,pending

    def supplement(self, record, query_id, bu_ids):
        if record.get('run_ref') != self.identity['source_run_ref']: raise ValueError('Supplement belongs to a different APK/run')
        self.facts[record['id']]=deepcopy(record)
        h=handle('fact',record['id'])
        if h in self.entries:
            old=self.entries[h]
            if old['record_sha256']!=fingerprint(record):raise ValueError('Supplement changed an existing fact')
            old.update(record=deepcopy(record),shown_fields=list(record),detail_fields_available=[],
                supplement_query_id=query_id,bu_ids=sorted(set(old['bu_ids'])|set(bu_ids)))
            return h
        for bu in bu_ids:
            self.add({'handle':h,'category':'fact','record_ref':record['id'],'record_sha256':fingerprint(record),
                'shown_fields':list(record),'record':deepcopy(record),'fact_refs':[record['id']],
                'detail_fields_available':[],'supplement_query_id':query_id},bu)
        return h
