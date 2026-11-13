"""Bounded, direction-preserving behavior units over verified fact services.

Original facts and contextual projections remain authoritative. Archive closure
is for audit; only the explicit model_visible projection is a future LLM input.
"""
from collections import Counter, defaultdict, deque
import base64
import hashlib
import json
from pathlib import Path
from typing import Literal
from uuid import uuid4

from pydantic import Field

from androserum import __version__
from androserum.facts.context_heap import TOOL as CONTEXT_TOOL, entry_for
from androserum.facts.identity import canonical_json, fingerprint, filesystem_path, sha256_file
from androserum.facts.models import Endpoint, InstructionRecord, MethodSignature, StrictModel
from androserum.facts.sapi import load_catalog, match_sapi


def _archive_storage_entry(item):
    # Explicit snapshot packaging namespace; logical entry and original SHA
    # remain in archive_support. Encoded source code is never written raw.
    prefix = 'evidence/base64-v1/'
    if item['path'].startswith('evidence/apk-entry-v1/'):
        if item['path'] != 'evidence/apk-entry-v1/' + item['sha256'] + '.json':
            raise ValueError('Invalid original-APK evidence identity')
        return 'archive/' + item['path']
    if item['path'].startswith(prefix):
        if item['path'] != prefix + item['sha256'] + '.b64':
            raise ValueError('Invalid encoded source evidence identity')
        return 'archive/base64-v1/' + item['sha256'] + '.b64'
    return 'archive/' + item['archive_entry']


class BUConfig(StrictModel):
    schema_version: Literal['bu-config.v1'] = 'bu-config.v1'
    root_signatures: list[MethodSignature] = Field(default_factory=list)
    max_units: int = Field(default=256, ge=1, le=100000)
    max_roots: int = Field(default=256, ge=1, le=100000)
    max_tasks: int = Field(default=2000, ge=1, le=100000)
    max_operations: int = Field(default=256, ge=1, le=10000)
    max_support_records: int = Field(default=5000, ge=1, le=100000)
    max_support_files: int = Field(default=5000, ge=1, le=100000)
    context_policy: Literal['existing_frame_projections_only'] = 'existing_frame_projections_only'
    source_policy: Literal['never_expand_other_consumers'] = 'never_expand_other_consumers'
    visibility_policy: Literal['explicit_records_no_raw_files'] = 'explicit_records_no_raw_files'
    condition_source_policy: Literal['existing_predicate_inputs'] = 'existing_predicate_inputs'
    information_flow_policy: Literal['unique_root_frame_summary'] = 'unique_root_frame_summary'


def _key(point):
    return canonical_json(point.model_dump(mode='json'))


class _Graph:
    """An adapter, not a new points-to or call/heap analysis."""
    def __init__(self, view, facts, root):
        self.root = root
        self.report = view.read_context_heap(root)
        self.frames, self.nodes, self.aux = {}, {}, {}
        self.incoming, self.outgoing, self.roots = defaultdict(list), defaultdict(list), defaultdict(list)
        self.raw_for_origin = defaultdict(list)
        self.mapping_refs = defaultdict(list)
        self.edges, self.flow_candidates = {}, []
        self.buffer_report = None
        self.selected_audio_rows = []
        self.method_output_rows = {}
        self.jca_effects = []
        if self.report.state != 'complete' or self.report.projection is None:
            self.adapt_information_flows(view, facts)
            return
        p = self.report.projection
        self.frames = {x.context_ref: x for x in p.frames}
        self.nodes = {x.node_ref: x for x in p.nodes}
        for edge in facts.relations:
            if edge.relation_kind == 'dex_jimple_mapping' and edge.resolution == 'resolved' and edge.target:
                self.raw_for_origin[edge.target.element_ref].append(edge.source.element_ref)
                self.mapping_refs[edge.target.element_ref].append(edge.id)
        for item in self.report.scalar.operand_nodes:
            self.aux[item.node_ref] = p.nodes[item.unit]
        for access in self.report.heap.accesses:
            if access.write_value:
                self.aux[access.write_value.element_ref] = p.nodes[access.unit]
        replaced = {_key(x.target) for x in self.report.heap.links if x.role == 'storage_read'}
        replaced.update(_key(x.endpoint) for x in self.report.heap.roots if x.kind == 'heap_read')
        for item in self.report.scalar.roots:
            if item.kind == 'heap_read' and _key(item.endpoint) in replaced:
                continue
            self.roots[_key(item.endpoint)].append(item.model_dump(mode='json'))
        for item in self.report.heap.roots:
            self.roots[_key(item.endpoint)].append(item.model_dump(mode='json'))
        storage = {entry_for(root) + f'#/heap/links/{i}': x
                   for i, x in enumerate(self.report.heap.links)}
        for edge in facts.relations:
            if edge.provenance.tool_ref != CONTEXT_TOOL or not edge.target:
                continue
            if not (edge.source_selector or '').startswith(entry_for(root) + '#'):
                continue
            binding = {'binding_refs': list(edge.binding_refs), 'object_refs': [], 'location_refs': [], 'state_refs': []}
            link = storage.get(edge.source_selector)
            if link:
                binding['object_refs'] = [link.object_ref] if link.object_ref else []
                binding['location_refs'] = [link.location_ref] if link.location_ref else []
            self.add(edge, edge.source, edge.target, binding)
        # F5/F7 models are tied to their own root allocation context. Do not
        # silently transplant these bindings into a different projected frame.
        for edge in facts.relations:
            if edge.provenance.tool_ref in {'tool:buffer-state','tool:audio-read-sites'}:
                continue  # Already projected; its own frame/objects must be retained below.
            if edge.relation_kind not in {'state_dependency', 'icc_data'} or not edge.target:
                continue
            point = self.project(edge.source, call_path=[])
            if point is None:
                continue
            binding = {'binding_refs': list(edge.binding_refs), 'object_refs': [],
                       'location_refs': [], 'state_refs': [edge.target.element_ref]}
            self.add(edge, point, edge.target, binding, modeled=True)

        if any(x.tool_id=='tool:buffer-state' for x in facts.run.tools):
            buffer=view.buffer_evidence([root]);effects={x['effect_ref']:x for x in buffer['effects']}
            self.buffer_report=buffer
            for ref,effect in effects.items():
                if effect['writer_ref'] in self.nodes:self.aux[ref]=self.nodes[effect['writer_ref']]
            for edge in facts.relations:
                if edge.provenance.tool_ref!='tool:buffer-state' or not edge.target:continue
                effect=effects.get(edge.source.element_ref) or effects.get(edge.target.element_ref)
                if not effect:continue
                self.add(edge,edge.source,edge.target,{'binding_refs':list(edge.binding_refs),
                    'object_refs':[effect['object_ref']] if effect['object_ref'] else [],'location_refs':[],
                    'state_refs':[effect['effect_ref']]},modeled=True)

            if any(t.tool_id=='tool:audio-read-sites' for t in facts.run.tools):
                selected=view.audio_read_evidence([root])
                self.selected_audio_rows=selected['reads']
                by_relation={r['relation_ref']:r for r in selected['reads'] if r['state']=='conditional_connection'}
                for edge in facts.relations:
                    if edge.id not in by_relation:continue
                    row=by_relation[edge.id]
                    self.add(edge,edge.source,edge.target,{'binding_refs':list(edge.binding_refs),
                        'object_refs':[row['writer_object_ref']],'location_refs':[],
                        'state_refs':[row['effect_ref']]},modeled=True)

        if any(t.tool_id == 'tool:method-outputs' for t in facts.run.tools):
            from androserum.facts.method_outputs import ENTRY as OUTPUT_ENTRY, TOOL as OUTPUT_TOOL
            output_report = json.loads(view.read_evidence(OUTPUT_ENTRY))
            for row in output_report['returns']:
                if row['root_ref'] != root or row['owner_projection_ref'] not in self.nodes:
                    continue
                self.method_output_rows[row['owner_projection_ref']] = row
                for ref in [row['output_endpoint']['element_ref'], row['constant_node_ref']]:
                    if ref:
                        self.aux[ref] = self.nodes[row['owner_projection_ref']]
                if row['constant_node_ref']:
                    self.roots[_key(Endpoint(**row['source_endpoint']))].append({
                        'kind':'constant','endpoint':row['source_endpoint'],
                        'details':{'value':row['value'],'basis':'explicit return literal'}})
            output_ids = {row['relation_ref'] for row in self.method_output_rows.values()}
            for edge in facts.relations:
                if edge.id in output_ids and edge.provenance.tool_ref == OUTPUT_TOOL:
                    self.add(edge, edge.source, edge.target, {'binding_refs': list(edge.binding_refs),
                        'object_refs': [], 'location_refs': [], 'state_refs': []})

        if any(t.tool_id == 'tool:jca-state' for t in facts.run.tools):
            jca = json.loads(view.read_evidence('analysis/jca-state/report.json'))
            self.jca_effects = [e for e in jca['effects'] if e['root_ref'] == root and e['owner_projection_ref'] in self.nodes]
            related = {}
            for effect in self.jca_effects:
                self.aux[effect['effect_ref']] = self.nodes[effect['owner_projection_ref']]
                for ref in effect['relation_refs']:
                    related[ref] = effect
            for edge in facts.relations:
                if edge.id in related and edge.target and edge.provenance.tool_ref == 'tool:jca-state':
                    effect = related[edge.id]
                    self.add(edge, edge.source, edge.target, {'binding_refs': list(edge.binding_refs),
                        'object_refs': [effect['object_ref']] if effect.get('object_ref') else [],
                        'location_refs': [], 'state_refs': [effect['effect_ref']]}, modeled=True)

        self.adapt_information_flows(view, facts)

    def adapt_information_flows(self, view, facts):
        records = {x.id: x for x in facts.elements}
        report, provider_failure = None, None
        if any(x.tool_id == 'tool:selected-flow' for x in facts.run.tools):
            try:
                report = json.loads(view.read_evidence('analysis/selected-flow/report.json'))
            except (OSError, ValueError, KeyError) as error:
                provider_failure = str(error)
        for edge in facts.relations:
            if edge.relation_kind != 'information_flow':
                continue
            candidate = {'record': edge, 'source': None, 'target': None, 'reason_code': None, 'summary': None,
                         'provider_failure': provider_failure}
            self.flow_candidates.append(candidate)
            source = records.get(edge.source.element_ref)
            sink = records.get(edge.target.element_ref) if edge.target else None
            owners = [getattr(getattr(x, 'position', None), 'method_ref', None) for x in (source, sink)]
            reason = None
            if not self.frames:
                reason = 'context_projection_unavailable'
            elif provider_failure:
                reason = 'flow_provider_read_failed'
            elif report is None or edge.provenance.tool_ref != 'tool:selected-flow':
                reason = 'information_flow_provider_not_supported'
            elif owners[0] != owners[1]:
                reason = 'cross_method_flow_context_not_recorded'
            elif len([f for f in self.frames.values() if f.method_ref == owners[0]]) > 1:
                reason = 'repeated_or_recursive_method_frames'
            elif owners[0] != self.root:
                reason = ('nested_frame_flow_scope_not_proven' if any(f.method_ref == owners[0] for f in self.frames.values())
                          else 'flow_endpoints_outside_analysis_root')
            elif edge.context_ref is not None or edge.binding_refs:
                reason = 'additional_flow_context_or_binding_not_adapted'
            elif not edge.target:
                reason = 'flow_sink_endpoint_unresolved'
            if reason:
                candidate['reason_code'] = reason
                continue
            a, b = self.project(edge.source, call_path=[]), self.project(edge.target, call_path=[])
            if a is None or b is None:
                candidate['reason_code'] = 'flow_endpoint_projection_unavailable'
                continue
            prefix = 'analysis/selected-flow/report.json#/mapped/'
            if not (edge.source_selector or '').startswith(prefix):
                candidate['reason_code'] = 'flow_support_selector_not_supported'
                continue
            row = report['mapped'][int(edge.source_selector[len(prefix):])]
            if row['issues'] or row['source_endpoint'] != edge.source.model_dump(mode='json') or row['sink_endpoint'] != edge.target.model_dump(mode='json'):
                candidate['reason_code'] = 'flow_endpoints_disagree_with_provider'
                continue
            summary = {'relation_ref': edge.id, 'evidence_role': 'information_flow_summary',
                'source_run_ref': facts.run.run_id, 'source_selector': edge.source_selector,
                'tool_ref': edge.provenance.tool_ref, 'rule_ref': edge.provenance.rule_ref,
                'source_endpoint': edge.source.model_dump(mode='json'), 'sink_endpoint': edge.target.model_dump(mode='json'),
                'projected_source': a.model_dump(mode='json'), 'projected_sink': b.model_dump(mode='json'),
                'context_ref': next(iter(self.frames.values())).context_ref, 'root_method_ref': self.root,
                'context_scope': 'Single root-method frame; existential provider flow, not a proven execution instance',
                'provider_configuration_ref': 'analysis/selected-flow/report.json#/configuration',
                'provider_configuration_sha256': fingerprint(report['configuration']),
                'selected_source_signature': source.declared_target.signature,
                'selected_sink_signature': sink.declared_target.signature,
                'provider_configuration': {k: report['configuration'][k] for k in ['platform_api', 'callbacks', 'implicit_flows', 'taint_wrapper']},
                'full_provider_configuration_archive_only': True, 'provider_state': report['state'],
                'path_mapping_complete': row['path_mapping_complete'],
                'unmapped_intermediate_nodes': sum(x['state'] != 'resolved' for x in row['path']),
                'fine_grained_path_claimed': False, 'path_feasibility_checked': False,
                'intermediate_path_expansion_performed': False}
            candidate.update(source=a, target=b, summary=summary)
            self.add(edge, a, b, {'binding_refs': [], 'object_refs': [], 'location_refs': [], 'state_refs': []}, summary=summary)

    def add(self, edge, source, target, binding, modeled=False, summary=None):
        item = {'record': edge, 'source': source, 'target': target, 'binding': binding, 'modeled': modeled, 'summary': summary}
        self.edges[edge.id] = item
        self.outgoing[_key(source)].append(item)
        self.incoming[_key(target)].append(item)

    def meta(self, point):
        return self.nodes.get(point.element_ref) or self.aux.get(point.element_ref)

    def describe(self, point):
        meta = self.meta(point)
        frame = self.frames[meta.frame_ref] if meta else next(iter(self.frames.values()), None)
        return {'endpoint': point.model_dump(mode='json'), 'root_method_ref': self.root,
                'context_ref': frame.context_ref if frame else None,
                'call_path': [x.model_dump(mode='json') for x in frame.call_path] if frame else [],
                'origin_ref': meta.origin_ref if meta else None, 'role': meta.role if meta else 'model_or_auxiliary'}

    def project(self, point, *, call_path):
        origins = {point.element_ref}
        origins.update(origin for origin, refs in self.raw_for_origin.items() if point.element_ref in refs)
        selected = []
        for meta in self.nodes.values():
            if meta.origin_ref not in origins or meta.role in {'exception_effect', 'exit'}:
                continue
            frame = self.frames[meta.frame_ref]
            if [x.model_dump(mode='json') for x in frame.call_path] != call_path:
                continue
            if meta.role == 'call_result' and point.slot_kind != 'result':
                continue
            if meta.role == 'call_entry' and point.slot_kind == 'result':
                continue
            if point.slot_kind == 'result' and any(x.origin_ref == meta.origin_ref and x.frame_ref == meta.frame_ref
                                                   and x.role == 'call_result' for x in self.nodes.values()):
                if meta.role != 'call_result':
                    continue
            selected.append(meta)
        if len(selected) != 1:
            return None
        meta = selected[0]
        return point.model_copy(update={'element_ref': meta.node_ref, 'position_label': f'unit:{meta.index}',
            **({'slot_index': point.slot_index + self.frames[meta.frame_ref].local_offset} if point.slot_kind == 'local' else {})})


class _Unit:
    def __init__(self, view, facts, config, match, graph, frame, extraction_run, archive_dependencies=None, query_cache=None):
        self.archive_dependencies=archive_dependencies
        self.shared_queries=query_cache
        self.view, self.facts, self.config = view, facts, config
        self.match, self.graph, self.frame = match, graph, frame
        self.records = {x.id: x for group in [facts.elements, facts.relations, facts.contexts, facts.bindings, facts.statuses] for x in group}
        root = graph.root if graph else match['method_ref']
        self.id = 'bu:' + fingerprint([extraction_run, match['match_id'], root, frame.context_ref if frame else None])[:32]
        self.queue, self.tasks, self.task_keys = deque(), {}, {}
        self.inclusions, self.selected, self.ops, self.relations = [], set(), {}, {}
        self.controls, self.events, self.ends, self.issues = [], [], [], []
        self.decorated, self.repeats, self.input_expanded = set(), [], set()
        self.queries, self.condition_sources = {}, {}
        self.task_dependencies = defaultdict(dict)
        self.archive_only_refs = set()
        self.flow_adaptations = []
        self.operation_budget_hit = False
        self.include(match['callsite_ref'], 'anchor', purpose='sensitive_call')
        for route in match['routes']:
            for ref in route['evidence_refs']:
                self.include(ref, 'sapi_match', purpose='anchor_match')

    def include(self, ref, reason, *, task=None, relation=None, purpose='support'):
        self.selected.add(ref)
        item = {'record_ref': ref, 'reason': reason, 'task_ref': task, 'via_relation_ref': relation, 'purpose': purpose}
        if item not in self.inclusions:
            self.inclusions.append(item)

    def issue(self, state, code, reason, **scope):
        item = {'state': state, 'code': code, 'reason': reason, **scope}
        if item not in self.issues:
            self.issues.append(item)

    def enqueue(self, point, direction, *, parent=None, edge=None, binding=None, purpose='data', reason='dependency'):
        scope = self.graph.describe(point) if self.graph else {'endpoint': point.model_dump(mode='json'),
            'root_method_ref': self.match['method_ref'], 'context_ref': None, 'call_path': [], 'origin_ref': None, 'role': 'unmapped'}
        binding = binding or {'binding_refs': [], 'object_refs': [], 'location_refs': [], 'state_refs': []}
        state = {**scope, 'direction': direction, 'binding': binding}
        key = canonical_json(state)
        if key in self.task_keys:
            self.repeats.append({'existing_task_ref': self.task_keys[key], 'parent_task_ref': parent,
                                 'relation_ref': edge, 'reason': 'same_endpoint_context_direction_binding',
                                 'requested_purpose': purpose, 'requested_reason': reason})
            if parent and edge:
                self.task_dependencies[parent].setdefault(self.task_keys[key], set()).add(edge)
            return self.task_keys[key]
        task_id = 'bu-task:' + fingerprint([self.id, state])[:32]
        task = {'task_id': task_id, **state, 'state': 'queued', 'parent_task_ref': parent,
                'via_relation_ref': edge, 'purpose': purpose, 'reason': reason}
        self.tasks[task_id], self.task_keys[key] = task, task_id
        if parent and edge:
            self.task_dependencies[parent].setdefault(task_id, set()).add(edge)
        self.queue.append(task_id)
        return task_id

    def collect_condition_inputs(self, cond, frame, operation_ref, parent):
        c, analysis = cond['record'], cond['analysis']
        group_key = c['id'], frame.context_ref
        if group_key in self.condition_sources:
            group = self.condition_sources[group_key]
            if operation_ref not in group['operation_refs']:
                group['operation_refs'].append(operation_ref)
            return group['id']
        group = {'id': 'bu-condition:' + fingerprint([self.id, *group_key])[:32], 'condition_ref': c['id'],
            'context_ref': frame.context_ref, 'operation_refs': [operation_ref], 'condition_recognized': True,
            'normalization': analysis['normalization'], 'inputs': [], 'constant_operands': [],
            'source_collection_state': 'pending', 'mapping_issues': [], 'source_origins': [], 'traversed_relation_refs': []}
        self.condition_sources[group_key] = group
        path = [x.model_dump(mode='json') for x in frame.call_path]
        target = Endpoint(**c['value_endpoint'])
        inputs = [(target, None)] if analysis['normalization'] == 'boolean_local' else [
            (edge.source, edge.id) for edge in self.facts.relations
            if edge.provenance.tool_ref == 'tool:control' and edge.relation_kind == 'data_dependency'
            and edge.target and _key(edge.target) == _key(target)]
        def constants(value):
            if value.get('constant_kind') is not None:
                literal = {k: value.get(k) for k in ['kind', 'type_descriptor', 'constant_kind', 'constant']}
                literal['support_refs'] = [c['id'], c['branch_ref']]
                if literal not in group['constant_operands']:
                    group['constant_operands'].append(literal)
            for child in value.get('children', []):
                constants(child)
        constants(analysis['expression'])
        for point, relation in inputs:
            mapped = self.graph.project(point, call_path=path)
            item = {'original_endpoint': point.model_dump(mode='json'), 'predicate_input_relation_ref': relation,
                    'projected_endpoint': mapped.model_dump(mode='json') if mapped else None, 'task_ref': None}
            group['inputs'].append(item)
            if relation:
                self.include(relation, 'predicate_input', task=parent, relation=relation, purpose='condition_source')
            if mapped:
                item['task_ref'] = self.enqueue(mapped, 'source', parent=parent, purpose='condition_source', reason='condition_value')
            else:
                group['mapping_issues'].append('Condition input endpoint cannot be mapped in the selected frame')
        if not inputs and not group['constant_operands']:
            group['mapping_issues'].append('F6 predicate input evidence is absent')
        if group['mapping_issues']:
            self.issue('unavailable', 'condition_input_adaptation', '; '.join(group['mapping_issues']),
                       condition_ref=c['id'], cause='BU_adapter', context_ref=frame.context_ref)
        return group['id']

    def finalize_condition_sources(self):
        for group in self.condition_sources.values():
            seen, relations = set(), set()
            for item in group['inputs']:
                queue = deque([item['task_ref']] if item['task_ref'] else []); reached = set()
                while queue:
                    task = queue.popleft()
                    if task in reached:
                        continue
                    reached.add(task)
                    relations.update(ref for refs in self.task_dependencies[task].values() for ref in refs)
                    queue.extend(self.task_dependencies[task])
                source_roots = [x for x in self.ends if x['task_ref'] in reached and x['reason'] == 'recorded_source']
                unresolved = any(x['source']['kind'] in {'undefined_local', 'unsupported_expression', 'incomplete_operand', 'heap_read', 'opaque_result'} for x in source_roots)
                missing = {x['task_ref'] for x in self.ends if x['task_ref'] in reached and x['reason'] == 'no_recorded_predecessor'} - {x['task_ref'] for x in source_roots}
                item['source_collection_state'] = ('unavailable' if not item['task_ref'] else
                    'truncated' if any(self.tasks[t]['state'] != 'processed' for t in reached) else
                    'partial' if unresolved or missing else 'collected' if source_roots else 'unknown')
                item['source_origin_task_refs'] = sorted({x['task_ref'] for x in source_roots})
                seen.update(reached)
            roots = [x for x in self.ends if x['task_ref'] in seen and x['reason'] == 'recorded_source']
            group['source_origins'] = roots
            group['traversed_relation_refs'] = sorted(relations)
            group['source_task_refs'] = sorted(seen)
            input_states = {x['source_collection_state'] for x in group['inputs']}
            group['source_collection_state'] = ('truncated' if 'truncated' in input_states else
                'partial' if group['mapping_issues'] or input_states - {'collected'} else
                'collected' if roots or group['constant_operands'] else 'unknown')
            group['concrete_predicate_value_proven'] = False
        states = {g['id']: g['source_collection_state'] for g in self.condition_sources.values()}
        for row in self.controls:
            row['condition_recognition'] = 'identified' if row['conditions'] else 'none_recorded'
            row['source_collection_states'] = {ref: states[ref] for ref in row['source_collection_refs']}

    def finalize_flow_adaptations(self):
        selected_raw = {self.match['callsite_ref']}
        selected_raw.update(r for op in self.ops.values() for r in op['raw_operation_refs'])
        candidates = self.graph.flow_candidates if self.graph else [
            {'record': e, 'source': None, 'target': None, 'reason_code': 'context_projection_unavailable', 'summary': None}
            for e in self.facts.relations if e.relation_kind == 'information_flow']
        for candidate in candidates:
            edge = candidate['record']
            related = edge.source.element_ref in selected_raw or edge.target and edge.target.element_ref in selected_raw
            admitted = edge.id in self.relations and self.relations[edge.id].get('evidence_role') == 'information_flow_summary'
            reason = candidate['reason_code']
            if admitted:
                state, reason = 'included_summary', None
            elif not related:
                state, reason = 'not_applicable', 'neither_endpoint_selected_in_this_BU'
            else:
                state = 'not_adapted'
                if reason is None:
                    source_key = _key(candidate['source'])
                    backward = any(_key(Endpoint(**t['endpoint'])) == source_key and t['direction'] == 'source' for t in self.tasks.values())
                    reason = 'source_reached_only_backwards_no_consumer_expansion' if backward else 'no_permitted_endpoint_task_reached'
                self.archive_only_refs.add(edge.id)
                if reason == 'source_reached_only_backwards_no_consumer_expansion':
                    state = 'excluded_by_direction'
                else:
                    self.issue('failed' if candidate.get('provider_failure') else 'unavailable',
                               'information_flow_not_adapted', reason, relation_ref=edge.id,
                               cause='BU_adapter_io' if candidate.get('provider_failure') else 'BU_adapter_scope', archive_only=True)
            transition_refs = {t['task_id'] for t in self.tasks.values() if t['via_relation_ref'] == edge.id}
            transition_refs.update(child for mapping in self.task_dependencies.values() for child, refs in mapping.items() if edge.id in refs)
            self.flow_adaptations.append({'relation_ref': edge.id, 'state': state, 'reason_code': reason,
                'evidence_role': 'information_flow_summary', 'model_visible': admitted,
                'archive_selected': bool(admitted or related), 'fine_grained_path_claimed': False,
                'directional_task_refs': sorted(transition_refs),
                'decision_basis': 'BU_boundary_policy' if state == 'excluded_by_direction' else 'BU_adapter_scope',
                'transition_queue_states': dict(Counter(self.tasks[t]['state'] for t in transition_refs)),
                'budget_limited': any(self.tasks[t]['state'] != 'processed' for t in transition_refs)})

    def _query(self, kind, ref):
        key = kind, ref
        if key not in self.queries:
            try:
                if self.shared_queries is not None and key in self.shared_queries:
                    self.queries[key]=json.loads(self.shared_queries[key])
                elif kind=='control':
                    from androserum.facts.control import control_evidence
                    self.queries[key]=control_evidence(self.facts,self.view.read_evidence,[ref])['operations'][0]
                elif kind=='event':
                    from androserum.facts.events import event_evidence
                    self.queries[key]=event_evidence(self.facts,self.view.read_evidence,[ref])['operations'][0]
                else:raise ValueError('Unsupported BU evidence query kind')
                if self.shared_queries is not None and key not in self.shared_queries:
                    self.shared_queries[key]=json.dumps(self.queries[key],ensure_ascii=False,allow_nan=False)
            except (ValueError, KeyError, OSError) as error:
                self.queries[key] = None
                self.issue('failed' if isinstance(error, OSError) else 'unavailable', kind + '_query', str(error), operation_ref=ref)
        return self.queries[key]

    def add_operation(self, meta, *, task=None, direction='source', purpose='data'):
        if not meta or not meta.origin_ref:
            return
        key = meta.node_ref
        if direction == 'use' and key not in self.input_expanded:
            self.input_expanded.add(key)
            for slot in getattr(self.records[key], 'slots', []):
                if slot.slot_kind in {'receiver', 'argument'}:
                    self.enqueue(Endpoint(element_ref=key, position_label=f'unit:{meta.index}', slot_kind=slot.slot_kind,
                        slot_index=slot.slot_index, slot_label=slot.slot_label), 'source', parent=task,
                        reason='input_of_relevant_use', purpose='input_context')
        if key in self.ops:
            self.include(key, 'operation_revisited', task=task, purpose=purpose)
            return
        if len(self.ops) >= self.config.max_operations:
            self.operation_budget_hit = True
            self.issue('truncated', 'operation_budget', 'Operation budget reached; branch not expanded', projected_ref=key)
            return
        frame = self.graph.frames[meta.frame_ref]
        raws = self.graph.raw_for_origin.get(meta.origin_ref, [])
        unit = self.graph.report.projection.method.units[meta.index]
        self.ops[key] = {'operation_ref': key, 'origin_ref': meta.origin_ref, 'raw_operation_refs': raws,
            'method_ref': meta.origin_method_ref, 'context_ref': meta.frame_ref, 'call_path': [x.model_dump(mode='json') for x in frame.call_path],
            'projection_role': meta.role, 'operation': unit.operation,
            'slots': [x.model_dump(mode='json') for x in getattr(self.records[key], 'slots', [])],
            'value_resolution': 'selected_source_roots_and_paths; no transfer of unrelated F5 root candidates'}
        self.include(key, 'traced_operation', task=task, purpose=purpose)
        self.include(meta.origin_ref, 'original_program_position', task=task, purpose='position')
        for ref in [*raws, *meta.support_refs, *self.graph.mapping_refs[meta.origin_ref]]:
            self.include(ref, 'operation_mapping_or_call_binding', task=task, purpose='position_or_binding')
        # An explicit return has a separately verified frame-local outward
        # result, not an arbitrary alias for all internal action values.
        output = self.graph.method_output_rows.get(key)
        if output:
            item = self.graph.edges[output['relation_ref']]
            edge = item['record']
            for ref in [output['output_endpoint']['element_ref'], output['source_endpoint']['element_ref'],
                        output['relation_ref'], output['binding_ref'], *output['condition_refs']]:
                self.include(ref, 'explicit_normal_method_result', task=task, relation=edge.id, purpose='method_boundary')
            self.relations[edge.id] = {'record_ref': edge.id,
                'traversal_source': edge.source.model_dump(mode='json'), 'traversal_target': edge.target.model_dump(mode='json'),
                'modeled': False, 'binding': item['binding'], 'root_method_ref': self.graph.root,
                'evidence_role': 'explicit_normal_method_result'}
        # Forward-discovered operations need their input evidence; these new
        # source tasks never turn around to the source's other consumers.
        if (meta.origin_ref, meta.frame_ref) in self.decorated:
            return
        self.decorated.add((meta.origin_ref, meta.frame_ref))
        refs = raws or [meta.origin_ref]
        for ref in refs:
            row = self._query('control', ref)
            if row:
                self.controls.append({'operation_ref': key, 'original_operation_ref': ref, 'context_ref': meta.frame_ref,
                    'conditions': [x['record']['id'] for x in row['conditions']], 'state': row['state'],
                    'source_collection_refs': [],
                    'scope': 'method_normal_completion', 'combined_path_checked': False})
                control_row = self.controls[-1]
                if row['state'] not in {'complete', 'partial'}:
                    self.issue(row['state'], 'control_scope', 'Control evidence incomplete', operation_ref=ref)
                for edge_ref in row['relation_refs']:
                    self.include(edge_ref, 'local_control', task=task, purpose='control')
                for cond in row['conditions']:
                    c = cond['record']; self.include(c['id'], 'local_condition', task=task, purpose='condition')
                    control_row['source_collection_refs'].append(self.collect_condition_inputs(cond, frame, key, task))
            event = self._query('event', ref)
            if event:
                # Possible backgrounds are not extra execution contexts. A
                # selected call path is not inferred from this model row.
                background = []
                context_calls = [x.callsite_ref for x in frame.call_path]
                for bg in event['background']:
                    recorded_calls = [self.records[e].callsite_ref or self.records[e].source.element_ref
                                      for e in bg['call_background']['call_path_refs']]
                    if context_calls and recorded_calls[-len(context_calls):] != context_calls:
                        self.issue('unavailable', 'event_context_scope', 'Method-level event candidate has no matching concrete call suffix for this frame', operation_ref=ref)
                        continue
                    background.append(bg)
                self.events.append({'operation_ref': key, 'original_operation_ref': ref, 'context_ref': meta.frame_ref,
                    'background': background, 'icc': event['icc'] if not frame.call_path else [], 'execution_asserted': False})
                if not frame.call_path:
                    for edge in self.facts.relations:
                        if edge.relation_kind == 'icc_target' and edge.source.element_ref == ref:
                            self.include(edge.id, 'related_icc_target', task=task, purpose='event_target_only')
                for bg in background:
                    root = bg['root']
                    for record_ref in [root['event_ref'], root['source_ref'], root['target_method_ref'], *bg['call_background']['call_path_refs']]:
                        self.include(record_ref, 'possible_event_background', task=task, purpose='event')
                    # Only bound registration values, not every operation at
                    # the event entry, get source tasks in an available frame.
                    point = (self.graph.project(Endpoint(**root['source_endpoint']), call_path=[])
                             if root['source_endpoint'] else None)
                    if point:
                        self.enqueue(point, 'source', parent=task, purpose='event_source', reason='registered_event_value')
                    elif root['source_endpoint']:
                        self.issue('unavailable', 'event_binding_scope', 'Event registration binding is outside this projection; retained as background only', event_ref=root['event_ref'])
                if frame.call_path and event['icc']:
                    self.issue('unavailable', 'model_binding_scope', 'Own-root ICC object models are not transplanted into this nested frame', operation_ref=ref)

    def run(self):
        g = self.graph
        if g is None or g.report.state != 'complete' or not self.frame:
            self.issue(g.report.state if g and g.report.state != 'complete' else 'unavailable', 'context_unavailable',
                (g.report.reason or 'No unique anchor mapping/context in this projection') if g else 'No resolved mapping/context projection for anchor')
            return self.finish()
        for item in g.report.projection.issues:
            if 'Depth budget' in item['reason']:
                self.issue('truncated', 'context_scope_truncated', item['reason'], scope='upstream_root_projection',
                           note='Root-scope coverage limit; not a newly traversed BU branch')
        path = [x.model_dump(mode='json') for x in self.frame.call_path]
        for index, call in enumerate(self.frame.call_path):
            record = self.records.get(call.callsite_ref)
            if isinstance(record, InstructionRecord):
                point = g.project(Endpoint(element_ref=record.id, position_label=record.position.position_label,
                    slot_kind='element'), call_path=path[:index])
                if point:
                    self.add_operation(g.meta(point), purpose='bound_invocation_context')
                else:
                    self.issue('unavailable', 'call_context_mapping', 'Bound caller location not uniquely mapped in this projection', callsite_ref=call.callsite_ref)
        for name, direction in [('receiver', 'source'), ('arguments', 'source'), ('result', 'use')]:
            for raw in self.match[name]:
                point = g.project(Endpoint(**raw), call_path=path)
                if point:
                    self.enqueue(point, direction, reason='anchor_' + name, purpose='anchor_input' if direction == 'source' else 'anchor_result')
                    # A recorded finalization can explain this anchor's result.
                    # Reverse only this exact result endpoint; a source trace
                    # through shared state must never expand other consumers.
                    if name == 'result':
                        for item in g.incoming[_key(point)]:
                            edge = item['record']
                            if (item['modeled'] and edge.relation_kind == 'state_dependency'
                                    and edge.provenance.tool_ref == 'tool:jca-state'):
                                self.enqueue(point, 'source', binding=item['binding'],
                                    reason='anchor_result_recorded_state', purpose='anchor_result')
                else:
                    self.issue('unavailable', 'anchor_endpoint_mapping', 'No unique contextual endpoint', endpoint=raw)
        anchor_meta = next((m for m in g.nodes.values() if m.frame_ref == self.frame.context_ref
            and self.match['callsite_ref'] in g.raw_for_origin.get(m.origin_ref, []) and m.role not in {'exception_effect', 'exit', 'call_result'}), None)
        if anchor_meta:
            self.add_operation(anchor_meta, purpose='anchor')
            if g.buffer_report:
                for effect in g.buffer_report['effects']:
                    if effect['writer_ref']!=anchor_meta.node_ref:continue
                    supplemental=[r for r in g.selected_audio_rows if r.get('effect_ref')==effect['effect_ref']]
                    resolved_sites={r['read_ref'] for r in supplemental if r['state']=='conditional_connection'}
                    self.issue('unknown','buffer_model_scope',
                        'Conditional framework API model; success, dispatch and runtime state not established',
                        effect_ref=effect['effect_ref'],rule_ref=effect['rule_ref'],model_issues=effect['issues'],
                        known_invalid_request=effect['known_invalid_request'],actual_interval=effect['actual_interval'],
                        **({'selected_site_supplement':{'conditional_sites':sorted(resolved_sites),'legacy_issues_remain_v1_scope_only':True}} if supplemental else {}))
                    for decision in g.buffer_report['read_decisions']:
                        if decision['effect_ref']==effect['effect_ref'] and decision['state']!='included_conditional':
                            if decision['read_ref'] in resolved_sites:continue
                            self.issue('unknown','buffer_state_not_connected',decision['reason'],
                                candidate_read_ref=decision['read_ref'],decision_state=decision['state'],
                                effect_ref=effect['effect_ref'],excluded_operation_is_not_citation_authorized=True)
                    for row in supplemental:
                        self.issue('unknown','selected_audio_element_precondition' if row['state']=='conditional_connection' else 'selected_audio_read_unresolved',
                            row['reason'],selected_read_ref=row.get('read_ref'),reader_offset_code_units=row['reader_offset_code_units'],
                            outcome=row['state'],all_iterations_written_claimed=False)
            for slot in getattr(self.records[anchor_meta.node_ref], 'slots', []):
                if slot.slot_kind == 'state':
                    self.enqueue(Endpoint(element_ref=anchor_meta.node_ref, position_label=f'unit:{anchor_meta.index}',
                        slot_kind='state', slot_label=slot.slot_label), 'source', reason='anchor_input_state', purpose='anchor_input')
            for item in g.edges.values():
                if item['modeled'] and item['record'].relation_kind == 'state_dependency' and item['source'].element_ref == anchor_meta.node_ref:
                    self.include(item['record'].id, 'anchor_state_effect', relation=item['record'].id, purpose='state')
                    self.relations[item['record'].id] = {'record_ref': item['record'].id,
                        'traversal_source': item['source'].model_dump(mode='json'), 'traversal_target': item['target'].model_dump(mode='json'),
                        'modeled': True, 'binding': item['binding'], 'root_method_ref': g.root}
                    self.enqueue(item['target'], 'use', edge=item['record'].id, binding=item['binding'], reason='anchor_modeled_effect', purpose='state')
        else:
            self.issue('unavailable', 'anchor_mapping', 'Anchor mapping did not select a unique operation')
        visits = 0
        while self.queue and visits < self.config.max_tasks:
            task_id = self.queue.popleft(); task = self.tasks[task_id]
            task['state'] = 'processed'; visits += 1
            point = Endpoint(**task['endpoint']); direction = task['direction']; meta = g.meta(point)
            self.include(point.element_ref, 'trace_endpoint', task=task_id, purpose=task['purpose'])
            self.add_operation(meta, task=task_id, direction=direction, purpose=task['purpose'])
            if self.operation_budget_hit:
                task['state'] = 'stopped_operation_budget'
                continue
            if meta:
                for issue in g.report.projection.issues:
                    if issue.get('unit_ref') == meta.origin_ref and issue.get('context_ref') == meta.frame_ref:
                        self.issue('truncated' if 'Depth budget' in issue['reason'] else 'unknown', 'opaque_call', issue['reason'], task_ref=task_id)
            links = g.incoming[_key(point)] if direction == 'source' else g.outgoing[_key(point)]
            if direction == 'source':
                for root in g.roots[_key(point)]:
                    self.ends.append({'task_ref': task_id, 'reason': 'recorded_source', 'source': root, 'scope': g.describe(point)})
                    if root['kind'] in {'undefined_local', 'unsupported_expression', 'incomplete_operand', 'opaque_result', 'heap_read', 'call_result'}:
                        self.issue('unknown', 'unresolved_value', 'Source identity retained; value/propagation unresolved', task_ref=task_id, source_kind=root['kind'])
            if not links:
                self.ends.append({'task_ref': task_id, 'reason': 'no_recorded_predecessor' if direction == 'source' else 'no_recorded_consumer'})
            for item in links:
                edge = item['record']; dest = item['source'] if direction == 'source' else item['target']
                self.include(edge.id, 'traversed_relation', task=task_id, relation=edge.id, purpose=task['purpose'])
                self.relations[edge.id] = {'record_ref': edge.id, 'traversal_source': item['source'].model_dump(mode='json'),
                    'traversal_target': item['target'].model_dump(mode='json'), 'modeled': item['modeled'],
                    'binding': item['binding'], 'root_method_ref': g.root,
                    'evidence_role': 'information_flow_summary' if item['summary'] else 'program_dependency',
                    'fine_grained_path_claimed': False if item['summary'] else None}
                if item['summary']:
                    self.relations[edge.id]['flow_summary'] = item['summary']
                for ref in [edge.source.element_ref, edge.target.element_ref, *edge.binding_refs, *edge.condition_refs]:
                    self.include(ref, 'relation_endpoint_or_binding', task=task_id, relation=edge.id, purpose='relation_support')
                if edge.resolution != 'resolved':
                    self.issue('unknown', 'partial_relation', edge.unresolved_reason, relation_ref=edge.id)
                if item['modeled']:
                    for ref in edge.provenance.support_refs:
                        self.include(ref, 'finite_model_support', task=task_id, relation=edge.id, purpose='state_or_icc')
                        record = self.records.get(ref)
                        if isinstance(record, InstructionRecord):
                            projected = g.project(Endpoint(element_ref=ref, position_label=record.position.position_label, slot_kind='element'), call_path=[])
                            if projected:
                                self.add_operation(g.meta(projected), task=task_id, direction=direction, purpose='modeled_use')
                binding = item['binding'] if any(item['binding'].values()) else task['binding']
                self.enqueue(dest, direction, parent=task_id, edge=edge.id, binding=binding, purpose=task['purpose'])
        if self.queue:
            self.issue('truncated', 'task_budget', 'Task budget reached; queued tasks preserved')
        return self.finish()

    def finish(self):
        self.finalize_condition_sources()
        self.finalize_flow_adaptations()
        # Explicit structural endpoints are visible, but arbitrary provenance
        # closure and all raw analysis files belong to the archive only.
        pending = deque(sorted(self.selected)); expanded = set()
        structural = {'method_ref', 'class_ref', 'dex_ref', 'parent_ref', 'context_ref', 'branch_ref', 'model_ref', 'tool_ref', 'rule_ref',
                      'element_ref', 'source_ref', 'target_ref', 'binding_refs', 'condition_refs', 'callsite_refs'}
        def references(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in structural:
                        for ref in item if isinstance(item, list) else [item]:
                            if isinstance(ref, str) and ref in self.records:
                                yield ref
                    if key != 'provenance':
                        yield from references(item)
            elif isinstance(value, list):
                for item in value:
                    yield from references(item)
        while pending:
            ref = pending.popleft()
            if ref in expanded or ref not in self.records:
                continue
            expanded.add(ref)
            for dep in references(self.records[ref].model_dump(mode='json')):
                if dep not in self.selected:
                    self.include(dep, 'structural_record', purpose='identity_or_endpoint'); pending.append(dep)
        visible_records = [self.records[x].model_dump(mode='json') for x in sorted(self.selected) if x in self.records]
        # Conditions/registration metadata are selected records, not traversable
        # invitations to every operation sharing that method or source.
        try:
            archival = collect_archive(self.view, sorted(self.selected | self.archive_only_refs), self.config,
                dependency_cache=self.archive_dependencies)
        except (OSError, ValueError, KeyError) as error:
            archival = {'records': [], 'files': [], 'analysis_files': [], 'missing_refs': sorted(self.selected),
                'missing_files': [], 'pending_refs': [], 'pending_files': [], 'truncated': False,
                'file_closure_complete': False, 'failure': str(error), 'visibility': 'Audit only'}
        if archival['missing_refs'] or archival['missing_files']:
            self.issue('failed', 'archive_missing', 'Selected archive support cannot be resolved')
        if archival['truncated']:
            self.issue('truncated', 'archive_budget', 'Archive support budget reached; pending references preserved')
        states = {x['state'] for x in self.issues}
        state = ('failed' if 'failed' in states else 'truncated' if 'truncated' in states else
                 'unavailable' if 'unavailable' in states and not self.ops else 'partial' if states else 'complete')
        visible_events = []
        for row in self.events:
            bg = [{'event_ref': x['root']['event_ref'], 'kind': x['root']['kind'], 'source_ref': x['root']['source_ref'],
                   'target_method_ref': x['root']['target_method_ref'], 'rule': x['root']['rule'],
                   'call_path_refs': x['call_background']['call_path_refs'], 'possible_only': True} for x in row['background']]
            icc = [{'callsite_ref': x['callsite_ref'], 'targets': [t['component_ref'] for t in x['targets']],
                    'payload_state': x['payload_state'],
                    'selected_payload_effect_refs': [p['effect_ref'] for p in x['payloads'] if p['effect_ref'] in self.selected],
                    'other_payloads_not_selected': any(p['effect_ref'] not in self.selected for p in x['payloads'])} for x in row['icc']]
            visible_events.append({'operation_ref': row['operation_ref'], 'context_ref': row['context_ref'],
                                   'background': bg, 'icc': icc, 'execution_asserted': False})
        return {'schema_version': 'behavior-unit.v1', 'bu_id': self.id, 'source_run_ref': self.facts.run.run_id,
            'source_snapshot_id': self.view.snapshot_id, 'extraction_config': self.config.model_dump(mode='json'),
            'anchor': {**self.match, 'root_method_ref': self.graph.root if self.graph else self.match['method_ref'],
                       'projection_context_ref': self.frame.context_ref if self.frame else None,
                       'call_path': [x.model_dump(mode='json') for x in self.frame.call_path] if self.frame else [],
                       'execution_context_asserted': False},
            'operation_records': list(self.ops.values()), 'relation_records': list(self.relations.values()),
            'control_records': self.controls, 'condition_sources': list(self.condition_sources.values()),
            'information_flow_adaptations': self.flow_adaptations,
            'event_records': self.events, 'inclusion_refs': self.inclusions,
            'tasks': list(self.tasks.values()), 'deduplicated_tasks': self.repeats, 'stops': self.ends,
            'extraction_status': {'state': state, 'queue_drained': not self.queue,
                'pending_task_refs': list(self.queue), 'task_count': len(self.tasks),
                'processed_count': sum(x['state'] == 'processed' for x in self.tasks.values()),
                'coverage': dict(self.view.manifest.coverage), 'complete_behavior_claimed': False},
            'issue_refs': self.issues,
            'model_visible': {'schema_version': 'bu-visible-evidence.v1', 'allowed_citation_refs': sorted(x for x in self.selected if x in self.records),
                'records': visible_records, 'raw_files': [], 'all_archive_support_visible': False,
                'operation_records': list(self.ops.values()), 'relation_records': list(self.relations.values()),
                'control_records': self.controls, 'condition_sources': list(self.condition_sources.values()),
                **({'method_output_records': [row for row in self.graph.method_output_rows.values()
                    if row['owner_projection_ref'] in self.ops and row['output_endpoint']['element_ref'] in self.selected]}
                   if self.graph and any(t.tool_id=='tool:method-outputs' for t in self.facts.run.tools) else {}),
                **({'model_conditions':[{'condition_ref':r['id'],'context_ref':self.graph.nodes[r['branch_ref']].frame_ref,
                    'scope':'model_relation_precondition_not_execution_guard'} for r in visible_records
                    if r.get('kind')=='condition' and r.get('provenance',{}).get('tool_ref') in {'tool:buffer-state','tool:audio-read-sites','tool:jca-state'}]}
                   if any(r.get('provenance',{}).get('tool_ref') in {'tool:buffer-state','tool:audio-read-sites','tool:jca-state'} for r in visible_records) else {}),
                'information_flow_evidence': [x['flow_summary'] for x in self.relations.values() if x.get('flow_summary')],
                'event_records': visible_events, 'source_stops': self.ends, 'issues': self.issues,
                'path_semantics': {'information_flow_is_summary': True, 'summary_is_not_a_fine_grained_path': True,
                                   'single_execution_path_claimed': False},
                'program_text_is_data': True, 'scope': 'Explicitly selected records only; LLM chunk assembly not implemented'},
            'archive_support': archival}


def collect_archive(view, refs, config, *, dependency_cache=None):
    support = view.collect_support(refs, limit=config.max_support_records).to_dict()
    manifest = {x.archive_entry: x for x in view.manifest.files}
    queue = deque(x['archive_entry'] for x in support['files'])
    seen, missing = set(), []
    keys = {'artifact_path', 'ir_entry', 'cfg_entry', 'input_flow_entry', 'raw_entry', 'source_selector', 'location'}
    def scan(value, target=None):
        target=queue if target is None else target
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'input_flow_sha256' and isinstance(item, dict):
                    target.extend(item)
                if key in keys and isinstance(item, str):
                    path = item.split('#', 1)[0]
                    if path.startswith('analysis/'):
                        target.append(path)
                scan(item,target)
        elif isinstance(value, list):
            for item in value:
                scan(item,target)
    for record in support['records']:
        scan(record)
    while queue and len(seen) < config.max_support_files:
        path = queue.popleft()
        if path in seen:
            continue
        seen.add(path)
        if path not in manifest:
            missing.append(path); continue
        try:
            raw = view.read_evidence(path)
            if path.endswith('.json'):
                # Bytes are still checked on EVERY read. Only the dependency
                # scan is shared, keyed by the actual immutable content hash.
                key=(path,hashlib.sha256(raw).hexdigest())
                if dependency_cache is not None and key in dependency_cache:
                    queue.extend(dependency_cache[key])
                else:
                    dependencies=[];scan(json.loads(raw),dependencies);queue.extend(dependencies)
                    if dependency_cache is not None:dependency_cache[key]=tuple(dependencies)
        except (OSError, ValueError, KeyError) as error:
            missing.append(path + ': ' + str(error))
    support['analysis_files'] = [manifest[x].model_dump(mode='json') for x in sorted(seen) if x in manifest]
    support['missing_files'], support['pending_files'] = missing, sorted(set(queue) - seen)
    support['truncated'] = support['truncated'] or bool(support['pending_files'])
    support['file_closure_complete'] = not missing and not support['pending_files']
    support['visibility'] = 'Audit only; never automatically appended to model input'
    return support


def anchor_context_table(units, facts):
    """Counts are a decomposition of analysis contexts, never behavior counts."""
    records = {x.id: x for x in facts.elements}
    result = []
    for unit in units:
        anchor = unit['anchor']; call = records[anchor['callsite_ref']]; path = anchor['call_path']
        methods = [anchor['root_method_ref'], *[x['callee_ref'] for x in path]]
        layer = max(0, methods.count(anchor['method_ref']) - 1)
        result.append({'bu_id': unit['bu_id'], 'physical_anchor_ref': call.id,
            'dex_ref': call.position.dex_ref, 'method_signature': records[anchor['method_ref']].signature,
            'offset_bytes': call.position.offset_bytes, 'sapi_match_id': anchor['match_id'],
            'sapi_context_ref': anchor['context_ref'], 'root_method_ref': anchor['root_method_ref'],
            'root_signature': records[anchor['root_method_ref']].signature,
            'projection_context_ref': anchor['projection_context_ref'], 'call_path': path,
            'call_path_signatures': [records[x['callee_ref']].signature for x in path],
            'call_path_positions': [{'callsite_ref': x['callsite_ref'],
                'position': records[x['callsite_ref']].position.model_dump(mode='json'),
                'caller_signature': records[records[x['callsite_ref']].position.method_ref].signature,
                'callee_signature': records[x['callee_ref']].signature} for x in path],
            'call_depth': len(path), 'recursion_expansion_level': layer,
            'context_kind': 'recursive_expansion' if layer else 'outer_call_path' if path else 'method_boundary',
            'state': unit['extraction_status']['state'], 'is_independent_behavior': False})
    return result


def build_units(view, catalog_path, config=None, *, extraction_run=None):
    with view.checked_evidence_reads():
        return _build_units(view,catalog_path,config,extraction_run=extraction_run)


def _build_units(view, catalog_path, config=None, *, extraction_run=None):
    """Run over a verified immutable snapshot; new BU run identity each time."""
    config = BUConfig.model_validate((config or BUConfig()).model_dump())
    catalog = load_catalog(catalog_path)
    multisource = catalog.get('schema_version') == 'sapi-multisource-catalog.v1'
    source_gaps = ({'source_status':catalog['source_status'], 'unimported_records':catalog['issues']}
                   if multisource else catalog['pending_sources'])
    if not view.verify()['valid']:
        raise ValueError('BU requires a valid fact snapshot')
    facts = view.export_bundle(); extraction_run = extraction_run or 'bu-run:' + uuid4().hex
    matches = match_sapi(facts, catalog)
    methods = {x.id: x for x in facts.elements if x.kind == 'method' and x.is_definition}
    selected_roots = {x for x, m in methods.items() if not config.root_signatures or m.signature in config.root_signatures}
    missing = set(config.root_signatures) - {methods[x].signature for x in selected_roots}
    if missing:
        raise ValueError('Requested BU root signatures are absent')
    graph_cache, graph_failures = {}, {}
    pending_roots = sorted(selected_roots)[config.max_roots:]
    for root in sorted(selected_roots)[:config.max_roots]:
        try:
            graph_cache[root] = _Graph(view, facts, root)
        except (KeyError, ValueError, OSError) as error:
            graph_failures[root] = {'state': 'failed' if isinstance(error, OSError) else 'unavailable', 'reason': str(error)}
    selections = []
    for match in matches['matches']:
        occurrences = []
        for root, graph in graph_cache.items():
            for frame in graph.frames.values():
                if frame.method_ref != match['method_ref']:
                    continue
                origins = {n.origin_ref for n in graph.nodes.values() if n.frame_ref == frame.context_ref
                    and match['callsite_ref'] in graph.raw_for_origin.get(n.origin_ref, [])
                    and n.role not in {'exception_effect', 'exit', 'call_result'}}
                if len(origins) == 1:
                    occurrences.append((match, graph, frame))
        if occurrences:
            selections.extend(occurrences)
        elif not config.root_signatures or match['method_ref'] in selected_roots:
            selections.append((match, graph_cache.get(match['method_ref']), None))
    units = [];archive_dependencies={};query_cache={}
    for match, graph, frame in selections[:config.max_units]:
        unit = _Unit(view, facts, config, match, graph, frame, extraction_run,archive_dependencies,query_cache)
        failure = graph_failures.get(graph.root if graph else match['method_ref'])
        if failure:
            unit.issue(failure['state'], 'context_query', failure['reason'], method_ref=match['method_ref'])
        units.append(unit.run())
    pending = [{'match_id': m['match_id'], 'callsite_ref': m['callsite_ref'],
        'root_method_ref': g.root if g else m['method_ref'], 'projection_context_ref': f.context_ref if f else None}
        for m, g, f in selections[config.max_units:]]
    flow_limits = {'state': 'not_started', 'unmapped_path_nodes': None}
    if any(x.tool_id == 'tool:selected-flow' for x in facts.run.tools):
        try:
            flow = json.loads(view.read_evidence('analysis/selected-flow/report.json'))
            flow_limits = {'state': flow['state'], 'unmapped_path_nodes': sum(x['state'] == 'unresolved' for row in flow.get('mapped', []) for x in row['path']),
                           'scope': 'Source-run mapping limits; actual per-BU admission is recorded in information_flow_adaptations'}
        except (OSError, ValueError, KeyError) as error:
            flow_limits = {'state': 'failed', 'reason': str(error), 'unmapped_path_nodes': None}
    return {'schema_version': 'bu-collection.v1', 'extraction_run_ref': extraction_run,
        'source_run_ref': facts.run.run_id, 'source_snapshot_id': view.snapshot_id, 'apk_sha256': facts.run.apk_sha256,
        'package_version': __version__, 'rule_sha256': sha256_file(__file__), 'catalog_id': catalog['catalog_id'],
        'configuration': config.model_dump(mode='json'), 'units': units,
        'anchor_context_table': anchor_context_table(units, facts),
        'selection': {'sapi_matches': len(matches['matches']), 'contextual_anchors': len(selections), 'pending_anchors': pending,
            'root_signatures_restricted': bool(config.root_signatures), 'graph_failures': graph_failures, 'pending_roots': pending_roots},
        'summary': {'units': len(units), 'physical_anchors': len({x['callsite_ref'] for x in matches['matches']}),
            'selected_physical_anchors': len({u['anchor']['callsite_ref'] for u in units}),
            'states': dict(Counter(x['extraction_status']['state'] for x in units)),
            'information_flow_adaptation_counts': dict(Counter(a['state'] for u in units for a in u['information_flow_adaptations'])),
            'anchor_budget_exhausted': bool(pending), 'root_budget_exhausted': bool(pending_roots),
            'coverage': dict(view.manifest.coverage), 'full_method_complete': False},
        'remaining_gaps': {'sapi_sources': source_gaps, 'general_dispatch_points_to': ({
            'implementation_status':'implemented' if any(t.tool_id=='tool:spark-points-to' for t in facts.run.tools) else 'not_run_in_this_source',
            'analysis_configuration':facts.run.configuration.options.get('points_to'),
            'precision':'Allocation-site context-insensitive may analysis; concrete contexts kept by separate call-frame projection',
            'unknown_after_analysis_is_not_not_implemented':True} if multisource else False),
            'precise_exceptional_heap': False, 'global_path_feasibility': False, 'llm_chunk_assembly': False, 'selected_flow_mapping': flow_limits},
        'visibility_contract': 'Only each BU model_visible records are citation-authorized; archived files require explicit future selection'}


def write_units(view, catalog_path, output, config=None):
    result = build_units(view, catalog_path, config)
    root = filesystem_path(output)
    source_catalog = filesystem_path(catalog_path)
    if source_catalog.is_file():
        source_catalog = source_catalog.parent
    if root.is_relative_to(filesystem_path(view.root)) or root.is_relative_to(source_catalog):
        raise ValueError('BU output must be outside the source snapshot and SAPI catalog')
    destination = root / result['apk_sha256'] / result['extraction_run_ref'].replace(':', '_')
    destination.mkdir(parents=True, exist_ok=False)
    files = {}
    def save(entry, raw):
        path = destination / entry; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        files[entry] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    for path in source_catalog.rglob('*'):
        if path.is_file():
            save('sapi/' + path.relative_to(source_catalog).as_posix(), path.read_bytes())
    save('rules/bu.py', Path(__file__).read_bytes())
    archives = {}
    for unit in result['units']:
        for item in unit['archive_support']['analysis_files']:
            archives[item['archive_entry']] = item
    for entry, item in sorted(archives.items()):
        if item['path'].startswith('evidence/apk-entry-v1/'):
            from androserum.facts.store import apk_entry_descriptor, EvidenceFile
            descriptor = apk_entry_descriptor(view.root, EvidenceFile.model_validate(item))
            # Archive the original authorized APK container and its descriptor,
            # never the decoded DEX returned by the read-only fact service.
            save(_archive_storage_entry(item), (view.root / item['path']).read_bytes())
            save('archive/' + descriptor['container_path'], (view.root / descriptor['container_path']).read_bytes())
            continue
        raw = view.read_evidence(entry)
        stored = base64.b64encode(raw) if item['path'].startswith('evidence/base64-v1/') else raw
        save(_archive_storage_entry(item), stored)
    save('collection.json', (json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8'))
    manifest = {'schema_version': 'bu-manifest.v1', 'extraction_run_ref': result['extraction_run_ref'],
        'source_snapshot_id': result['source_snapshot_id'], 'files': files, 'state': 'published',
        'model_visibility': 'collection.json#/units/*/model_visible only; archive is not model input'}
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    return destination, result


def verify_units(path, view):
    root = filesystem_path(path)
    manifest = json.loads((root / 'manifest.json').read_text('utf-8'))
    if manifest.get('schema_version') != 'bu-manifest.v1' or manifest.get('state') != 'published':
        raise ValueError('Unsupported/unpublished BU package')
    for entry, meta in manifest['files'].items():
        dest = filesystem_path(root / entry)
        if not dest.is_relative_to(root) or sha256_file(dest) != meta['sha256'] or dest.stat().st_size != meta['bytes']:
            raise ValueError('BU archive file identity mismatch')
    result = json.loads((root / 'collection.json').read_text('utf-8'))
    if result['source_snapshot_id'] != view.snapshot_id or manifest['source_snapshot_id'] != view.snapshot_id:
        raise ValueError('BU source snapshot mismatch')
    expected = build_units(view, root / 'sapi', BUConfig.model_validate(result['configuration']), extraction_run=result['extraction_run_ref'])
    # Exact pre-buffer adapter profile. Replay *all* content with current code;
    # only the archived source-hash field may differ on runs without this model.
    # No archived Python is executed and no semantic mismatch is ignored.
    historical_rule=result['rule_sha256']!=expected['rule_sha256']
    if historical_rule:
        profiles={
            '3282e99df0f2da79efed8049e8b8063c8a7ffaf081ae77f6b80cff86f795c3d7':set(),  # Successful query reuse only; full collection comparison remains exact.
            'e8d9449517eddc11869b2f7d04c641b4e17c978ee84208a45463d8c486ad2b0e':set(),  # Checked-byte archive dependency indexing only; every result field still replays.
            'cf29c6b676c7d9a1d603ba9b83d43bda8ac9ef4a6ea40523a4704b184af18854':set(),  # Exact pre-query-reuse profile; result content still replays.
            '4666fc915d10ce9d941290ddfa93800eb59a572f392aa9bd5bfddd21b2dfd492':set(),  # Exact legacy-catalog profile; all content still replays.
            # Exact pre-finalization adapter: only packages without JCA state
            # can replay unchanged. Earlier JCA attempts remain incomplete.
            'dd502384826bac70db9657d9cd4ffa0b8986439be904eff51fffcc81a45d059e':{'tool:jca-state'},
            '773526a9da9c2d0ac4e078d7033b486f2bdb8ec7fc81c4b77d2b003f0c97a05b':{'tool:method-outputs','tool:jca-state'},
            # Exact pre-codec profile. Only physical evidence packaging was
            # extended; replay still compares every anchor, task, record,
            # scope, inclusion reason and visibility field unchanged.
            '91780216a356b9828259bcba29f733c9de8474e0e23960fe183ab0372946eb70':set(),
            '68cd4cb602584b0dda8e6bd5aa2aaffda37babeda6046e5b8e27d03bd6672a73':{'tool:buffer-state','tool:audio-read-sites'},
            'f9213e7e882ea808c0ca3abb5e9e3d5a5f27449b7849e6471c5f2436f15c596c':{'tool:audio-read-sites'}}
        forbidden=profiles.get(result['rule_sha256'])
        if forbidden is None or any(x.tool_id in forbidden for x in view.export_bundle().run.tools):
            raise ValueError('Unknown historical BU rule profile; use matching extraction version')
        expected['rule_sha256']=result['rule_sha256']
    if result != expected:
        raise ValueError('BU replay mismatch: anchor/context/path/inclusion/visibility/status differs')
    if manifest['extraction_run_ref'] != result['extraction_run_ref']:
        raise ValueError('BU manifest run mismatch')
    actual_files = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    if actual_files != set(manifest['files']) | {'manifest.json'}:
        raise ValueError('BU archive inventory mismatch')
    if sha256_file(root/'rules/bu.py') != result['rule_sha256']:
        raise ValueError('BU archived extraction rule mismatch')
    for unit in result['units']:
        for item in unit['archive_support']['analysis_files']:
            archived = root/_archive_storage_entry(item)
            if item['path'].startswith('evidence/apk-entry-v1/'):
                from androserum.facts.store import EvidenceFile, read_evidence_file
                read_evidence_file(root/'archive', EvidenceFile.model_validate(item))
            elif item['path'].startswith('evidence/base64-v1/'):
                stored = archived.read_bytes()
                try:
                    raw = base64.b64decode(stored, validate=True)
                except ValueError as error:
                    raise ValueError('Invalid encoded BU archive') from error
                if (len(stored) != 4 * ((item['bytes'] + 2) // 3) or base64.b64encode(raw) != stored or
                        len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']):
                    raise ValueError('BU encoded evidence differs from source snapshot')
            elif sha256_file(archived) != item['sha256']:
                raise ValueError('BU archived fact evidence differs from source snapshot')
    return {'valid': True, 'units': len(result['units']), 'extraction_run_ref': result['extraction_run_ref'],
            'source_snapshot_id': view.snapshot_id, 'files': len(manifest['files'])}
