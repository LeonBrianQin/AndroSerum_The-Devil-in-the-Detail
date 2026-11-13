"""Explicit normal method results, distinct from their internal return operands.

The projection preserves analysis root, frame and return site. Reaching a
return is a static possibility, never an observation of successful execution.
Caught-exception arrival is identified separately from an escaping throw.
"""
from collections import defaultdict, deque
import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import Field
from androserum.facts.context_heap import ContextHeapReport, entry_for, TOOL as CONTEXT_TOOL
from androserum.facts.identity import canonical_json, fingerprint, parse_method_signature, record_id
from androserum.facts.io import loads_facts
from androserum.facts.local_flow import _constant_value
from androserum.facts.models import (AnalysisNodeRecord, AnalysisPosition, AnalysisScope, AnalysisStatus,
    BindingRecord, Endpoint, ProgramSlot, Provenance, RelationRecord, StrictModel, ToolVersion,
    ValueInfo, VersionedArtifact)

TOOL = 'tool:method-outputs'
RULE = 'rule:method-outputs-v1'
ENTRY = 'analysis/method-outputs/report.json'
VERSION = 'method-output-projection.v1'


class MethodOutputConfig(StrictModel):
    schema_version: Literal['method-output-config.v1'] = 'method-output-config.v1'
    max_returns: int = Field(default=10000, ge=1, le=100000)
    max_visits: int = Field(default=100000, ge=1, le=10000000)
    scope: Literal['explicit_returns_in_existing_frames'] = 'explicit_returns_in_existing_frames'


def _witnesses(projection, limit):
    adjacent = defaultdict(list)
    for source, target in projection.cfg.normal_edges:
        adjacent[source].append({'source': source, 'target': target, 'kind': 'normal'})
    for edge in projection.cfg.exception_edges:
        adjacent[edge.source].append({'source': edge.source, 'target': edge.target,
            'kind': 'exception', 'exception_type': edge.exception_type, 'transfer': edge.transfer})
    # Retain one deterministic normal and one exceptional-arrival witness.
    queue = deque([(0, False, [])] if projection.nodes else [])
    seen, paths = set(), {}
    while queue:
        unit, exceptional, path = queue.popleft()
        key = unit, exceptional
        if key in seen:
            continue
        if len(seen) >= limit:
            return paths, True
        seen.add(key); paths[key] = path
        for edge in sorted(adjacent[unit], key=canonical_json):
            queue.append((edge['target'], exceptional or edge['kind'] == 'exception', [*path, edge]))
    return paths, False


def analyze_method_outputs(facts, read, config):
    records = {r.id: r for r in facts.elements}; original_ir_cache = {}
    roots = sorted({r.method_ref for r in facts.elements if isinstance(r, AnalysisNodeRecord)
        and r.provenance.tool_ref == CONTEXT_TOOL and r.position.position_label == 'context-heap'})
    raw_mappings = defaultdict(list)
    for edge in facts.relations:
        if edge.relation_kind == 'dex_jimple_mapping' and edge.target and edge.resolution == 'resolved':
            raw_mappings[edge.target.element_ref].append(edge.source.element_ref)
    report = {'schema_version': VERSION, 'run_ref': facts.run.run_id,
              'configuration': config.model_dump(mode='json'), 'roots': [], 'returns': [],
              'void_returns': [], 'exceptional_exits': [], 'unsupported': [],
              'runtime_execution_established': False, 'path_feasibility_checked': False}
    for root in roots:
        raw = read(entry_for(root)); source = ContextHeapReport.model_validate_json(raw)
        status = {'root_ref': root, 'state': source.state, 'source_report_sha256': hashlib.sha256(raw).hexdigest()}
        report['roots'].append(status)
        if source.state != 'complete' or source.projection is None:
            status['reason'] = source.reason or 'Context projection unavailable'; continue
        projection = source.projection; frames = {f.context_ref: f for f in projection.frames}
        paths, truncated = _witnesses(projection, config.max_visits)
        if truncated:
            status.update(state='truncated', reason='Return reachability budget exhausted')
        for meta, unit in zip(projection.nodes, projection.method.units):
            if meta.role not in {'original', 'return_binding'} or not meta.origin_ref:
                continue
            original = records[meta.origin_ref]
            # The original structured IR is authoritative for a nested return,
            # whose contextual implementation is an assignment to its caller.
            path = original.position.artifact_path
            if path not in original_ir_cache:
                original_ir_cache[path] = json.loads(read(path))
            original_ir = original_ir_cache[path]
            index = int(original.position.position_label.split(':', 1)[1])
            source_unit = original_ir['units'][index]
            if source_unit['operation'] == 'throw':
                report['exceptional_exits'].append({'root_ref': root, 'context_ref': meta.frame_ref,
                    'owner_projection_ref': meta.node_ref, 'origin_ref': meta.origin_ref,
                    'kind': 'explicit_throw_site', 'escape_proven': False,
                    'handler_targets': sorted({e.target for e in projection.cfg.exception_edges if e.source == meta.index}),
                    'normal_result_generated': False})
                continue
            if source_unit['operation'] != 'return':
                continue
            frame = frames[meta.frame_ref]
            return_type = parse_method_signature(records[frame.method_ref].signature)[3]
            normal = paths.get((meta.index, False)); exceptional = paths.get((meta.index, True))
            if normal is None and exceptional is None:
                report['unsupported'].append({'root_ref': root, 'owner_projection_ref': meta.node_ref,
                    'reason': 'Explicit return has no reachable witness in this bounded projection'}); continue
            if return_type == 'V' or not source_unit['uses']:
                report['void_returns'].append({'root_ref': root, 'context_ref': frame.context_ref,
                    'owner_projection_ref': meta.node_ref, 'kind': 'void_return', 'value_result_generated': False}); continue
            if len(report['returns']) >= config.max_returns:
                report['unsupported'].append({'root_ref': root, 'owner_projection_ref': meta.node_ref,
                    'reason': 'Method result budget exhausted'}); continue
            operand = unit.uses[0] if unit.uses else None
            if operand is None or operand.truncated or (operand.local_index is None and operand.constant_kind is None):
                report['unsupported'].append({'root_ref': root, 'owner_projection_ref': meta.node_ref,
                    'reason': 'Return operand is absent, truncated or not a supported local/literal'}); continue
            identity = [root, frame.context_ref, meta.node_ref]
            output_ref = record_id(facts.run.run_id, 'analysis', ['method-normal-result-v1', *identity])
            position = 'method-result:' + meta.node_ref
            output = Endpoint(element_ref=output_ref, slot_kind='result', position_label=position)
            constant_ref = None
            if operand.local_index is not None:
                point = Endpoint(element_ref=meta.node_ref, slot_kind='local', slot_index=operand.local_index,
                                 position_label='unit:' + str(meta.index))
                value = ValueInfo(status='unknown', reason='Value returned on this recorded path; concrete runtime value unknown')
            else:
                constant_ref = record_id(facts.run.run_id, 'analysis', ['method-return-literal-v1', *identity])
                point = Endpoint(element_ref=constant_ref, slot_kind='value', position_label='return-literal:' + meta.node_ref)
                value = _constant_value(operand)
            conditions = sorted({c for edge in facts.relations if edge.relation_kind == 'control_dependency'
                and edge.target and edge.target.element_ref in {meta.node_ref, meta.origin_ref}
                for c in edge.condition_refs})
            row = {'schema_version': VERSION, 'root_ref': root, 'method_ref': frame.method_ref,
                'context_ref': frame.context_ref, 'parent_context_ref': frame.parent_ref,
                'call_path': [f.model_dump(mode='json') for f in frame.call_path],
                'owner_projection_ref': meta.node_ref, 'origin_ref': meta.origin_ref,
                'projection_role': meta.role, 'return_type': return_type,
                'source_endpoint': point.model_dump(mode='json'), 'output_endpoint': output.model_dump(mode='json'),
                'constant_node_ref': constant_ref, 'value': value.model_dump(mode='json'),
                'relation_ref': record_id(facts.run.run_id, 'relation', ['normal-method-result-v1', *identity]),
                'binding_ref': record_id(facts.run.run_id, 'binding', ['normal-method-result-v1', *identity]),
                'condition_refs': conditions, 'raw_return_refs': sorted(raw_mappings.get(meta.origin_ref, [])),
                'normal_return': True, 'normal_completion_required': True,
                'arrival_scope': 'normal_cfg_witness' if normal is not None else 'handler_arrival_witness',
                'cfg_witness': normal if normal is not None else exceptional,
                'additional_handler_arrival_possible': exceptional is not None,
                'execution_established': False, 'outward_scope': 'this exact method frame and return site only'}
            report['returns'].append(row)
    return report


def _emit(facts, report):
    nodes, bindings, edges = [], [], []
    for index, row in enumerate(report['returns']):
        support = [row['method_ref'], row['context_ref'], row['owner_projection_ref'], row['origin_ref'], *row['raw_return_refs']]
        provenance = Provenance(kind='static_analysis', tool_ref=TOOL, rule_ref=RULE, support_refs=list(dict.fromkeys(support)))
        output = Endpoint(**row['output_endpoint']); source = Endpoint(**row['source_endpoint'])
        node = AnalysisNodeRecord(id=output.element_ref, run_ref=facts.run.run_id, kind='analysis_node',
            node_kind='mapping', method_ref=row['method_ref'], provenance=provenance,
            position=AnalysisPosition(kind='analysis', artifact_path=ENTRY, position_label=output.position_label),
            text=canonical_json(row), slots=[ProgramSlot(slot_kind='result', type_descriptor=row['return_type'],
                value=ValueInfo.model_validate(row['value']))])
        nodes.append(node)
        if row['constant_node_ref']:
            nodes.append(AnalysisNodeRecord(id=source.element_ref, run_ref=facts.run.run_id, kind='analysis_node',
                node_kind='mapping', method_ref=row['method_ref'], provenance=provenance,
                position=AnalysisPosition(kind='analysis', artifact_path=ENTRY, position_label=source.position_label),
                text='Literal operand of an explicit normal return',
                slots=[ProgramSlot(slot_kind='value', type_descriptor=row['return_type'], value=ValueInfo.model_validate(row['value']))]))
        bindings.append(BindingRecord(id=row['binding_ref'], run_ref=facts.run.run_id, provenance=provenance,
            binding_kind='value', endpoints=[source, output], context_ref=row['context_ref'], condition_refs=row['condition_refs']))
        edges.append(RelationRecord(id=row['relation_ref'], run_ref=facts.run.run_id, provenance=provenance,
            relation_kind='data_dependency', source=source, target=output, context_ref=row['context_ref'],
            binding_refs=[row['binding_ref']], condition_refs=row['condition_refs'], resolution='resolved',
            source_selector=ENTRY + '#/returns/' + str(index)))
    return nodes, bindings, edges


def extend_method_outputs(result, config=None):
    config = config or MethodOutputConfig(); facts = result.facts
    if any(t.tool_id == TOOL for t in facts.run.tools):
        raise ValueError('Method-output projection already exists; create a new analysis run')
    facts.run.configuration.options['method_outputs'] = config.model_dump(mode='json')
    facts.run.config_fingerprint = fingerprint(facts.run.configuration.model_dump(mode='json'))
    report = analyze_method_outputs(facts, lambda e: result.blobs[result.entry_digests[e]], config)
    facts.run.tools.append(ToolVersion(tool_id=TOOL, name='explicit frame-local normal method results', version='1'))
    for entry, data, artifact in [('analysis/rules/method_outputs.py', Path(__file__).read_bytes(), RULE),
                                   (ENTRY, canonical_json(report).encode(), None)]:
        digest = hashlib.sha256(data).hexdigest(); result.blobs[digest] = data; result.entry_digests[entry] = digest
        if artifact:
            facts.run.artifacts.append(VersionedArtifact(artifact_id=artifact, kind='rule', name=VERSION,
                version='1', sha256=digest, location=entry))
    nodes, bindings, edges = _emit(facts, report)
    facts.elements.extend(nodes); facts.bindings.extend(bindings); facts.relations.extend(edges)
    for root in report['roots']:
        facts.statuses.append(AnalysisStatus(id=record_id(facts.run.run_id, 'status', ['method-output-v1', root['root_ref']]),
            run_ref=facts.run.run_id, tool_ref=TOOL, capability='data_flow',
            scope=AnalysisScope(kind='element', element_ref=root['root_ref']), state='partial',
            reason='Explicit returns only; reachability is a may-witness, not execution or API-success proof'))
    result.facts = loads_facts(facts.model_dump_json())
    verify_method_outputs(result.facts, lambda e: result.blobs[result.entry_digests[e]])
    result.summary['method_outputs'] = {'value_returns': len(report['returns']), 'void_returns': len(report['void_returns']),
        'explicit_throw_exits': len(report['exceptional_exits']), 'unsupported': len(report['unsupported'])}
    return result


def verify_method_outputs(facts, read):
    own = lambda r: r.provenance.tool_ref == TOOL or r.provenance.rule_ref == RULE
    actual = [{r.id: r for r in group if own(r)} for group in [facts.elements, facts.bindings, facts.relations]]
    if not any(t.tool_id == TOOL for t in facts.run.tools):
        if any(actual):
            raise ValueError('Method outputs lack their analysis tool')
        return
    config = MethodOutputConfig.model_validate(facts.run.configuration.options['method_outputs'])
    report = json.loads(read(ENTRY))
    if report != analyze_method_outputs(facts, read, config):
        raise ValueError('Method result endpoints do not match explicit returns and reachable frames')
    if actual != [{r.id: r for r in group} for group in _emit(facts, report)]:
        raise ValueError('Forged method-result node, transfer or binding')


def method_output_evidence(facts, read, refs=()):
    if not any(t.tool_id == TOOL for t in facts.run.tools):
        return {'state': 'not_started', 'returns': [], 'exceptional_exits': [], 'void_returns': [], 'unsupported': []}
    report = json.loads(read(ENTRY)); selected = set(refs)
    def keep(row):
        return not selected or bool(selected & {row.get('root_ref'), row.get('method_ref'), row.get('owner_projection_ref')})
    return {'state': 'partial', **{key: [row for row in report[key] if keep(row)]
        for key in ['returns', 'exceptional_exits', 'void_returns', 'unsupported']},
        'runtime_execution_established': False}
