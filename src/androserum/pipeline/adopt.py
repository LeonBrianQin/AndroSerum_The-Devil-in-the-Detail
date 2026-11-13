"""Adopt an independently reviewed query freeze without rerunning its sources."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import json
import shutil
import time

from androserum.facts.identity import filesystem_path, fingerprint, sha256_file
from androserum.facts.store import FactView
from androserum.inference.provider import write
from androserum.mining.ledger import Ledger
from .approval import load_frozen, verify_files
from .config import PipelineConfig


def read(path): return json.loads(filesystem_path(path).read_text('utf-8'))


def adopt_frozen_source(apk, freeze, output, config=None):
    """Bind current APK bytes to the freeze's actual old fact/BU/model runs.

    No static analysis, BU extraction, BERT encoding or generative invocation is
    performed. Source costs are preserved as lineage metadata, never charged as
    fresh extraction in the new round. Original packages remain untouched.
    """
    started = time.monotonic(); apk = filesystem_path(apk); freeze = filesystem_path(freeze)
    output = filesystem_path(output); config = config or PipelineConfig()
    if not apk.is_file(): raise ValueError('Adopted APK does not exist')
    actual_sha = sha256_file(apk); policy, entries = load_frozen(freeze)
    if policy['role'] != 'query': raise ValueError('Adoption requires a separately reviewed query-role freeze')
    review = read(freeze / 'review.json'); freeze_manifest = read(freeze / 'manifest.json')
    if review.get('apk_sha256') is not None and review['apk_sha256'] != actual_sha:
        raise ValueError('Freeze review belongs to a different actual APK')
    if entries:
        if any(e['source_apk_sha256'] != actual_sha for e in entries):
            raise ValueError('Frozen BC source differs from actual APK bytes')
        snapshots = sorted({str(filesystem_path(e['source_snapshot'])) for e in entries})
        bu_packages = sorted({str(filesystem_path(e['source_bu_package'])) for e in entries})
        mining_runs = sorted({str(filesystem_path(e['source_mining_run'])) for e in entries})
    else:
        required = ['apk_sha256', 'source_run_ref', 'source_snapshot', 'source_bu_package']
        if any(key not in review for key in required) or not review.get('source_snapshot') or not review.get('source_run_ref'):
            raise ValueError('An empty freeze requires explicit review APK/run/source_snapshot/source_bu_package bindings')
        if review['source_bu_package'] is None and review.get('bu_extraction_status') != 'no_bu_evidence':
            raise ValueError('An absent BU package requires explicit no_bu_evidence review status')
        snapshots = [str(filesystem_path(review['source_snapshot']))]
        bu_packages = [str(filesystem_path(review['source_bu_package']))] if review['source_bu_package'] else []
        mining_runs = [str(filesystem_path(review['source_mining_run']))] if review.get('source_mining_run') else []
        if policy['excluded_count'] and not mining_runs:
            raise ValueError('Excluded candidates in an empty freeze require their actual source_mining_run binding')
    forbidden = [freeze, *map(filesystem_path, snapshots + bu_packages + mining_runs)]
    if any(output == source or output.is_relative_to(source) for source in forbidden):
        raise ValueError('Adoption output cannot modify a frozen source package')
    source_manifests = {path: read(filesystem_path(path) / 'manifest.json') for path in snapshots}
    identities = {(m['apk_sha256'], m['run_ref'], m['snapshot_id']) for m in source_manifests.values()}
    if len(identities) != 1 or next(iter(identities))[0] != actual_sha:
        raise ValueError('All adopted BCs must share the same actual APK, logical fact snapshot and analysis run')
    _, run_ref, snapshot_id = next(iter(identities))
    if review.get('source_run_ref') is not None and review['source_run_ref'] != run_ref:
        raise ValueError('Freeze review run differs from its actual source snapshot')
    if review.get('source_snapshot_id') is not None and review['source_snapshot_id'] != snapshot_id:
        raise ValueError('Freeze review logical snapshot differs from its actual source')
    snapshot = filesystem_path(snapshots[0]); bu_sources = []; units = {}; selected_roots = set()
    for path in bu_packages:
        directory = filesystem_path(path); manifest = verify_files(directory); collection = read(directory / 'collection.json')
        if (collection['apk_sha256'], collection['source_run_ref'], collection['source_snapshot_id']) != (actual_sha, run_ref, snapshot_id):
            raise ValueError('Frozen BU package belongs to another APK/snapshot/run')
        selected_roots.update(collection['configuration'].get('root_signatures', []))
        for unit in collection['units']:
            if unit['bu_id'] in units and units[unit['bu_id']] != unit:
                raise ValueError('Adopted BU identity collision')
            units[unit['bu_id']] = unit
        bu_sources.append({'path': path, 'manifest_sha256': sha256_file(directory / 'manifest.json'),
                           'extraction_run_ref': collection['extraction_run_ref'], 'catalog_id': collection['catalog_id'],
                           'bu_count': len(collection['units'])})
    native_runs = []; selected_ids = set()
    for path in mining_runs:
        directory = filesystem_path(path); verify_files(directory)
        info = read(directory / 'run.json'); report = read(directory / 'report.json')
        source = info['identity']['source']
        if (source['apk_sha256'], source['source_run_ref'], source['source_snapshot_id']) != (actual_sha, run_ref, snapshot_id):
            raise ValueError('Frozen native model run belongs to another APK/snapshot/run')
        if bu_sources and source['extraction_run_ref'] not in {b['extraction_run_ref'] for b in bu_sources}:
            raise ValueError('Native model run does not originate in an adopted BU package')
        with Ledger(directory / 'ledger.sqlite', readonly=True) as ledger:
            ledger.verify(); state = ledger.state()
            if state != report['accepted_state']: raise ValueError('Adopted native model report differs from its actual ledger')
        selected_ids.update(info['identity']['selected_bu_ids'])
        native_runs.append({'path': path, 'manifest_sha256': sha256_file(directory / 'manifest.json'),
                            'ledger_sha256': sha256_file(directory / 'ledger.sqlite'),
                            'ledger_revision': state['revision'], 'provider': info['provider'],
                            'historical_source_attempt_count': len(report['attempts']),
                            'source_budget_metadata': report['budgets'],
                            'counted_as_new_round_model_calls': False})
    if not selected_ids: selected_ids = set(units)
    if not selected_ids <= set(units): raise ValueError('Native model run selected a BU absent from adopted packages')
    with FactView(snapshot) as view:
        if (view.manifest.apk_sha256, view.run_ref, view.snapshot_id) != (actual_sha, run_ref, snapshot_id):
            raise ValueError('Adopted fact database identity differs')
        facts = view.export_bundle(); coverage = dict(view.manifest.coverage)
        if any(f.archive_entry == 'analysis/selected-flow/report.json' for f in view.manifest.files):
            flow = json.loads(view.read_evidence('analysis/selected-flow/report.json'))
            selected_flow = {'state': flow['state'], 'reason': flow.get('reason'),
                             'mapped_rows': len(flow.get('mapped', [])),
                             'source_evidence_entry': 'analysis/selected-flow/report.json'}
        else:
            selected_flow = {'state': 'unavailable', 'reason': 'Original source snapshot has no selected-flow report',
                             'source_evidence_entry': None}
    source_origin = {'query_freeze': str(freeze), 'freeze_id': freeze_manifest['freeze_id'],
                     'freeze_manifest_sha256': sha256_file(freeze / 'manifest.json'),
                     'snapshot_sources': [{'path': p, 'manifest_sha256': sha256_file(filesystem_path(p) / 'manifest.json'),
                                            'database_sha256': source_manifests[p]['database_sha256']} for p in snapshots],
                     'source_snapshot_id': snapshot_id, 'source_run_ref': run_ref,
                     'bu_packages': bu_sources, 'native_model_runs': native_runs,
                     'approved_qualified_refs': policy['qualified_refs'],
                     'original_sources_modified': False, 'archive_does_not_expand_model_visibility': True,
                     'existing_source_costs_are_not_fresh_extraction_costs': True}
    binding = fingerprint({'apk_sha256': actual_sha, 'source_origin': source_origin,
                           'config': config.model_dump(mode='json')})
    if (output / 'prepared.json').exists():
        old = read(output / 'prepared.json')
        if not old.get('adopted_frozen_sources') or old.get('adoption_binding_sha256') != binding:
            raise ValueError('Cannot replace existing preparation with different adopted sources')
        if sha256_file(old['input_apk']) != actual_sha: raise ValueError('Adopted input APK changed on resume')
        return old
    output.mkdir(parents=True, exist_ok=True); target = output / 'input.apk'
    if target.exists() and sha256_file(target) != actual_sha: raise ValueError('Adoption output already contains a different APK')
    if not target.exists(): shutil.copyfile(apk, target)
    config_value = config.model_dump(mode='json')
    if (output / 'config.json').exists() and read(output / 'config.json') != config_value:
        raise ValueError('Adoption output already contains a different pipeline configuration')
    write(output / 'config.json', config_value)
    result = {'schema_version': 'prepared-apk-pipeline.v1', 'apk_sha256': actual_sha,
              'source_path': str(apk), 'input_apk': str(target), 'snapshot': str(snapshot),
              'source_run_ref': run_ref, 'bu_package': bu_packages[0] if len(bu_packages) == 1 else None,
              'source_bu_packages': bu_packages, 'selected_bu_ids': sorted(selected_ids),
              'bu_count': len(selected_ids), 'available_sapi_roots': sorted(selected_roots),
              'selected_roots': sorted(selected_roots), 'unprocessed_roots': [],
              'root_policy': 'Adopt original frozen BU/model scope; no new context or evidence expansion',
              'physical_sapi_calls': len({u['anchor']['callsite_ref'] for u in units.values()}),
              'sapi_matches': len({u['anchor']['match_id'] for u in units.values()}),
              'fact_coverage': coverage,
              'fact_summary': {'outcome': 'adopted_original_source', 'coverage': coverage,
                               'selected_flow': selected_flow, 'source_run_id': run_ref,
                               'element_counts': dict(Counter(e.kind for e in facts.elements)),
                               'relation_counts': dict(Counter(e.relation_kind for e in facts.relations))},
              'source_origin': source_origin, 'existing_native_model_runs': native_runs,
              'adopted_frozen_sources': True, 'adoption_binding_sha256': binding,
              'adopted_utc': datetime.now(timezone.utc).isoformat(),
              'new_static_analysis_runs': 0, 'new_bu_extractions': 0, 'new_generative_model_calls': 0,
              'source_generation_costs_counted_as_fresh': False,
              'elapsed_seconds': time.monotonic()-started,
              'elapsed_scope': 'Adoption validation/copy only; original extraction and model costs are inherited audit metadata',
              'config_sha256': fingerprint(config_value), 'apk_execution': False,
              'labels_used': False, 'full_behavior_coverage_claimed': False}
    write(output / 'source-origin.json', source_origin); write(output / 'prepared.json', result)
    return result


__all__ = ['adopt_frozen_source']
