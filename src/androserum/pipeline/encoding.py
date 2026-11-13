"""Generic approved-list encoding using the unchanged pinned BERT baseline."""
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import re
import shutil

from androserum.encoding.bert import BertEncoder, aggregate, chunk_records, tokenizer_for, verify_model_files
from androserum.encoding.models import EncodingConfig
from androserum.encoding.runner import read, write
from androserum.encoding.semantic import Projector, semantic_records, REF, HANDLE, ADDRESS
from androserum.facts.identity import canonical_json, filesystem_path, fingerprint, sha256_file
from .approval import load_frozen, inventory, verify_files

VERSION = 'reviewed-bc-encoding.v1'

LEGACY_V1_RULE_PROFILE = {'pipeline/approval.py': '8f65b84390f1bfc787299883a050e11b2e7d6ae4db149e419ac126fc647cd373', 'pipeline/encoding.py': '50f8f4df1c3e97a2977e39cdcba185e3e7833b9f593b900d88a19a0651fd5779', 'baseline/bert.py': 'ecc06472a1bb486480fae84e6294fe925533b7bc6b673fb041cefcf5557f2d25', 'baseline/models.py': '4650f1408a2e913c4409b8fc89bcb84771ed65cac87c209af2eb93df6e487dc2', 'baseline/runner.py': '07a056f036e4b85af293ce46d0dda3461b3a30a26e55b4c1c0caa49d168154b0', 'baseline/semantic.py': 'ec98d18a731e9a30412414c49a4b079e4ae42313e55b5262ac713ad137ecac48', 'baseline/verification.py': 'b0b2cf90cb24bff9c87d22124ed68ae8404b4df5c5638d41c35fc94ef8fe1171', 'baseline/__init__.py': '051af5dee36ebddf6d7936119134cf0f550ef7c27ae45b2bd61ce2f0eab89dda'}


class ReviewedProjector(Projector):
    """Preserve unfamiliar conditions/effects explicitly instead of dropping them.

    Existing finite models use exactly the baseline serializer. A generic local
    predicate keeps its required truth and supported operator/literals; operand
    meaning remains unknown when the visible registry does not normalize it.
    Raw program statements remain in audit only.
    """
    def condition(self, handle):
        if handle in self.conditions:
            return self.conditions[handle]['alias']
        try:
            return super().condition(handle)
        except ValueError as error:
            if not str(error).startswith('Unsupported '):
                raise
        evidence = self.get(handle, 'condition')
        record = self.facts.get(evidence['record_ref'])
        if record is None:
            raise ValueError('Condition fact is not visible')
        alias = 'Condition' + str(len(self.conditions) + 1)
        expected = evidence['expected_value']
        value = {'alias': alias, 'kind': 'recorded condition with limited semantic normalization',
                 'required_truth': deepcopy(expected), 'runtime_established': False,
                 'scope': evidence['scope'], 'unconditional_execution_claimed': False,
                 'predicate_meaning': 'unknown from the supported visible semantic models',
                 'source_collection_states': sorted(set(evidence.get('source_collection_by_bu', {}).values()))}
        point = record.get('value_endpoint', {})
        branch = self.facts.get(evidence['branch_ref'], {})
        if point.get('slot_kind') == 'local':
            value['predicate_shape'] = 'recorded boolean value must have the required truth'
        else:
            match = re.search(r'\bif\s+(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+?)\s+goto\b', branch.get('text', ''))
            if match:
                ops = {'==': 'equal', '!=': 'not equal', '>=': 'greater than or equal', '<=': 'less than or equal',
                       '>': 'greater than', '<': 'less than'}
                def operand(text, number):
                    text = text.strip()
                    if re.fullmatch(r'-?\d+[Ll]?', text):
                        return {'role': 'constant', 'value': int(text.rstrip('Ll'))}
                    if text == 'null':
                        return {'role': 'constant', 'value': None}
                    return {'role': 'operand ' + str(number), 'meaning': 'unknown; provenance remains in audit'}
                value['predicate_shape'] = {'left': operand(match[1], 1), 'operator': ops[match[2]],
                                            'right': operand(match[3], 2)}
        self.conditions[handle] = value
        self.audit['conditions'][alias] = {'handle': handle, 'record_ref': evidence['record_ref'],
                                         'original_condition': deepcopy(record), 'branch_record': deepcopy(branch),
                                         'semantic_adapter': 'limited-generic-condition.v1'}
        return alias

    def effect(self, handle):
        if handle in self.effects:
            return self.effects[handle]['alias']
        try:
            return super().effect(handle)
        except ValueError as error:
            if not str(error).startswith('Unsupported state effect model'):
                raise
        evidence = self.get(handle, 'effect')
        raw = self.facts.get(evidence['record_ref'])
        if raw is None:
            raise ValueError('Effect fact is not visible')
        alias = 'Effect' + str(len(self.effects) + 1)
        self.effects[handle] = {'alias': alias, 'kind': 'recorded potential modeled state effect',
                                'meaning': 'unknown outside the supported finite semantic models',
                                'execution': 'possible only', 'success_established': False,
                                'scope': 'attached operation/state evidence only; detailed rule in audit'}
        self.audit['effects'][alias] = {'handle': handle, 'record_ref': evidence['record_ref'],
                                      'record': deepcopy(raw), 'semantic_adapter': 'explicit-unknown-effect.v1'}
        return alias

    def validate_link(self, link):
        try:
            return super().validate_link(link)
        except ValueError as error:
            if str(error) != 'Unsupported semantic relationship profile':
                raise
        path = [self.get(h, 'relation') for h in link['support_path']]
        allowed = {'icc_data': {'icc_data'}, 'control_constraint': {'control_dependency'},
                   'event_context': {'event_trigger'}, 'component_target': {'icc_target'}}
        kinds = {e['kind'] for e in path}
        if link['relation_kind'] not in allowed or not kinds <= allowed[link['relation_kind']]:
            raise ValueError('Unsupported typed semantic relationship profile')
        # native_check has already validated all endpoints, conditions, bindings
        # and relationship strength; this adapter never manufactures a path.
        if link['execution_claim'] != 'possible_only':
            raise ValueError('Cannot strengthen execution claim')
        return path


def serialize_reviewed(entry, config=None):
    config=config or EncodingConfig()
    projector=ReviewedProjector
    if config.serializer_version=='bc-semantics.v2':
        from .semantic_v2 import ReviewedProjectorV2
        projector=ReviewedProjectorV2
    projection, audit = projector(entry).project()
    units = semantic_records(projection)
    text, spans = '', []
    for unit in units:
        if text:
            text += '\n\n'
        start = len(text); text += unit['text']
        spans.append({**unit, 'char_start': start, 'char_end': len(text)})
    from .semantic_v2 import LOCATOR
    location_pattern=ADDRESS if config.serializer_version=='bc-semantics.v1' else LOCATOR
    if REF.search(text) or HANDLE.search(text) or location_pattern.search(text):
        raise ValueError('Program locator leaked into semantic text')
    return {'projection': projection, 'text': text + '\n', 'records': spans, 'audit': audit}


def _rules():
    here = Path(__file__).parent
    baseline = here.parent / 'encoding'
    return {'pipeline/' + name: here / name for name in ['approval.py', 'encoding.py', 'semantic_v2.py']} | {
        'baseline/' + p.name: p for p in baseline.glob('*.py')}


def encode_frozen(freeze_dir, model_dir, lock_path, output, config=None):
    import numpy as np
    freeze_dir = filesystem_path(freeze_dir)
    policy, entries = load_frozen(freeze_dir)
    if not entries:
        raise ValueError('No approved BCs; preserve empty review inventory without fabricating an embedding')
    config = config or EncodingConfig()
    encoder = BertEncoder(model_dir, read(lock_path), config)
    serialized = [serialize_reviewed(e,config) for e in entries]
    plans = [chunk_records(s, encoder.tokenizer, config) for s in serialized]
    run = filesystem_path(output) / ('encoding_' + uuid4().hex)
    run.mkdir(parents=True, exist_ok=False)
    shutil.copytree(freeze_dir, run / 'audit/freeze')
    shutil.copyfile(filesystem_path(lock_path), run / 'audit/model-lock.json')
    write(run / 'audit/approved-pool.json', {'entries': entries})
    for name, source in _rules().items():
        target = run / 'audit/rules' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    write(run / 'config.json', config.model_dump(mode='json'))
    write(run / 'runtime.json', encoder.runtime)
    write(run / 'model-artifacts.json', encoder.artifacts)
    rows, chunks, groups = [], [], []
    backlinks = read(freeze_dir / 'backlinks.json')
    for i, (entry, semantic, plan, backlink) in enumerate(zip(entries, serialized, plans, backlinks)):
        directory = 'bc-' + format(i + 1, '04d')
        base = run / directory; base.mkdir()
        (base / 'semantic.txt').write_text(semantic['text'], 'utf-8', newline='\n')
        for filename, value in [('semantic.json', semantic['projection']), ('records.json', semantic['records']),
                                ('chunks.json', plan), ('audit/aliases.json', semantic['audit']),
                                ('audit/source.json', backlink), ('audit/approved-entry.json', entry)]:
            write(base / filename, value)
        for chunk in plan:
            (base / f"chunk-{chunk['chunk_index'] + 1:04d}.txt").write_text(chunk['text'], 'utf-8', newline='\n')
        group = list(range(len(chunks), len(chunks) + len(plan)))
        groups.append(group); chunks.extend(plan)
        rows.append({'bc_vector_row': i, 'qualified_ref': entry['qualified_ref'], 'source_case': entry['source_case'],
                     'source_apk_sha256': entry['source_apk_sha256'], 'directory': directory,
                     'chunk_vector_rows': group, 'chunk_count': len(plan),
                     'semantic_sha256': sha256_file(base / 'semantic.txt'),
                     'source_ledger_revision': entry['ledger_revision'],
                     'token_counts': [c['model_token_count'] for c in plan]})
    chunk_vectors = encoder.encode(chunks)
    means, vectors = aggregate(chunk_vectors, groups, config)
    for filename, array in [('chunk_vectors.npy', chunk_vectors), ('bc_raw_means.npy', means), ('bc_vectors.npy', vectors)]:
        np.save(run / filename, array, allow_pickle=False)
    write(run / 'rows.json', rows)
    write(run / 'run.json', {'schema_version': VERSION, 'state': 'published', 'role': policy['role'],
          'source_freeze_id': read(freeze_dir / 'manifest.json')['freeze_id'],
          'created_utc': datetime.now(timezone.utc).isoformat(), 'qualified_refs': policy['qualified_refs'],
          'bc_count': len(rows), 'chunk_count': len(chunks), 'dimensions': 768,
          'excluded_candidate_count': policy['excluded_count'], 'generative_llm_calls': 0,
          'encoder_changed': False, 'retrieval_quality_validated': False, 'history_updated': False})
    files = inventory(run)
    write(run / 'manifest.json', {'schema_version': 'reviewed-bc-encoding-manifest.v1', 'state': 'published',
          'encoding_id': fingerprint(files), 'files': files})
    return run


def verify_encoding(run, model_dir, *, reencode=False, verify_sources=True):
    import numpy as np
    run = filesystem_path(run)
    manifest = verify_files(run)
    if manifest.get('encoding_id') != fingerprint(manifest['files']):
        raise ValueError('Encoding identity differs')
    policy, entries = load_frozen(run / 'audit/freeze', verify_sources=verify_sources)
    info = read(run / 'run.json')
    config = EncodingConfig.model_validate(read(run / 'config.json'))
    if info['schema_version'] != VERSION or info['qualified_refs'] != policy['qualified_refs'] or info['role'] != policy['role']:
        raise ValueError('Encoding differs from approved freeze')
    artifacts = verify_model_files(model_dir, read(run / 'audit/model-lock.json'))
    if artifacts != read(run / 'model-artifacts.json'):
        raise ValueError('Pinned BERT artifact identity differs')
    current_rules={name:sha256_file(source) for name,source in _rules().items()}
    archived_rules={p.relative_to(run/'audit/rules').as_posix():sha256_file(p) for p in (run/'audit/rules').rglob('*.py')}
    legacy_rules=(config.serializer_version=='bc-semantics.v1' and archived_rules==LEGACY_V1_RULE_PROFILE
        and all(current_rules.get(k)==LEGACY_V1_RULE_PROFILE[k] for k in
            ['pipeline/approval.py','baseline/bert.py','baseline/semantic.py','baseline/__init__.py']))
    if archived_rules!=current_rules and not legacy_rules:
        raise ValueError('Encoding rules do not match the current or exact known v1 profile')
    tokenizer = tokenizer_for(model_dir, config)
    rows = read(run / 'rows.json')
    if [r['qualified_ref'] for r in rows] != policy['qualified_refs']:
        raise ValueError('Vector rows differ from frozen BC order')
    chunks, groups = [], []
    for i, (entry, row) in enumerate(zip(entries, rows)):
        base = filesystem_path(run / row['directory'])
        if not base.is_relative_to(run):
            raise ValueError('BC asset escaped encoding run')
        semantic = serialize_reviewed(entry,config); plan = chunk_records(semantic, tokenizer, config)
        if (semantic['text'] != (base / 'semantic.txt').read_text('utf-8') or
                semantic['projection'] != read(base / 'semantic.json') or
                semantic['records'] != read(base / 'records.json') or
                semantic['audit'] != read(base / 'audit/aliases.json') or plan != read(base / 'chunks.json') or
                entry != read(base / 'audit/approved-entry.json')):
            raise ValueError('Semantic/chunk/native replay differs')
        group = list(range(len(chunks), len(chunks) + len(plan)))
        if row['bc_vector_row'] != i or row['chunk_vector_rows'] != group:
            raise ValueError('Chunk/vector mapping differs')
        groups.append(group); chunks.extend(plan)
    cv, means, vectors = [np.load(run / filename, allow_pickle=False)
                          for filename in ['chunk_vectors.npy', 'bc_raw_means.npy', 'bc_vectors.npy']]
    if cv.shape != (len(chunks), 768) or means.shape != vectors.shape or vectors.shape != (len(entries), 768):
        raise ValueError('Generic encoding vector dimensions differ')
    if any(a.dtype != np.float32 or not np.isfinite(a).all() for a in [cv, means, vectors]):
        raise ValueError('Invalid generic encoding vectors')
    expected = np.stack([np.sum(cv[g], axis=0, dtype=np.float32) / np.float32(len(g)) for g in groups])
    norms = np.sqrt(np.sum(expected.astype(np.float64) ** 2, axis=1))
    if not np.array_equal(means, expected) or not np.array_equal(vectors, (expected / norms[:, None]).astype(np.float32)):
        raise ValueError('Aggregation differs from frozen BERT baseline')
    if reencode:
        encoder = BertEncoder(model_dir, read(run / 'audit/model-lock.json'), config)
        if not np.array_equal(cv, encoder.encode(chunks)):
            raise ValueError('Offline BERT replay differs')
    return {'status': 'passed', 'schema_version': 'reviewed-bc-encoding-verification.v1',
            'bc_count': len(entries), 'chunk_count': len(chunks), 'dimensions': 768,
            'role': policy['role'], 'excluded_candidates': policy['excluded_count'], 'reencoded': reencode,
            'retrieval_quality_validated': False, 'generative_llm_calls': 0,
            'serializer_version':config.serializer_version, 'exact_legacy_rule_profile_replayed':legacy_rules,
            'archived_python_executed':False}
