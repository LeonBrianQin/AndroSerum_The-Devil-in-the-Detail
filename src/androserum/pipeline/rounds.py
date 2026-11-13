"""Freeze a new arbitrary APK/query round before any generative inference."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import re
from urllib.parse import urlsplit

from androserum.facts.identity import filesystem_path, fingerprint, sha256_file
from androserum.inference.compact import COMPACT_INSTRUCTIONS
from androserum.inference.matching import MATCH_PROMPT, match_protocol
from androserum.inference.provider import strict_schema, write
from androserum.matching.models import MatchProposal
from androserum.mining.models import Proposal, CurrentProposal, CurrentMiningConfig
from androserum.mining.providers import settings
from .approval import read
from .config import PipelineConfig
from .knowledge import load_history
from .tasking import PROMPT, proposal_schema


VERSION = 'apk-pipeline-round.v1'
_LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')


def _model_options(value):
    options = deepcopy(settings() if value is None else value)
    allowed = {'executable', 'model', 'provider', 'spec', 'provider_host', 'reasoning_effort'}
    if set(options) != allowed:
        raise ValueError('Model options require nonsecret CLI configuration only; do not pass credentials')
    if any(not isinstance(options[k], str) or not options[k] for k in allowed - {'spec'}):
        raise ValueError('Pinned model/CLI/provider configuration is incomplete')
    if not filesystem_path(options['executable']).is_file():
        raise ValueError('Pinned authenticated CLI executable does not exist')
    spec = options['spec']
    if not isinstance(spec, dict) or set(spec) - {'name', 'base_url', 'wire_api', 'requires_openai_auth', 'env_key'}:
        raise ValueError('Provider configuration contains an unsupported or secret field')
    url = urlsplit(spec.get('base_url', ''))
    if url.scheme not in {'https', 'http'} or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Provider base_url must contain no credentials, query parameters or fragment')
    if url.hostname != options['provider_host']:
        raise ValueError('Pinned provider_host differs from the configured base URL')
    return options


def _limits(count, supplied, workload_budget=None):
    values = {'per_sample_mining_call_limit': 16, 'per_sample_matching_call_limit': 8,
              'per_sample_task_call_limit': 6, 'compact_validation_call_limit': 0,
              'aggregate_input_char_limit': count * 1_500_000,
              'reported_input_token_stop': count * 750_000,
              'timeout_seconds': 300, 'max_compact_request_chars': 400000,
              'max_response_chars': 60000, 'top_k': 2}
    supplied = supplied or {}
    if set(supplied) - set(values):
        raise ValueError('Unknown round limit; declare supported finite budgets explicitly')
    values.update(supplied)
    bounds = {'per_sample_mining_call_limit': (1, 16), 'per_sample_matching_call_limit': (0, 8),
              'per_sample_task_call_limit': (1, 6), 'compact_validation_call_limit': (0, 8),
              'aggregate_input_char_limit': (10000, 1000000000),
              'reported_input_token_stop': (1000, 1000000000), 'timeout_seconds': (1, 1800),
              'max_compact_request_chars': (10000, 1000000), 'max_response_chars': (1000, 120000),
              'top_k': (1, 10)}
    if workload_budget is not None:
        _verify_workload_budget(workload_budget)
        # Old rounds retain the original limits. A new explicit workload
        # contract can represent the measured plan rather than silently clamp
        # hundreds of blocks/BCs to the old 8/6-call prototype configuration.
        bounds.update(per_sample_mining_call_limit=(1, 10000),
                      per_sample_matching_call_limit=(0, 10000),
                      per_sample_task_call_limit=(1, 1000))
        expected = workload_budget['per_sample_call_caps']
        for phase in ('mining', 'matching', 'task'):
            if values['per_sample_' + phase + '_call_limit'] != expected[phase]:
                raise ValueError('Round call limit differs from the explicit workload contract: ' + phase)
    for key, (low, high) in bounds.items():
        if type(values[key]) is not int or not low <= values[key] <= high:
            raise ValueError('Round limit out of supported bounds: ' + key)
    return values


def _verify_workload_budget(value):
    if not isinstance(value, dict) or value.get('schema_version') != 'stability-workload-budget.v1':
        raise ValueError('Unknown workload budget contract')
    required = {'schema_version', 'scope_sha256', 'packing_profile', 'per_sample_call_caps',
                'ordinary_mining_call_cap', 'reserved_final_mining_calls',
                'task_synthesis_reserved_calls', 'measured_block_count', 'budget_id'}
    if set(value) != required:
        raise ValueError('Workload contract must explicitly bind scope, packing and phase reserves')
    body = {k:v for k,v in value.items() if k != 'budget_id'}
    if value['budget_id'] != fingerprint(body):
        raise ValueError('Workload budget identity changed')
    if not re.fullmatch(r'[0-9a-f]{64}', value['scope_sha256']):
        raise ValueError('Workload scope must have an exact digest')
    if value['packing_profile'] not in {'lossless-compact.v2','lossless-scoped-compact.v3'}:
        raise ValueError('Stability workload requires its explicitly measured packing profile')
    caps = value['per_sample_call_caps']
    if set(caps) != {'mining', 'matching', 'task'} or any(type(v) is not int or v < 0 for v in caps.values()):
        raise ValueError('Invalid workload phase caps')
    for key in ('ordinary_mining_call_cap', 'reserved_final_mining_calls',
                'task_synthesis_reserved_calls', 'measured_block_count'):
        if type(value[key]) is not int or value[key] < 0:
            raise ValueError('Invalid workload count: ' + key)
    if value['ordinary_mining_call_cap'] < value['measured_block_count']:
        raise ValueError('Every measured mining block needs an initial dispatch allowance')
    if caps['mining'] != value['ordinary_mining_call_cap'] + value['reserved_final_mining_calls']:
        raise ValueError('Mining phase must retain its separate final-review reserve')
    if caps['task'] < value['task_synthesis_reserved_calls']:
        raise ValueError('Task phase cannot represent its synthesis reserve')


def _history_binding(history):
    history = filesystem_path(history)
    rows, _, checked = load_history(history)
    relative_files = ['manifest.json', 'encoding/bc_vectors.npy', 'encoding/rows.json',
                      'encoding/audit/approved-pool.json', 'encoding/config.json',
                      'encoding/model-artifacts.json']
    files = {name: sha256_file(history / name) for name in relative_files}
    return {'history_snapshot': str(history), 'verification': checked,
            'manifest_and_index_files': files, 'bc_instances': [row['instance_ref'] for row in rows],
            'bc_count': len(rows), 'history_admission': 'Explicit independent freeze only; current queries do not update history'}


def freeze_round(samples, history, output, model_options=None, limits=None, *, matching_protocol='v1',mining_protocol='v1',task_definitions=None,defined_task_config=None,mining_config=None,workload_budget=None):
    """Create a fresh immutable setup for any nonempty list of real APK paths.

    Sample labels and counts have no relationship to the initial 3-BC baseline.
    Only identity/path/hash metadata is admitted from the input manifest; labels
    or report answers are not copied into inference configuration.
    """
    if mining_config is not None and mining_protocol!='current_facts.v1':
        raise ValueError('Explicit current-facts mining config requires its matching protocol')
    if defined_task_config is not None and task_definitions is None:
        raise ValueError('Typed task budgets require explicit task definitions')
    matching_model, matching_prompt = match_protocol({'schema_version': 'behavior-match-request.' + matching_protocol})
    if not isinstance(samples, list) or not samples:
        raise ValueError('A new round requires a nonempty APK sample list')
    output = filesystem_path(output); history = filesystem_path(history)
    if output.exists(): raise ValueError('Round output must be a fresh directory; frozen runs are not overwritten')
    if output == history or output.is_relative_to(history):
        raise ValueError('A query round cannot be created inside a frozen history snapshot')
    normalized = []; names = set(); hashes = set()
    for row in samples:
        if not isinstance(row, dict): raise ValueError('Each sample must be an object')
        name = row.get('sample_id', '')
        if not isinstance(name, str) or not _LABEL.fullmatch(name):
            raise ValueError('Sample ID must be a short directory label without separators')
        # Windows directory identity is case-insensitive even when tests run on
        # another OS; do not let two labels alias one sample output directory.
        if name.casefold() in names: raise ValueError('Duplicate sample directory label')
        names.add(name.casefold())
        source = row.get('apk_path', row.get('input_path'))
        if not isinstance(source, str) or not source: raise ValueError('Sample requires apk_path or input_path')
        apk = filesystem_path(source)
        if not apk.is_file(): raise ValueError('APK file does not exist: ' + source)
        digest = sha256_file(apk)
        expected = row.get('sha256', row.get('sha', row.get('apk_sha256', row.get('actual_sha256'))))
        if expected is not None and (not isinstance(expected, str) or expected.lower() != digest):
            raise ValueError('Supplied sample SHA-256 differs from actual APK bytes')
        if digest in hashes: raise ValueError('Duplicate APK content in one query round; deduplicate the sample list')
        hashes.add(digest)
        normalized.append({'sample_id': name, 'input_path': str(apk), 'apk_sha256': digest,
                           'bytes': apk.stat().st_size})
    pinned_model = _model_options(model_options)
    if workload_budget is not None and len(normalized)!=1:
        raise ValueError('Freeze each measured APK workload in its own bound child round')
    pinned_limits = _limits(len(normalized), limits, workload_budget)
    binding = _history_binding(history)
    if mining_protocol=='current_facts.v1':
        from androserum.encoding.models import EncodingConfig
        if read(history/'encoding/config.json')!=EncodingConfig(serializer_version='bc-semantics.v2').model_dump(mode='json'):
            raise ValueError('New current-facts rounds require an explicit compatible v2 history encoding; old history is retained')
    from .provider import mining_prompt as prompt_for_mining
    mining_prompt = prompt_for_mining(mining_protocol)
    mining_model = CurrentProposal if mining_protocol=='current_facts.v1' else Proposal
    schemas = {'mining': mining_model.model_json_schema(), 'matching': matching_model.model_json_schema(),
               'task': proposal_schema()}
    prompts = {'mining': mining_prompt, 'matching': matching_prompt, 'task': PROMPT,
               'compact_transport': COMPACT_INSTRUCTIONS}
    definitions=[]
    if task_definitions is not None:
        from .tasks import load_task_definition,task_proposal_schema,task_prompt
        definitions=[load_task_definition(d) for d in task_definitions]
        if not definitions or len({d.task_id for d in definitions})!=len(definitions):
            raise ValueError('Task definitions must be nonempty with unique task IDs')
        for index,definition in enumerate(definitions):
            key='defined-task-'+str(index)
            schemas[key]=task_proposal_schema(definition)
            prompts[key]=task_prompt(definition)
    config = {'schema_version': VERSION, 'created_utc': datetime.now(timezone.utc).isoformat(),
              'model_options': pinned_model, **pinned_limits,
              'call_limits': {'compact_validation': pinned_limits['compact_validation_call_limit'],
                              'mining': len(normalized) * pinned_limits['per_sample_mining_call_limit'],
                              'matching': len(normalized) * pinned_limits['per_sample_matching_call_limit'],
                              'task': len(normalized) * pinned_limits['per_sample_task_call_limit']},
              'samples': normalized, 'sample_selection_sha256': fingerprint(normalized),
              'history_snapshot': str(history), 'history_binding_sha256': fingerprint(binding),
              'history_manifest_sha256': binding['manifest_and_index_files']['manifest.json'],
              'history_pool_update': False, 'bert_changed': False, 'reviewed_freeze_role': 'query',
              'compact_instructions_sha256': fingerprint(COMPACT_INSTRUCTIONS),
              'matching_protocol': matching_protocol,
              'matching_prompt_sha256': fingerprint(matching_prompt), 'task_prompt_sha256': fingerprint(PROMPT),
              'mining_prompt_sha256': sha256_file(Path(__file__).parents[1] / 'mining/prompt.txt'),
              'schema_sha256': {key: fingerprint(value) for key, value in schemas.items()},
              'strict_schema_sha256': {key: fingerprint(strict_schema(value)) for key, value in schemas.items()},
              'token_stop_semantics': 'Stop new calls once reported cumulative input_tokens reaches the declared bound; one in-flight call may cross it. No monetary claim.',
              'primary_acceptance': 'Actual new APKs through fresh extraction, actual model mining, explicit per-round BC review/freeze, encoding, references and task report; evidence, omissions and cost reviewed separately.',
              'no_oracle_to_model': True, 'tests_are_regression_support_only': True,
              'model_changed_automatically': False, 'auth_handled_by_cli': True}
    policy = PipelineConfig()
    if workload_budget is not None:
        if mining_protocol != 'current_facts.v1':
            raise ValueError('Explicit stability workload requires current-facts mining')
        config['workload_budget'] = deepcopy(workload_budget)
        config['mining_packing_profile'] = workload_budget['packing_profile']
    if definitions:
        config['task_definitions']=[d.model_dump(mode='json') for d in definitions]
        config['task_definition_prompt_sha256']={d.task_id:fingerprint(prompts['defined-task-'+str(i)]) for i,d in enumerate(definitions)}
        config['task_definition_scope']={d.task_id:{'kind':d.kind,'blocked_reasons':d.blocked_reasons()} for d in definitions}
        from .tasks import DefinedTaskConfig
        from androserum.tasking.models import TaskConfig
        from androserum.facts.queries import FactQueryBudget
        definition_policy=(DefinedTaskConfig.model_validate(defined_task_config) if defined_task_config is not None else
            DefinedTaskConfig(ledger=TaskConfig(max_attempts=pinned_limits['per_sample_task_call_limit'],
                max_response_chars=pinned_limits['max_response_chars'],max_packet_chars=5000000),
                queries=FactQueryBudget(max_queries=policy.max_task_queries,max_records=32,max_return_chars=100000),
                max_model_calls=pinned_limits['per_sample_task_call_limit'],max_attempts_per_stage=2))
        if definition_policy.max_model_calls>pinned_limits['per_sample_task_call_limit']:
            raise ValueError('Task definition call limit exceeds the frozen sample task limit')
        if definition_policy.queries.max_queries>16:raise ValueError('Pipeline task query count exceeds its supported bound')
        policy.max_task_queries=definition_policy.queries.max_queries
        config['defined_task_config']=definition_policy.model_dump(mode='json')
        from .tasks import task_query_rules_binding
        config['task_query_rules_binding']=task_query_rules_binding()
    if mining_protocol == 'current_facts.v1':
        from androserum.encoding.models import EncodingConfig
        config['query_encoding_config']=EncodingConfig(serializer_version='bc-semantics.v2').model_dump(mode='json')
        config['mining_protocol']=mining_protocol
        config['effective_mining_prompt_sha256']=fingerprint(mining_prompt)
        config['bc_admission']='program_checked'
        config['analysis_profile']='method.v1'
        config['primary_acceptance']='Actual model BCs pass program checks, automatically continue; independent semantic evaluation is not an admission gate.'
        policy.mining=CurrentMiningConfig(max_request_chars=350000,max_chunk_chars=65000,
            max_ledger_context_chars=140000,max_supplement_rounds=2,max_supplement_records=16,
            max_queries_per_proposal=2,max_response_chars=60000,max_actions=256,max_bcs=128)
        if mining_config is not None:policy.mining=CurrentMiningConfig.model_validate(mining_config)
        config['effective_mining_policy']=policy.mining.model_dump(mode='json')
    if workload_budget is not None:
        if mining_config is not None and policy.mining.max_model_calls!=pinned_limits['per_sample_mining_call_limit']:
            raise ValueError('Explicit mining policy must represent the entire frozen workload and final reserve')
        policy.mining.max_model_calls=pinned_limits['per_sample_mining_call_limit']
    else:
        policy.mining.max_model_calls = min(policy.mining.max_model_calls,pinned_limits['per_sample_mining_call_limit'])
    policy.max_matches_per_sample = pinned_limits['per_sample_matching_call_limit']
    policy.max_task_attempts = pinned_limits['per_sample_task_call_limit']
    policy.top_k = pinned_limits['top_k']; policy.timeout_seconds = pinned_limits['timeout_seconds']
    policy.max_compact_request_chars = pinned_limits['max_compact_request_chars']
    policy.max_response_chars = pinned_limits['max_response_chars']
    policy.mining.max_response_chars = min(policy.mining.max_response_chars,pinned_limits['max_response_chars'])
    policy.mining.model_timeout_seconds = min(policy.mining.model_timeout_seconds,pinned_limits['timeout_seconds'])
    if mining_protocol == 'current_facts.v1':config['effective_mining_policy']=policy.mining.model_dump(mode='json')
    output.mkdir(parents=True, exist_ok=False)
    write(output / 'samples.json', normalized); write(output / 'history-binding.json', binding)
    write(output / 'pipeline-policy.json', policy.model_dump(mode='json'))
    write(output / 'experiment-config.json', config)
    for key, value in prompts.items():
        target = output / 'frozen-prompts' / (key + '.txt'); target.parent.mkdir(exist_ok=True)
        target.write_text(value, encoding='utf-8')
    for key, value in schemas.items(): write(output / 'frozen-schemas' / (key + '.json'), value)
    files = {str(p.relative_to(output)).replace('\\', '/'): sha256_file(p)
             for p in sorted(output.rglob('*')) if p.is_file()}
    write(output / 'round-manifest.json', {'schema_version': 'apk-pipeline-round-manifest.v1',
          'state': 'frozen_before_inference', 'round_id': fingerprint(files), 'files': files,
          'actual_model_calls_during_creation': 0})
    verify_round(output)
    return output


def verify_round(directory):
    """Verify frozen inputs and history binding without altering either package."""
    directory = filesystem_path(directory); manifest = read(directory / 'round-manifest.json')
    if manifest.get('schema_version') != 'apk-pipeline-round-manifest.v1' or manifest['round_id'] != fingerprint(manifest['files']):
        raise ValueError('Unknown/modified frozen round identity')
    for relative, digest in manifest['files'].items():
        path = filesystem_path(directory / relative)
        if not path.is_relative_to(directory) or sha256_file(path) != digest:
            raise ValueError('Frozen round material changed: ' + relative)
    config = read(directory / 'experiment-config.json'); binding = read(directory / 'history-binding.json')
    if config.get('workload_budget') is not None:
        _verify_workload_budget(config['workload_budget'])
        if config.get('mining_packing_profile') != config['workload_budget']['packing_profile']:
            raise ValueError('Frozen workload packing profile changed')
        for phase, cap in config['workload_budget']['per_sample_call_caps'].items():
            if config['per_sample_' + phase + '_call_limit'] != cap:
                raise ValueError('Frozen workload phase allowance changed')
        if config.get('effective_mining_policy',{}).get('max_model_calls')!=config['per_sample_mining_call_limit']:
            raise ValueError('Effective mining policy cannot represent the frozen complete workload')
    if config['history_binding_sha256'] != fingerprint(binding): raise ValueError('History binding changed')
    history = filesystem_path(config['history_snapshot'])
    for relative, digest in binding['manifest_and_index_files'].items():
        if sha256_file(history / relative) != digest: raise ValueError('Frozen history manifest or BC index changed')
    if config['samples'] != read(directory / 'samples.json'):
        raise ValueError('Frozen samples differ from the round configuration')
    matching_model, matching_prompt = match_protocol({'schema_version': 'behavior-match-request.' + config.get('matching_protocol', 'v1')})
    from .provider import mining_prompt as prompt_for_mining
    mining_model = CurrentProposal if config.get('mining_protocol')=='current_facts.v1' else Proposal
    current_schema = {'mining': mining_model.model_json_schema(), 'matching': matching_model.model_json_schema(),
                      'task': proposal_schema()}
    if config.get('task_definitions'):
        from .tasks import load_task_definition,task_proposal_schema,task_prompt,DefinedTaskConfig
        definitions=[load_task_definition(d) for d in config['task_definitions']]
        for index,definition in enumerate(definitions):current_schema['defined-task-'+str(index)]=task_proposal_schema(definition)
        if config.get('task_definition_prompt_sha256')!={d.task_id:fingerprint(task_prompt(d)) for d in definitions}:
            raise ValueError('Task definition prompts differ from frozen round')
        definition_policy=DefinedTaskConfig.model_validate(config['defined_task_config'])
        policy=read(directory/'pipeline-policy.json')
        if definition_policy.queries.max_queries!=policy['max_task_queries'] or definition_policy.max_model_calls>config['per_sample_task_call_limit']:
            raise ValueError('Defined task budget differs from the frozen pipeline policy')
        from .tasks import task_query_rules_binding
        if config.get('task_query_rules_binding')!=task_query_rules_binding():
            raise ValueError('Typed task query/checker rules differ from the frozen round')
    if config['schema_sha256'] != {k: fingerprint(v) for k, v in current_schema.items()}:
        raise ValueError('Current proposal schemas differ from the frozen round')
    if config['strict_schema_sha256'] != {k: fingerprint(strict_schema(v)) for k, v in current_schema.items()}:
        raise ValueError('Current strict transport schemas differ from the frozen round')
    if (config['matching_prompt_sha256'] != fingerprint(matching_prompt)
            or config['task_prompt_sha256'] != fingerprint(PROMPT)
            or config['compact_instructions_sha256'] != fingerprint(COMPACT_INSTRUCTIONS)
            or config['mining_prompt_sha256'] != sha256_file(Path(__file__).parents[1] / 'mining/prompt.txt')):
        raise ValueError('Current inference prompts differ from the frozen round')
    if config.get('mining_protocol') and config.get('effective_mining_prompt_sha256')!=fingerprint(prompt_for_mining(config['mining_protocol'])):
        raise ValueError('Current structured fact-query mining prompt differs from frozen round')
    if config.get('effective_mining_policy') and config['effective_mining_policy']!=read(directory/'pipeline-policy.json')['mining']:
        raise ValueError('Effective mining policy differs from the frozen round')
    if 'query_encoding_config' in config:
        from androserum.encoding.models import EncodingConfig
        encoding=EncodingConfig.model_validate(config['query_encoding_config'])
        if encoding.model_dump(mode='json')!=config['query_encoding_config']:
            raise ValueError('Frozen query encoding configuration is incomplete or modified')
        if read(history/'encoding/config.json')!=config['query_encoding_config']:
            raise ValueError('Frozen query/history encoding profiles differ')
    for row in config['samples']:
        if sha256_file(row['input_path']) != row['apk_sha256']:
            raise ValueError('Frozen APK bytes changed: ' + row['sample_id'])
    return {'valid': True, 'round_id': manifest['round_id'], 'sample_count': len(config['samples']),
            'historical_bc_count': binding['bc_count'], 'actual_model_calls': 0}


__all__ = ['freeze_round', 'verify_round']
