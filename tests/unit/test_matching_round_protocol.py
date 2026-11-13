"""New rounds explicitly select v2; omission retains the v1 baseline."""
import json

import pytest

from androserum.facts.identity import sha256_file, fingerprint
from androserum.inference.matching import MATCH_PROMPT, MATCH_PROMPT_V2
from androserum.matching.models import MatchProposal, MatchProposalV2
from androserum.pipeline import rounds


@pytest.mark.parametrize('protocol', ['v1', 'v2'])
def test_round_freezes_the_explicit_matching_schema_and_prompt(tmp_path, monkeypatch, protocol):
    apk = tmp_path/'identity-control.apk'; apk.write_bytes(b'Identity-only protocol fixture; never parsed or executed.')
    history = tmp_path/'history'; history.mkdir(); manifest = history/'manifest.json'; manifest.write_text('{}', encoding='utf-8')
    monkeypatch.setattr(rounds, '_model_options', lambda value: {'model': 'protocol-control-never-invoked'})
    monkeypatch.setattr(rounds, '_history_binding', lambda value: {'history_snapshot': str(history),
        'manifest_and_index_files': {'manifest.json': sha256_file(manifest)}, 'bc_instances': [], 'bc_count': 0})
    options = {'matching_protocol': 'v2'} if protocol == 'v2' else {}
    directory = rounds.freeze_round([{'sample_id': 'control', 'apk_path': str(apk)}], history,
                                   tmp_path/('round-'+protocol), **options)
    config = json.loads((directory/'experiment-config.json').read_text('utf-8'))
    assert config['matching_protocol'] == protocol
    model, prompt = (MatchProposalV2, MATCH_PROMPT_V2) if protocol == 'v2' else (MatchProposal, MATCH_PROMPT)
    assert config['matching_prompt_sha256'] == fingerprint(prompt)
    assert config['schema_sha256']['matching'] == fingerprint(model.model_json_schema())
    assert rounds.verify_round(directory)['actual_model_calls'] == 0
