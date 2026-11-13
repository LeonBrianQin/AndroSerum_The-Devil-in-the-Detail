import pytest
from androserum.pipeline.provider import PipelineBudget


def policy():
    return {'call_limits':{'mining':3},'per_sample_mining_call_limit':1,
            'aggregate_input_char_limit':250,'reported_input_token_stop':1000}


def test_sample_and_inflight_input_reservations_survive_resume(tmp_path):
    path=tmp_path/'budget';b=PipelineBudget(path,policy());b.stage('a',100);b.reserve('mining','a:0');b.close()
    b=PipelineBudget(path,policy());b.stage('a',1)
    with pytest.raises(ValueError,match='per-sample'):b.reserve('mining','a:1')
    b.stage('b',100);b.reserve('mining','b:0');b.stage('c',51)
    with pytest.raises(ValueError,match='input reservation'):b.reserve('mining','c:0')
    assert len(b.report()['calls'])==2;b.close()


def test_reservation_is_bound_to_the_sample_label(tmp_path):
    b=PipelineBudget(tmp_path/'budget',policy());b.stage('a',100)
    with pytest.raises(ValueError,match='identity'):b.reserve('mining','b:0')
    assert not b.report()['calls'];b.close()
