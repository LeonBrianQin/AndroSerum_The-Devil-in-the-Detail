"""Immutable fixed-response protocol runs; rejection preserves accepted state."""
from pathlib import Path
from uuid import uuid4
from copy import deepcopy
from androserum.facts.identity import filesystem_path,sha256_file,fingerprint
from androserum.encoding.runner import write
from .checker import check_match
from .models import MatchConfig


def run_fixed(request,responses,output,config=None):
    config=config or MatchConfig();run=filesystem_path(output)/('match_'+uuid4().hex);run.mkdir(parents=True,exist_ok=False)
    write(run/'request.json',request);write(run/'config.json',config.model_dump(mode='json'))
    accepted=None;attempts=[]
    for i,raw in enumerate(responses[:config.max_pair_attempts]):
        before=fingerprint(accepted);check=check_match(raw,request,config)
        base=run/'attempts'/str(i);base.mkdir(parents=True)
        (base/'response.txt').write_text(raw,encoding='utf-8');write(base/'check.json',check)
        if check['valid']:accepted=deepcopy(check['accepted'])
        attempts.append({'index':i,'valid':check['valid'],'accepted_before_sha256':before,'accepted_after_sha256':fingerprint(accepted),
            'rejected_update_preserved_state':True if check['valid'] else fingerprint(accepted)==before})
    write(run/'accepted.json',accepted)
    report={'schema_version':'fixed-match-protocol-run.v1','attempts':attempts,'accepted':accepted,
        'pending_responses':max(0,len(responses)-config.max_pair_attempts),'budget_exhausted':len(responses)>config.max_pair_attempts,
        'provider':'fixed_responses_only','generative_llm_calls':0,'actual_llm_matching_quality_evaluated':False,
        'request_sha256':sha256_file(run/'request.json')}
    write(run/'report.json',report)
    for source in [*Path(__file__).parent.glob('*.py'),*Path(__file__).parent.glob('*.txt')]:
        (run/'rules').mkdir(exist_ok=True);(run/'rules'/source.name).write_bytes(source.read_bytes())
    files={str(p.relative_to(run)).replace('\\','/'):{'sha256':sha256_file(p),'bytes':p.stat().st_size} for p in run.rglob('*') if p.is_file()}
    write(run/'manifest.json',{'schema_version':'behavior-match-run.v1','state':'published','files':files})
    return run,report
