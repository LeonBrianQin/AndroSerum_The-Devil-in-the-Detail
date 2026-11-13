"""Explicitly resume BU construction from one identified immutable fact snapshot."""
import argparse
import json
from pathlib import Path
from uuid import uuid4
from datetime import datetime,timezone
from androserum.facts.identity import filesystem_path,sha256_file
from androserum.pipeline.prepare import recover_fact_preparation
from androserum.pipeline.config import PipelineConfig
from androserum.pipeline.workplan import discover_plan
from androserum.inference.provider import write


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--output',required=True);p.add_argument('--sapi',required=True)
    p.add_argument('--snapshot',required=True);p.add_argument('--snapshot-id',required=True)
    args=p.parse_args();out=filesystem_path(args.output)
    attempt=out/('recovery-attempt-'+uuid4().hex+'.json')
    write(attempt,{'started_utc':datetime.now(timezone.utc).isoformat(),'snapshot':args.snapshot,
        'snapshot_id':args.snapshot_id,'new_static_solver_runs':0,'new_model_calls':0})
    result=recover_fact_preparation(out,args.sapi,args.snapshot,expected_snapshot_id=args.snapshot_id)
    config=PipelineConfig.model_validate_json((out/'config.json').read_text('utf-8'))
    collection=json.loads((filesystem_path(result['bu_package'])/'collection.json').read_text('utf-8')) if result['bu_package'] else None
    plan=discover_plan(result,json.loads((out/'sapi-matches.json').read_text('utf-8')),collection,config.mining)
    write(out/'complete-candidate-plan.json',plan)
    write(out/'recovery-final.json',{'prepared':str(out/'prepared.json'),'snapshot_id':args.snapshot_id,
        'source_database_sha256':sha256_file(filesystem_path(args.snapshot)/'facts.sqlite'),
        'physical_anchors':result['physical_sapi_calls'],'roots':len(result['available_sapi_roots']),
        'bu_count':result['bu_count'],'blocks':sum(i['kind']=='block' for i in plan['items']),
        'elapsed_seconds':result['recovery_elapsed_seconds'],'new_static_solver_runs':0,'new_model_calls':0})
    print(json.dumps(json.loads((out/'recovery-final.json').read_text('utf-8')),ensure_ascii=False),flush=True)


if __name__=='__main__':main()
