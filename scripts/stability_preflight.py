"""Measure a new complete, losslessly packed scope before any model dispatch."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from androserum.facts.identity import filesystem_path, fingerprint, sha256_file
from androserum.inference.provider import write
from androserum.mining.models import CurrentMiningConfig
from androserum.pipeline.workplan import discover_plan
from androserum.pipeline.workload_planning import scope_readiness, mining_budget, final_review_budget, downstream_budgets
from androserum.mining_packing import PROFILE, catalog_for


def read(path):return json.loads(filesystem_path(path).read_text('utf-8'))


def measure(directory, output, *, packing_profile=PROFILE):
    directory=filesystem_path(directory);output=filesystem_path(output)
    prepared=read(directory/'prepared.json')
    collection=read(filesystem_path(prepared['bu_package'])/'collection.json')
    identity={k:prepared[k] for k in ('apk_sha256','source_run_ref','snapshot','bu_package')}
    identity.update(prepared_sha256=sha256_file(directory/'prepared.json'),
        bu_manifest_sha256=sha256_file(filesystem_path(prepared['bu_package'])/'manifest.json'))
    config=CurrentMiningConfig(max_bu=100000,max_chunks=1000000,max_chunk_chars=65000,
        max_ledger_context_chars=140000,max_request_chars=350000,max_model_calls=10000,
        max_supplement_rounds=16,max_supplement_records=128,max_queries_per_proposal=2,
        max_query_return_chars=250000,max_actions=4096,max_bcs=256)
    print(json.dumps({'sample':directory.name,'state':'measuring_complete_scope',
        'contexts':collection['selection']['contextual_anchors'],'units':len(collection['units'])}),flush=True)
    plan=discover_plan(prepared,read(directory/'sapi-matches.json'),collection,config,packing_profile=packing_profile)
    blocks=[x for x in plan['items'] if x['kind']=='block']
    atoms=[x for x in plan['items'] if x['kind']=='unpackable_evidence']
    scope=scope_readiness(discovered_contexts=collection['selection']['contextual_anchors'],
        materialized_contexts=len(collection['units']),blocks=len(blocks),unpackable_atoms=len(atoms),
        pending_roots=len(collection['selection']['pending_roots'])+len(prepared.get('unprocessed_roots',[])),
        failed_contexts=len(collection['selection']['graph_failures']))
    supplemental=min(16,max(4,(len(blocks)+3)//4)) if blocks else 0
    budget=mining_budget(len(blocks),repairs_per_block=1,supplement_review_rounds=supplemental)
    result={'schema_version':'stability-complete-scope-preflight.v1','created_utc':datetime.now(timezone.utc).isoformat(),
        'identity':identity,'scope':scope,'plan_id':plan['plan_id'],'packing_profile':packing_profile,
        'packing_rule_sha256':plan.get('packing_rule_sha256'),'complete_block_count':len(blocks),
        'unpackable_atom_count':len(atoms),'mining_config':config.model_dump(mode='json'),
        'ordinary_mining_budget':budget,
        'post_BU_review':final_review_budget(),
        'downstream':downstream_budgets(bc_upper_bound=config.max_bcs),
        'preflight_is_not_frozen_model_budget':True,'actual_BC_and_issue_frontiers_not_yet_known':True,
        'new_model_calls':0,'new_static_solver_runs':0,'dispatch_authorized':False}
    output.mkdir(parents=True,exist_ok=True)
    existing=output/'scope.json'
    if existing.exists():
        old=read(existing)
        if (old['identity']!=identity or old['plan_id']!=plan['plan_id'] or
                old.get('packing_rule_sha256')!=plan.get('packing_rule_sha256')):
            raise ValueError('Scope changed; retain the prior preflight and use a new output')
        print(json.dumps({'sample':directory.name,'state':'retained_preflight','blocks':len(blocks)}),flush=True)
        return old
    write(output/'complete-plan.json',plan);write(existing,result)
    print(json.dumps({'sample':directory.name,'state':scope['state'],'blocks':len(blocks),
        'unpackable_atoms':len(atoms),'ordinary_mining_call_cap':budget['max_calls'],
        'new_model_calls':0,'scope_sha256':sha256_file(existing)}),flush=True)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared-root',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--sample',action='append')
    parser.add_argument('--packing-profile',default=PROFILE,
        choices=(PROFILE,'lossless-scoped-compact.v3'))
    args=parser.parse_args()
    root=filesystem_path(args.prepared_root);out=filesystem_path(args.output)
    cases=args.sample or [p.name for p in (root/'samples').iterdir() if (p/'prepared.json').is_file()]
    for label in cases:
        if Path(label).name!=label:raise ValueError('Invalid sample label')
        measure(root/'samples'/label,out/label,packing_profile=args.packing_profile)


if __name__=='__main__':main()
