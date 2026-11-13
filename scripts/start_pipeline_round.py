"""Freeze a fresh bounded round from an arbitrary actual APK manifest."""
import argparse
import json
from pathlib import Path
from androserum.pipeline.rounds import freeze_round, verify_round


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', required=True, help='JSON list of sample_id and apk_path/input_path, optional SHA-256')
    parser.add_argument('--history', required=True)
    parser.add_argument('--output', required=True, help='Fresh directory; existing rounds are never overwritten')
    parser.add_argument('--limits', help='Optional JSON object of lower per-sample/round limits')
    parser.add_argument('--matching-protocol', choices=['v1', 'v2', 'v3'], default='v3',
                        help='v3 uses English decisions and typed paths; v1/v2 preserve historical wire contracts')
    parser.add_argument('--mining-protocol',choices=['v1','current_facts.v1'],default='v1')
    parser.add_argument('--tasks',help='JSON list of independently versioned task definitions')
    parser.add_argument('--mining-config',help='Explicit current-facts MiningConfig JSON; frozen before dispatch')
    parser.add_argument('--defined-task-config',help='Explicit typed task ledger/query/retry budget JSON')
    args = parser.parse_args()
    samples = json.loads(Path(args.samples).read_text('utf-8-sig'))
    limits = json.loads(Path(args.limits).read_text('utf-8-sig')) if args.limits else None
    definitions=json.loads(Path(args.tasks).read_text('utf-8-sig')) if args.tasks else None
    extra={}
    if args.mining_config:extra['mining_config']=json.loads(Path(args.mining_config).read_text('utf-8-sig'))
    if args.defined_task_config:extra['defined_task_config']=json.loads(Path(args.defined_task_config).read_text('utf-8-sig'))
    output = freeze_round(samples, args.history, args.output, limits=limits, matching_protocol=args.matching_protocol,
                          mining_protocol=args.mining_protocol,task_definitions=definitions,**extra)
    print(json.dumps({'round': str(output), **verify_round(output)}, ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
