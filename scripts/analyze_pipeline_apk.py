"""Run a reviewed new APK freeze through encoding, references and task analysis."""
import argparse
import json
from androserum.pipeline.analyze import analyze_apk


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--sample', required=True)
    parser.add_argument('--freeze', required=True)
    parser.add_argument('--history', required=True)
    parser.add_argument('--model-dir')
    parser.add_argument('--lock', default='configs/bert-artifacts.lock.json')
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--task-segment-call-limit',type=int)
    args = parser.parse_args()
    report = analyze_apk(args.root, args.sample, args.freeze, args.history,
                         model_dir=args.model_dir, lock_path=args.lock,resume=args.resume,
                         task_segment_call_limit=args.task_segment_call_limit)
    print(json.dumps({'sample_id': args.sample, 'status': report['status'],
                      'program_qualified_bc_count': report.get('program_qualified_bc_count',report.get('approved_bc_count')), 'cost': report.get('cost')},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__': main()
