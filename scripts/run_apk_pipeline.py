"""APK-parametric Method mainline; semantic review is an explicit optional mode."""
import argparse,json
from pathlib import Path
from androserum.pipeline.runner import run_apk,freeze_mined,freeze_automined

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--sample',required=True)
    p.add_argument('--apk');p.add_argument('--sapi');p.add_argument('--review');p.add_argument('--freeze');p.add_argument('--history')
    p.add_argument('--analysis-profile',choices=['bounded.v1','method.v1'])
    p.add_argument('--flow-config',help='Explicit selected-flow v1/v2/v3 JSON for fresh preparation only')
    p.add_argument('--admission',choices=['program_checked','explicit_semantic_review'],default='program_checked')
    p.add_argument('--freeze-only',action='store_true');a=p.parse_args()
    if (a.freeze_only or a.freeze) and (a.analysis_profile is not None or a.flow_config is not None):
        p.error('Preparation profile/flow options require fresh preparation, without --freeze or --freeze-only')
    if a.freeze_only:
        if a.review:result=freeze_mined(a.root,a.sample,a.review)
        elif a.admission=='program_checked':result=freeze_automined(a.root,a.sample)
        else:p.error('Explicit semantic-review admission requires --review')
        print(str(result));return
    if not a.apk:p.error('--apk required')
    if not a.freeze and not a.sapi:p.error('--sapi required for fresh preparation without --freeze')
    if a.freeze and a.review:p.error('Choose --freeze or --review')
    options={}
    if a.admission!='program_checked':options['admission']=a.admission
    if a.analysis_profile is not None:options['analysis_profile']=a.analysis_profile
    if a.flow_config is not None:options['flow_config']=json.loads(Path(a.flow_config).read_text('utf-8'))
    print(json.dumps(run_apk(a.apk,a.root,a.sample,a.sapi,review_file=a.review,freeze=a.freeze,history=a.history,**options),ensure_ascii=False,default=str))

if __name__=='__main__':main()
