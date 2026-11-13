"""Prepare any APK, without a hard-coded fixture or generative call."""
import argparse,json
from pathlib import Path
from androserum.pipeline.prepare import prepare_apk
from androserum.pipeline.config import PipelineConfig

def main():
    p=argparse.ArgumentParser();p.add_argument('--apk',required=True);p.add_argument('--output',required=True)
    p.add_argument('--sapi',required=True);p.add_argument('--config')
    p.add_argument('--analysis-profile',choices=['bounded.v1','method.v1'])
    p.add_argument('--flow-config',help='Explicit selected-flow v1/v2/v3 JSON; bound to this preparation')
    p.add_argument('--reference-input',action='store_true',help='Read the original APK without copying; bind its path and hash')
    a=p.parse_args()
    c=PipelineConfig.model_validate_json(Path(a.config).read_text('utf-8')) if a.config else PipelineConfig()
    options={}
    if a.analysis_profile is not None:options['analysis_profile']=a.analysis_profile
    if a.flow_config is not None:options['flow_config']=json.loads(Path(a.flow_config).read_text('utf-8'))
    if a.reference_input:options['reference_input']=True
    print(json.dumps(prepare_apk(a.apk,a.output,a.sapi,c,**options),ensure_ascii=False))

if __name__=='__main__':main()
