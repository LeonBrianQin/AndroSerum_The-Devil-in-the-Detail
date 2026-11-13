"""Use the actual BU/mining service for any prepared APK under a frozen round."""
import argparse,json
from pathlib import Path
from androserum.pipeline.runner import mine_prepared

def main():
    p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--sample',required=True)
    p.add_argument('--resume',action='store_true');p.add_argument('--segment-call-limit',type=int);a=p.parse_args()
    print(json.dumps(mine_prepared(a.root,a.sample,resume=a.resume,call_limit=a.segment_call_limit),ensure_ascii=False))
if __name__=='__main__':main()
