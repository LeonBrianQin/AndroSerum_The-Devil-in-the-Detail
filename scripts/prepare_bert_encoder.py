"""Download only pinned public BERT data files; verify git/LFS hashes."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import hashlib,json,time,urllib.request

ROOT=Path(__file__).resolve().parents[1]


def main():
    lock=json.loads((ROOT/'configs/bert-artifacts.lock.json').read_text('utf-8'))
    dest=ROOT/'.models/bert-base-uncased'/lock['revision'];dest.mkdir(parents=True,exist_ok=True)
    def verified(path,item):
        if not path.is_file() or path.stat().st_size!=item['bytes']:return False
        raw=path.read_bytes()
        if item.get('sha256') and hashlib.sha256(raw).hexdigest()!=item['sha256']:return False
        return hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==item['git_blob_sha1'] if 'sha256' not in item else True
    def fetch(pair):
        name,item=pair;path=dest/name
        if not verified(path,item):
            partial=path.with_suffix(path.suffix+'.partial')
            url='https://huggingface.co/'+lock['repository']+'/resolve/'+lock['revision']+'/'+name+'?download=true&task='+str(time.time_ns())
            error=None
            for attempt in range(3):
                try:
                    with urllib.request.urlopen(url,timeout=60) as source,partial.open('wb') as out:
                        while block:=source.read(1024*1024):out.write(block)
                    if not verified(partial,item):raise ValueError('Downloaded bytes do not match pinned upstream hash: '+name)
                    partial.replace(path);error=None;break
                except Exception as current:error=current
            if error:raise error
        result={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size,'git_blob_sha1':item['git_blob_sha1']}
        print(name,result['bytes'],result['sha256'],flush=True);return name,result
    with ThreadPoolExecutor(max_workers=3) as executor:files=dict(executor.map(fetch,lock['files'].items()))
    manifest={**lock,'local_files':files,'remote_code_executed':False}
    (dest/'model-artifacts.json').write_text(json.dumps(manifest,indent=2)+'\n','utf-8')
    print(dest)


if __name__=='__main__':main()
