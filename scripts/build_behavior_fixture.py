"""Compile the inert resource-backed identity logging acceptance APK."""
from pathlib import Path
import hashlib,json,subprocess,zipfile
ROOT=Path(__file__).resolve().parents[1]


def main():
    source=ROOT/'tests/fixtures/behavior_progress';out=ROOT/'artifacts/fixtures/behavior-progress'
    build=ROOT/'.tools/android-sdk/build-tools/35.0.0';jdk=ROOT/'.tools/jdk-17/bin';platform=ROOT/'.tools/android-sdk/platforms/android-28/android.jar'
    for name in ['classes','generated','dex']:(out/name).mkdir(parents=True,exist_ok=True)
    commands=[]
    def run(args):
        p=subprocess.run([str(a) for a in args],cwd=ROOT,capture_output=True,timeout=90)
        commands.append({'argv':[str(a) for a in args],'exit_code':p.returncode,'stdout':p.stdout.decode('utf-8',errors='replace'),'stderr':p.stderr.decode('utf-8',errors='replace')})
        if p.returncode:raise RuntimeError(commands[-1]['stderr'])
        return p.stdout
    run([build/'aapt2.exe','compile','--dir',source/'res','-o',out/'resources.zip'])
    run([build/'aapt2.exe','link','--manifest',source/'AndroidManifest.xml','-I',platform,out/'resources.zip','--java',out/'generated','--output-text-symbols',out/'R.txt','-o',out/'base.apk'])
    run([jdk/'javac.exe','--release','8','-classpath',platform,'-d',out/'classes',*sorted(source.glob('*.java')),*sorted((out/'generated').rglob('*.java'))])
    run([jdk/'java.exe','-cp',build/'lib/d8.jar','com.android.tools.r8.D8','--debug','--lib',platform,'--min-api','16','--output',out/'dex',*sorted((out/'classes').rglob('*.class'))])
    with zipfile.ZipFile(out/'base.apk') as z:files={n:z.read(n) for n in z.namelist() if not n.endswith('/')}
    files['classes.dex']=(out/'dex/classes.dex').read_bytes()
    with zipfile.ZipFile(out/'valid.apk','w',zipfile.ZIP_DEFLATED) as z:
        for n,data in sorted(files.items()):
            info=zipfile.ZipInfo(n,(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data)
    (out/'dexdump.txt').write_bytes(run([build/'dexdump.exe','-d','-f',out/'dex/classes.dex']))
    (out/'build.json').write_text(json.dumps({'commands':commands,'apk_sha256':hashlib.sha256((out/'valid.apk').read_bytes()).hexdigest(),
        'source_sha256':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}},indent=2)+'\n',encoding='utf-8')
    print(out/'valid.apk')


if __name__=='__main__':main()
