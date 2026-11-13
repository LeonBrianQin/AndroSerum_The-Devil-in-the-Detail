"""Expose exact proposed claims and DEX context for separate code inspection."""
import argparse,json,re,subprocess,zipfile
from pathlib import Path
from androserum.facts.identity import filesystem_path
from androserum.facts.store import FactView
from androserum.mining.evidence import EvidenceCatalog
ROOT=Path(__file__).resolve().parents[1]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('case',type=Path);args=p.parse_args();case=args.case
    a=json.loads((case/'prepared.json').read_text('utf-8'))
    paths=[(p,json.loads(p.read_text('utf-8'))) for p in (case/'model-runs').glob('*/report.json')]
    path,r=max(paths,key=lambda x:(x[1]['budgets']['model_calls'],x[1]['accepted_state']['revision']))
    collection=json.loads((filesystem_path(a['bu_package'])/'collection.json').read_text('utf-8'));c=EvidenceCatalog(collection,a['selected_bu_ids'])
    records={r['id']:r for u in c.units.values() for r in u['model_visible']['records']}
    methods={c.entries[h]['method_ref'] for action in r['accepted_state']['actions'].values() for h in action['operation_refs']}
    raw={ref:{'signature':records[ref]['signature'],'scope':'BU model-visible instruction context; full context in independent dexdump',
        'instructions':[x for x in records.values() if x.get('kind')=='instruction' and x['position']['method_ref']==ref]} for ref in methods}
    result={'case':a['case'],'apk_sha256':a['apk_sha256'],'mining_run':str(path.parent),'actions':[],
        'bcs':{k:{i:b[i] for i in ['description','action_ids','relations','boundary','limitation_notes']} for k,b in r['accepted_state']['bcs'].items()},
        'unresolved':r['accepted_state']['unresolved'],'raw_method_context':raw,'reviewer_kind':'assistant_code_inspection','independent_human_annotators':0}
    for key,action in r['accepted_state']['actions'].items():
        result['actions'].append({'id':key,'claims':{k:action[k] for k in ['function','objects','inputs','outputs','limitation_notes']},
            'program_operations':[c.entries[h] for h in action['operation_refs']]})
    (case/'review-inputs.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    out=case/'independent-dexdump';out.mkdir(exist_ok=False)
    with zipfile.ZipFile(case/'input.apk') as archive:
        for name in archive.namelist():
            if re.fullmatch(r'classes\d*\.dex',name):
                dex=out/name;dex.write_bytes(archive.read(name))
                process=subprocess.run([str(ROOT/'.tools/android-sdk/build-tools/35.0.0/dexdump.exe'),'-d','-f',str(dex)],capture_output=True,timeout=60)
                (out/(name+'.stdout.txt')).write_bytes(process.stdout);(out/(name+'.stderr.txt')).write_bytes(process.stderr)
                if process.returncode:raise ValueError('Independent dexdump failed')
    print(case/'review-inputs.json')


if __name__=='__main__':main()
