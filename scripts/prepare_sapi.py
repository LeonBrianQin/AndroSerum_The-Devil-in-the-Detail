"""Inventory pinned local FlowDroid resources without creating a formal SAPI catalog."""
from datetime import datetime,timedelta,timezone
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def classify_roles(text):
    entries,unparsed=[],[]
    for number,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line or line.startswith(('#','%','//')):continue
        match=re.fullmatch(r'(<.+>)\s*->\s*(_SOURCE_|_SINK_|_BOTH_|_NONE_)',line)
        if not match:
            unparsed.append({'line':number,'content':line,'reason':'Not a supported tagged source/sink line'})
            continue
        roles={'_SOURCE_':['source'],'_SINK_':['sink'],'_BOTH_':['source','sink'],'_NONE_':[]}[match[2]]
        entries.append({'line':number,'raw_soot_signature':match[1],'roles':roles,
                        'anchor_candidate_after_normalization':'source' in roles,'formal_anchor':False})
    return entries,unparsed


def main():
    stamp=datetime.now(timezone(timedelta(hours=8)));key=stamp.strftime('%Y%m%d_%H%M%S_%f')
    output=ROOT/'artifacts/sapi-preparation'/key;output.mkdir(parents=True,exist_ok=False)
    policy=json.loads((ROOT/'configs/sapi-source-policy.json').read_text('utf-8'))
    report={'schema_version':'sapi-preparation.v1','status':'partial','checked_at':stamp.isoformat(timespec='seconds'),
            'formal_anchor_catalog_ready':False,'policy':policy,'resources':[],'outputs':{},
            'limits':['Inventory and role classification only; no signature normalization, matching, permissions or cryptographic rules imported',
                      'Bundled SourcesAndSinks contains mixed ecosystems; Android scope and coverage require explicit review']}
    specs=[('soot-infoflow-android','SourcesAndSinks.txt','source_sink_configuration'),
           ('soot-infoflow','EasyTaintWrapperSource.txt','propagation_summary'),
           ('soot-infoflow-android','AndroidCallbacks.txt','callback_model')]
    for artifact,entry,role in specs:
        jar=ROOT/f'.tools/m2/de/fraunhofer/sit/sse/flowdroid/{artifact}/2.15.1/{artifact}-2.15.1.jar'
        if not jar.is_file():
            report['resources'].append({'artifact':artifact,'version':'2.15.1','entry':entry,'state':'unavailable','role':role})
            continue
        with zipfile.ZipFile(jar) as archive:data=archive.read(entry)
        target=output/entry;target.write_bytes(data)
        report['resources'].append({'artifact':artifact,'version':'2.15.1','maven_coordinate':f'de.fraunhofer.sit.sse.flowdroid:{artifact}:2.15.1',
            'jar':jar.relative_to(ROOT).as_posix(),'jar_sha256':hashlib.sha256(jar.read_bytes()).hexdigest(),
            'entry':entry,'entry_sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),'role':role,
            'state':'inventoried','copy':target.relative_to(ROOT).as_posix(),'automatic_bu_anchor':False})
        if role=='source_sink_configuration':
            entries,unparsed=classify_roles(data.decode('utf-8-sig'))
            classified={'schema_version':'flowdroid-role-inventory.v1','version':'2.15.1','entries':entries,'unparsed':unparsed}
            path=output/'flowdroid-entry-roles.json';path.write_text(json.dumps(classified,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            report['outputs']['role_inventory']=path.relative_to(ROOT).as_posix()
            report['role_counts']={role:sum(role in x['roles'] for x in entries) for role in ['source','sink']}
            report['unparsed_lines']=len(unparsed)
    path=ROOT/'docs/evidence'/f'sapi_preparation_{key}.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'report':path.relative_to(ROOT).as_posix(),'status':report['status'],
                      'role_counts':report.get('role_counts',{}),'formal_anchor_catalog_ready':False}))
    return 0


if __name__=='__main__':raise SystemExit(main())
