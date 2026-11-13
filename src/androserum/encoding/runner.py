"""Frozen approved BCs only; publish new, separately auditable encoding runs."""
from datetime import datetime,timezone
import json,sqlite3,shutil
from pathlib import Path
from uuid import uuid4
from androserum.facts.identity import filesystem_path,sha256_file,fingerprint
from .models import EncodingConfig
from .semantic import serialize_entry
from .bert import BertEncoder,chunk_records,aggregate


def read(path):return json.loads(filesystem_path(path).read_text('utf-8'))


def write(path,value):
    path=filesystem_path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2,allow_nan=False)+'\n',encoding='utf-8')


def load_frozen(policy_path,root):
    root=filesystem_path(root);policy=read(policy_path)
    if policy['schema_version']!='p4b-frozen-inputs.v1':raise ValueError('Unknown freeze policy')
    pool_path=root/policy['approved_pool'];review_path=root/policy['review']
    if sha256_file(pool_path)!=policy['pool_sha256'] or sha256_file(review_path)!=policy['review_sha256']:
        raise ValueError('Frozen pool/review hash differs')
    pool=read(pool_path);review=read(review_path);entries=pool['entries']
    if review['status']!='passed' or not review['ready_for_p4b']:raise ValueError('P4A exit has not approved encoding')
    refs=[e['qualified_ref'] for e in entries]
    if len(refs)!=3 or len(set(refs))!=3 or refs!=policy['qualified_refs']:raise ValueError('Only the three frozen approved entries are allowed')
    if refs!=[e['qualified_ref'] for e in review['qualified_bcs']]:raise ValueError('Pool differs from exit review')
    if len(review['candidates'])!=policy['excluded_candidate_count'] or policy['excluded_candidate_count']!=10:
        raise ValueError('Excluded candidate inventory differs')
    for entry in entries:
        if fingerprint(entry)!=policy['entry_sha256'][entry['qualified_ref']]:raise ValueError('Approved native entry changed')
        if entry['qualification']['program_check']!='passed':raise ValueError('Unapproved BC')
    return policy,pool,entries


def source_backlink(entry):
    """Read the exact ledger revision without changing the source SQLite file."""
    run=filesystem_path(entry['source_mining_run']);manifest=read(run/'manifest.json')
    if sha256_file(run/'manifest.json')!=entry['source_mining_manifest_sha256']:raise ValueError('Source mining manifest changed')
    for name,item in manifest['files'].items():
        path=filesystem_path(run/name)
        if not path.is_relative_to(run) or sha256_file(path)!=item['sha256']:raise ValueError('Source mining file changed: '+name)
    # Windows extended filesystem prefix is not a URI authority.
    ledger_uri=Path(str(run/'ledger.sqlite').removeprefix('\\\\?\\')).as_uri()
    db=sqlite3.connect(ledger_uri+'?mode=ro&immutable=1',uri=True)
    try:
        row=db.execute('SELECT payload,sha256 FROM versions WHERE revision=?',(entry['ledger_revision'],)).fetchone()
    finally:db.close()
    if row is None or fingerprint(json.loads(row[0]))!=row[1]:raise ValueError('Missing or altered ledger revision')
    state=json.loads(row[0]);bc=entry['bc'];bc_id=bc['bc_id']
    if any(state['bcs'][bc_id].get(k)!=v for k,v in bc.items() if k in state['bcs'][bc_id]):raise ValueError('BC differs from source ledger')
    for key,a in entry['actions'].items():
        if any(state['actions'][key].get(k)!=v for k,v in a.items() if k in state['actions'][key]):raise ValueError('Action differs from ledger')
    sources={}
    for role,key in [('snapshot','source_snapshot'),('bu','source_bu_package'),('mining','source_mining_run')]:
        directory=filesystem_path(entry[key]);m=directory/'manifest.json'
        sources[role]={'path':str(directory),'manifest_sha256':sha256_file(m)}
    return {'qualified_ref':entry['qualified_ref'],'source_apk_sha256':entry['source_apk_sha256'],
        'sources':sources,'ledger_revision':entry['ledger_revision'],'ledger_state_sha256':row[1],
        'ledger_file_sha256':sha256_file(run/'ledger.sqlite'),'bc_id':bc_id,
        'archive_policy':entry['archive_support_policy'],'full_registry_in':'approved-entry.json',
        'backlink_scope':'Original manifests and exact accepted ledger revision; source analyses were certified in P4A, not recomputed by BERT'}


def encode_approved(policy_path,root,model_dir,lock_path,output,config=None):
    import numpy as np
    root=filesystem_path(root);config=config or EncodingConfig()
    if config.serializer_version!='bc-semantics.v1':
        raise ValueError('The original P4B encoder is the v1 baseline; use pipeline.encode_frozen for versioned serializers')
    policy,pool,entries=load_frozen(policy_path,root);lock=read(lock_path)
    # Check source and all semantics before loading the encoder or publishing.
    backlinks=[source_backlink(e) for e in entries];serialized=[serialize_entry(e) for e in entries]
    encoder=BertEncoder(model_dir,lock,config)
    plans=[chunk_records(s,encoder.tokenizer,config) for s in serialized]
    run=filesystem_path(output)/('encoding_'+uuid4().hex);run.mkdir(parents=True,exist_ok=False)
    write(run/'run.json',{'schema_version':'bc-encoding-run.v1','state':'building',
        'created_utc':datetime.now(timezone.utc).isoformat(),'qualified_refs':policy['qualified_refs'],
        'excluded_candidate_count':10,'generative_llm_calls':0,'knowledge_base_built':False,'quality_evaluation_performed':False})
    write(run/'config.json',config.model_dump(mode='json'));write(run/'runtime.json',encoder.runtime)
    write(run/'model-artifacts.json',encoder.artifacts);write(run/'audit/freeze.json',policy)
    shutil.copyfile(filesystem_path(policy_path),run/'audit/frozen-inputs.json')
    shutil.copyfile(root/policy['approved_pool'],run/'audit/approved-pool.json')
    shutil.copyfile(root/policy['review'],run/'audit/exit-review.json')
    shutil.copyfile(filesystem_path(lock_path),run/'audit/model-lock.json')
    rules=Path(__file__).parent
    for file in sorted(rules.glob('*.py')):
        target=run/'audit/rules'/file.name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target)
    all_chunks=[];groups=[];rows=[]
    for i,(entry,s,plan,backlink) in enumerate(zip(entries,serialized,plans,backlinks)):
        name=f'bc-{i+1:02d}';base=run/name;base.mkdir()
        (base/'semantic.txt').write_text(s['text'],encoding='utf-8',newline='\n')
        write(base/'semantic.json',s['projection']);write(base/'records.json',s['records']);write(base/'chunks.json',plan)
        for chunk in plan:
            (base/f"chunk-{chunk['chunk_index']+1:02d}.txt").write_text(chunk['text'],encoding='utf-8',newline='\n')
        write(base/'audit/aliases.json',s['audit']);write(base/'audit/source.json',backlink)
        write(base/'audit/approved-entry.json',entry)
        group=list(range(len(all_chunks),len(all_chunks)+len(plan)));groups.append(group);all_chunks.extend(plan)
        rows.append({'bc_vector_row':i,'qualified_ref':entry['qualified_ref'],'source_case':entry['source_case'],
            'directory':name,'chunk_vector_rows':group,'semantic_sha256':sha256_file(base/'semantic.txt'),
            'semantic_record_count':len(s['records']),'chunk_count':len(plan),'token_counts':[c['model_token_count'] for c in plan],
            'source_ledger_revision':entry['ledger_revision'],'audit_source':name+'/audit/source.json'})
    vectors=encoder.encode(all_chunks);raw,normalized=aggregate(vectors,groups,config)
    for name,array in [('chunk_vectors.npy',vectors),('bc_raw_means.npy',raw),('bc_vectors.npy',normalized)]:np.save(run/name,array,allow_pickle=False)
    write(run/'rows.json',rows)
    complete=read(run/'run.json');complete.update(state='published',bc_count=len(rows),chunk_count=len(all_chunks),dimensions=768)
    write(run/'run.json',complete)
    files={str(p.relative_to(run)).replace('\\','/'):{'sha256':sha256_file(p),'bytes':p.stat().st_size} for p in sorted(run.rglob('*')) if p.is_file()}
    write(run/'manifest.json',{'schema_version':'bc-encoding-manifest.v1','state':'published','files':files})
    return run
