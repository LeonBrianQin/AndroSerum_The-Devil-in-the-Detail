"""Portable APK--BC provenance snapshots and exact, read-only inspection."""
from datetime import datetime,timezone
from contextlib import contextmanager
from pathlib import Path
import json,shutil,sqlite3,zipfile
from uuid import uuid4
import numpy as np
from androserum.facts.identity import filesystem_path,sha256_file,fingerprint,canonical_json
from androserum.encoding.runner import read,write
from androserum.encoding.verification import verify_encoding
from androserum.encoding.models import EncodingConfig

VERSION='behavior-knowledge-store.v1'
SCHEMA='''
PRAGMA foreign_keys=ON;
CREATE TABLE metadata(key TEXT PRIMARY KEY,value_json TEXT NOT NULL);
CREATE TABLE apks(apk_sha256 TEXT PRIMARY KEY,identity_json TEXT NOT NULL,background_json TEXT NOT NULL);
CREATE TABLE bcs(qualified_ref TEXT PRIMARY KEY,bc_id TEXT NOT NULL,source_case TEXT NOT NULL,
 ledger_revision INTEGER NOT NULL,vector_row INTEGER UNIQUE NOT NULL,asset_directory TEXT NOT NULL,payload_json TEXT NOT NULL);
CREATE TABLE apk_bc_edges(apk_sha256 TEXT NOT NULL REFERENCES apks,qualified_ref TEXT UNIQUE NOT NULL REFERENCES bcs,
 edge_type TEXT NOT NULL CHECK(edge_type='origin'),PRIMARY KEY(apk_sha256,qualified_ref));
CREATE TABLE actions(qualified_ref TEXT NOT NULL REFERENCES bcs,action_id TEXT NOT NULL,payload_json TEXT NOT NULL,
 PRIMARY KEY(qualified_ref,action_id));
CREATE TABLE action_relations(qualified_ref TEXT NOT NULL REFERENCES bcs,link_id TEXT NOT NULL,payload_json TEXT NOT NULL,
 PRIMARY KEY(qualified_ref,link_id));
CREATE TABLE visible_evidence(qualified_ref TEXT NOT NULL REFERENCES bcs,handle TEXT NOT NULL,category TEXT NOT NULL,
 record_ref TEXT,payload_json TEXT NOT NULL,PRIMARY KEY(qualified_ref,handle));
CREATE INDEX evidence_by_record ON visible_evidence(qualified_ref,record_ref);
CREATE INDEX bc_by_native_id ON bcs(bc_id);
'''


@contextmanager
def readonly(path):
    path=filesystem_path(path)
    if not path.is_file():raise ValueError('Knowledge/ledger database absent')
    uri=Path(str(path).removeprefix('\\\\?\\')).as_uri()
    db=sqlite3.connect(uri+'?mode=ro&immutable=1',uri=True)
    try:yield db
    finally:db.close()


def safe_asset(base,relative):
    if Path(relative).is_absolute() or '..' in Path(relative).parts:raise ValueError('Asset path escapes snapshot')
    path=filesystem_path(base/relative)
    if not path.is_relative_to(base):raise ValueError('Asset path escapes snapshot')
    return path


def apk_identity(entry):
    snapshot=filesystem_path(entry['source_snapshot']);manifest=read(snapshot/'manifest.json')
    database=snapshot/manifest['database']
    if sha256_file(database)!=manifest['database_sha256']:raise ValueError('APK metadata source changed')
    with readonly(database) as db:
        row=db.execute('SELECT metadata_json,apk_sha256 FROM analysis_runs WHERE run_id=?',(manifest['run_ref'],)).fetchone()
    if row is None or row[1]!=entry['source_apk_sha256']:raise ValueError('APK identity differs')
    meta=json.loads(row[0])['run']['apk_metadata']
    return {'apk_sha256':row[1],**{key:meta.get(key) for key in ['package','version_code','version_name']},
        'source_snapshot_manifest_sha256':sha256_file(snapshot/'manifest.json'),
        'source_database_sha256':manifest['database_sha256'],'identity_scope':'Static APK identity only; no inferred malware label'}


def create_snapshot(encoding_run,root,output,*,background=None,before_commit=None):
    root=filesystem_path(root);encoding_run=filesystem_path(encoding_run);output=filesystem_path(output)
    model=root/'.models/bert-base-uncased'/EncodingConfig().revision
    verify_encoding(encoding_run,root,model)
    rows=read(encoding_run/'rows.json');pool=read(encoding_run/'audit/approved-pool.json')['entries']
    if [r['qualified_ref'] for r in rows]!=[e['qualified_ref'] for e in pool]:raise ValueError('Approved identities differ')
    if len(rows)!=3 or len({r['qualified_ref'] for r in rows})!=3:raise ValueError('P5A v1 accepts exactly three approved instances')
    identities={e['source_apk_sha256']:apk_identity(e) for e in pool}
    background=background or {}
    if set(background)-set(identities):raise ValueError('Unknown APK background identity')
    token=uuid4().hex;building=output/('.building_'+token);final=output/('knowledge_'+token)
    output.mkdir(parents=True,exist_ok=True);building.mkdir(exist_ok=False)
    if not building.is_relative_to(output) or not final.is_relative_to(output):raise ValueError('Publication path escapes output')
    db=None
    try:
        shutil.copytree(encoding_run,building/'encoding')
        (building/'rules').mkdir()
        for source in Path(__file__).parent.glob('*.py'):shutil.copyfile(source,building/'rules'/source.name)
        write(building/'apk-identities.json',{'identities':identities,'source_background':background})
        write(building/'provenance.json',{'schema_version':VERSION,'source_encoding_run':str(encoding_run),
            'source_encoding_manifest_sha256':sha256_file(encoding_run/'manifest.json'),
            'frozen_qualified_refs':[e['qualified_ref'] for e in pool],
            'excluded_candidate_count':10,'query_roles':{'visible_evidence':'exactly the P4A actually displayed registry',
                'ledger_and_backlinks':'archive audit, not automatically model visible'},
            'background_policy':'APK source background only; no inheritance to BC; absent labels remain absent',
            'vector_policy':'Original P4B vectors retained for storage; retrieval effectiveness unvalidated',
            'retrieval_quality_validated':False,'similarity_search_implemented':False,'generative_llm_calls':0})
        db=sqlite3.connect(building/'knowledge.sqlite');db.executescript(SCHEMA);db.execute('BEGIN IMMEDIATE')
        for key,value in {'store_version':VERSION,'retrieval_quality_validated':False,'source_encoding_manifest_sha256':sha256_file(encoding_run/'manifest.json')}.items():
            db.execute('INSERT INTO metadata VALUES (?,?)',(key,canonical_json(value)))
        for sha,identity in identities.items():db.execute('INSERT INTO apks VALUES (?,?,?)',(sha,canonical_json(identity),canonical_json(background.get(sha,{}))))
        for entry,row in zip(pool,rows):
            ref=entry['qualified_ref'];bc=entry['bc']
            db.execute('INSERT INTO bcs VALUES (?,?,?,?,?,?,?)',(ref,bc['bc_id'],entry['source_case'],entry['ledger_revision'],
                row['bc_vector_row'],'encoding/'+row['directory'],canonical_json(bc)))
            db.execute('INSERT INTO apk_bc_edges VALUES (?,?,?)',(entry['source_apk_sha256'],ref,'origin'))
            for key,a in entry['actions'].items():db.execute('INSERT INTO actions VALUES (?,?,?)',(ref,key,canonical_json(a)))
            for link in bc['relations']:db.execute('INSERT INTO action_relations VALUES (?,?,?)',(ref,link['link_id'],canonical_json(link)))
            for handle,evidence in entry['model_visible_evidence']['registry'].items():
                db.execute('INSERT INTO visible_evidence VALUES (?,?,?,?,?)',(ref,handle,evidence['category'],evidence.get('record_ref'),canonical_json(evidence)))
            ledger=filesystem_path(entry['source_mining_run'])/'ledger.sqlite';target=building/'ledgers'/f"{row['directory']}.sqlite"
            target.parent.mkdir(exist_ok=True);shutil.copyfile(ledger,target)
        if before_commit:before_commit(db)
        db.execute('COMMIT');db.close();db=None
        files={str(p.relative_to(building)).replace('\\','/'):{'sha256':sha256_file(p),'bytes':p.stat().st_size} for p in building.rglob('*') if p.is_file()}
        write(building/'manifest.json',{'schema_version':'behavior-knowledge-snapshot.v1','store_version':VERSION,'state':'published',
            'snapshot_id':fingerprint(files),'created_utc':datetime.now(timezone.utc).isoformat(),
            'apk_count':len(identities),'bc_count':len(rows),'origin_edge_count':len(rows),
            'retrieval_quality_validated':False,'files':files})
        verify_snapshot(building)
        building.rename(final)
        return final
    except Exception as error:
        if db is not None:db.rollback();db.close()
        write(building/'failure.json',{'state':'failed_not_published','error':repr(error)})
        raise


def verify_snapshot(path):
    path=filesystem_path(path);manifest=read(path/'manifest.json')
    if manifest['state']!='published' or manifest['store_version']!=VERSION:raise ValueError('Not a published P5A snapshot')
    files=manifest['files'];actual={str(p.relative_to(path)).replace('\\','/') for p in path.rglob('*') if p.is_file() and p!=path/'manifest.json'}
    if actual!=set(files):raise ValueError('Knowledge file inventory differs')
    for name,item in files.items():
        file=safe_asset(path,name)
        if file.stat().st_size!=item['bytes'] or sha256_file(file)!=item['sha256']:raise ValueError('Knowledge file changed: '+name)
    if fingerprint(files)!=manifest['snapshot_id']:raise ValueError('Snapshot identity changed')
    provenance=read(path/'provenance.json');encoded=path/'encoding';em=read(encoded/'manifest.json')
    if sha256_file(encoded/'manifest.json')!=provenance['source_encoding_manifest_sha256']:raise ValueError('Original encoding manifest changed')
    for name,item in em['files'].items():
        if sha256_file(safe_asset(encoded,name))!=item['sha256']:raise ValueError('Original encoding assets changed')
    rows=read(encoded/'rows.json');entries=read(encoded/'audit/approved-pool.json')['entries'];vectors=np.load(encoded/'bc_vectors.npy',allow_pickle=False)
    freeze=read(encoded/'audit/frozen-inputs.json')
    if [e['qualified_ref'] for e in entries]!=provenance['frozen_qualified_refs'] or provenance['frozen_qualified_refs']!=freeze['qualified_refs']:
        raise ValueError('Unapproved identities in knowledge snapshot')
    if sha256_file(encoded/'audit/approved-pool.json')!=freeze['pool_sha256']:raise ValueError('Frozen approval pool changed')
    if vectors.shape!=(3,768) or vectors.dtype!=np.float32 or not np.isfinite(vectors).all():raise ValueError('Invalid stored vectors')
    if manifest['retrieval_quality_validated'] or provenance['retrieval_quality_validated'] or provenance['similarity_search_implemented']:
        raise ValueError('Storage must not assert retrieval validation')
    counts={}
    with readonly(path/'knowledge.sqlite') as db:
        if db.execute('PRAGMA integrity_check').fetchone()[0]!='ok' or db.execute('PRAGMA foreign_key_check').fetchall():raise ValueError('Knowledge database integrity failure')
        for table in ['apks','bcs','apk_bc_edges','actions','action_relations','visible_evidence']:
            counts[table]=db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
        if counts['bcs']!=3 or counts['apk_bc_edges']!=3 or counts['apks']!=3:raise ValueError('Knowledge graph counts differ')
        identities=read(path/'apk-identities.json')
        expected_apks={sha:(canonical_json(identity),canonical_json(identities['source_background'].get(sha,{}))) for sha,identity in identities['identities'].items()}
        if {a:(b,c) for a,b,c in db.execute('SELECT * FROM apks')}!=expected_apks:raise ValueError('APK identity or background differs')
        metadata={k:json.loads(v) for k,v in db.execute('SELECT * FROM metadata')}
        if metadata!={'store_version':VERSION,'retrieval_quality_validated':False,'source_encoding_manifest_sha256':provenance['source_encoding_manifest_sha256']}:
            raise ValueError('Knowledge metadata differs')
        for i,(entry,row) in enumerate(zip(entries,rows)):
            ref=entry['qualified_ref'];bc=entry['bc'];record=db.execute('SELECT bc_id,source_case,ledger_revision,vector_row,asset_directory,payload_json FROM bcs WHERE qualified_ref=?',(ref,)).fetchone()
            if record!=(bc['bc_id'],entry['source_case'],entry['ledger_revision'],i,'encoding/'+row['directory'],canonical_json(bc)):
                raise ValueError('Stored BC differs from approved instance')
            if db.execute('SELECT apk_sha256,edge_type FROM apk_bc_edges WHERE qualified_ref=?',(ref,)).fetchone()!=(entry['source_apk_sha256'],'origin'):
                raise ValueError('Wrong APK--BC origin')
            for table,column,expected in [('actions','action_id',entry['actions']),
                ('action_relations','link_id',{r['link_id']:r for r in bc['relations']}),
                ('visible_evidence','handle',entry['model_visible_evidence']['registry'])]:
                found={k:json.loads(v) for k,v in db.execute('SELECT '+column+',payload_json FROM '+table+' WHERE qualified_ref=?',(ref,))}
                if found!=expected:raise ValueError('Stored '+table+' differs from approved visibility')
            evidence_columns={h:(category,ref) for h,category,ref in db.execute('SELECT handle,category,record_ref FROM visible_evidence WHERE qualified_ref=?',(ref,))}
            if evidence_columns!={h:(v['category'],v.get('record_ref')) for h,v in entry['model_visible_evidence']['registry'].items()}:raise ValueError('Evidence lookup columns differ')
            source=read(encoded/row['directory']/'audit/source.json')
            ledger=path/'ledgers'/f"{row['directory']}.sqlite"
            if sha256_file(ledger)!=source['ledger_file_sha256']:raise ValueError('Copied source ledger changed')
            with readonly(ledger) as ldb:
                ledger_row=ldb.execute('SELECT payload,sha256 FROM versions WHERE revision=?',(entry['ledger_revision'],)).fetchone()
            if ledger_row is None or fingerprint(json.loads(ledger_row[0]))!=source['ledger_state_sha256'] or ledger_row[1]!=source['ledger_state_sha256']:
                raise ValueError('Copied source revision mismatch')
        if counts['actions']!=sum(len(e['actions']) for e in entries) or counts['action_relations']!=sum(len(e['bc']['relations']) for e in entries):raise ValueError('Extra native records')
    if any(p.name=='facts.sqlite' for p in path.rglob('*')):raise ValueError('Full program fact database must not be imported')
    return {'schema_version':'behavior-knowledge-verification.v1','status':'passed','snapshot_id':manifest['snapshot_id'],
        'counts':counts,'all_visible_evidence_exact':True,'source_ledgers_recoverable':True,
        'external_original_sources_required_for_local_queries':False,'retrieval_quality_validated':False,'similarity_search_implemented':False}


def query_snapshot(path,kind,*,qualified_ref=None,apk_sha256=None,key=None,limit=100):
    if type(limit) is not int or limit<1 or limit>1000:raise ValueError('Exact query limit must be 1..1000')
    path=filesystem_path(path);verification=verify_snapshot(path)
    with readonly(path/'knowledge.sqlite') as db:
        if kind=='apk':
            sql='SELECT apk_sha256,identity_json,background_json FROM apks';values=[]
            if apk_sha256:sql+=' WHERE apk_sha256=?';values=[apk_sha256]
            records=[{'apk_sha256':a,'identity':json.loads(b),'source_background':json.loads(c)} for a,b,c in db.execute(sql+' ORDER BY apk_sha256',values)]
        elif kind=='bc':
            sql='SELECT b.qualified_ref,b.payload_json,b.asset_directory,b.vector_row,e.apk_sha256 FROM bcs b JOIN apk_bc_edges e USING(qualified_ref)';values=[];filters=[]
            if qualified_ref:filters.append('b.qualified_ref=?');values.append(qualified_ref)
            if apk_sha256:filters.append('e.apk_sha256=?');values.append(apk_sha256)
            if filters:sql+=' WHERE '+' AND '.join(filters)
            records=[{'qualified_ref':r,'bc':json.loads(p),'asset_directory':asset,'vector_row':row,'source_apk_sha256':a,
                'source_labels_inherited':False,'retrieval_quality_validated':False} for r,p,asset,row,a in db.execute(sql+' ORDER BY b.qualified_ref',values)]
        elif kind in {'action','relation','evidence'}:
            if not qualified_ref:raise ValueError('Scoped lookup requires qualified_ref')
            table,column={'action':('actions','action_id'),'relation':('action_relations','link_id'),'evidence':('visible_evidence','handle')}[kind]
            sql='SELECT '+column+',payload_json FROM '+table+' WHERE qualified_ref=?';values=[qualified_ref]
            if key:sql+=' AND '+column+'=?';values.append(key)
            records=[{'key':k,'record':json.loads(v),'visibility_role':'actually_shown_P4A_registry' if kind=='evidence' else 'approved_native_structure'} for k,v in db.execute(sql+' ORDER BY '+column,values)]
        elif kind=='audit':
            if not qualified_ref:raise ValueError('Audit lookup requires qualified_ref')
            row=db.execute('SELECT asset_directory FROM bcs WHERE qualified_ref=?',(qualified_ref,)).fetchone();records=[]
            if row:
                base=safe_asset(path,row[0]);source=read(base/'audit/source.json')
                records=[{'source':source,'aliases':read(base/'audit/aliases.json'),
                    'local_ledger':'ledgers/'+base.name+'.sqlite','role':'archive_only_not_automatically_model_visible'}]
        else:raise ValueError('Unsupported exact query kind; no similarity query')
    return {'schema_version':'behavior-knowledge-query.v1','snapshot_id':verification['snapshot_id'],
        'kind':kind,'total_matches':len(records),'records':records[:limit],'truncated':len(records)>limit,
        'retrieval_quality_validated':False,'missing':not records,'lookup_type':'exact',
        'missing_describes_index_only':True,
        'visibility_note':'Native BC and archive pointers do not grant visibility to all original facts; evidence queries return only the actually shown P4A registry.'}


def export_snapshot(path,destination):
    path=filesystem_path(path);destination=filesystem_path(destination);result=verify_snapshot(path)
    if destination.is_relative_to(path):raise ValueError('Export must stay outside immutable snapshot')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for file in sorted(path.rglob('*')):
            if file.is_file():archive.write(file,str(file.relative_to(path)).replace('\\','/'))
    return {'schema_version':'behavior-knowledge-export.v1','snapshot_id':result['snapshot_id'],
        'output':str(destination),'sha256':sha256_file(destination),'all_snapshot_files_included':True,
        'retrieval_quality_validated':False}
