"""Read-only independent reconstruction of semantic/chunk/vector products."""
from pathlib import Path
from .runner import read,load_frozen,source_backlink
from .models import EncodingConfig
from .semantic import serialize_entry
from .bert import tokenizer_for,chunk_records,BertEncoder,verify_model_files
from androserum.facts.identity import filesystem_path,sha256_file


LEGACY_V1_RULE_PROFILE = {'bert.py': 'ecc06472a1bb486480fae84e6294fe925533b7bc6b673fb041cefcf5557f2d25', 'models.py': '4650f1408a2e913c4409b8fc89bcb84771ed65cac87c209af2eb93df6e487dc2', 'runner.py': '07a056f036e4b85af293ce46d0dda3461b3a30a26e55b4c1c0caa49d168154b0', 'semantic.py': 'ec98d18a731e9a30412414c49a4b079e4ae42313e55b5262ac713ad137ecac48', 'verification.py': 'b0b2cf90cb24bff9c87d22124ed68ae8404b4df5c5638d41c35fc94ef8fe1171', '__init__.py': '051af5dee36ebddf6d7936119134cf0f550ef7c27ae45b2bd61ce2f0eab89dda'}

def verify_encoding(path,root,model_dir,*,reencode=False):
    import numpy as np
    path=filesystem_path(path);manifest=read(path/'manifest.json');checks=[]
    def check(label,ok):
        if not ok:raise ValueError(label)
        checks.append(label)
    actual={str(p.relative_to(path)).replace('\\','/') for p in path.rglob('*') if p.is_file() and p!=path/'manifest.json'}
    check('published exact file inventory',manifest['state']=='published' and actual==set(manifest['files']))
    for name,item in manifest['files'].items():
        file=filesystem_path(path/name)
        check('hash '+name,file.is_relative_to(path) and file.stat().st_size==item['bytes'] and sha256_file(file)==item['sha256'])
    config=EncodingConfig.model_validate(read(path/'config.json'))
    policy,pool,entries=load_frozen(path/'audit/frozen-inputs.json',root)
    check('native frozen pool intact',read(path/'audit/approved-pool.json')==pool)
    check('review copy intact',read(path/'audit/exit-review.json')==read(filesystem_path(root)/policy['review']))
    lock=read(path/'audit/model-lock.json');artifacts=verify_model_files(model_dir,lock)
    check('fixed model artifact identity',artifacts==read(path/'model-artifacts.json') and
        (lock['repository'],lock['revision'])==(config.repository,config.revision))
    rules=Path(__file__).parent
    current_rules={p.name:sha256_file(p) for p in rules.glob('*.py')}
    archived_rules={p.name:sha256_file(p) for p in (path/'audit/rules').glob('*.py')}
    legacy_rules=(config.serializer_version=='bc-semantics.v1' and archived_rules==LEGACY_V1_RULE_PROFILE
        and all(current_rules[k]==LEGACY_V1_RULE_PROFILE[k] for k in ['bert.py','semantic.py','__init__.py']))
    check('serializer and encoder rules match current or exact known v1 profile',
        config.serializer_version=='bc-semantics.v1' and (current_rules==archived_rules or legacy_rules))
    tokenizer=tokenizer_for(model_dir,config);rows=read(path/'rows.json');chunks=[];groups=[]
    check('three approved vector identities',len(rows)==3 and [r['qualified_ref'] for r in rows]==policy['qualified_refs'])
    for i,(entry,row) in enumerate(zip(entries,rows)):
        base=filesystem_path(path/row['directory']);check('BC directory stays in run',base.is_relative_to(path))
        s=serialize_entry(entry);plan=chunk_records(s,tokenizer,config)
        check(f'BC {i} semantic projection',s['projection']==read(base/'semantic.json'))
        check(f'BC {i} semantic text',s['text']==(base/'semantic.txt').read_text('utf-8') and sha256_file(base/'semantic.txt')==row['semantic_sha256'])
        check(f'BC {i} exact record spans',s['records']==read(base/'records.json'))
        check(f'BC {i} lossless bounded chunks',plan==read(base/'chunks.json') and not any(c['truncated'] for c in plan))
        for c in plan:check(f"BC {i} chunk {c['chunk_index']} text",c['text']==(base/f"chunk-{c['chunk_index']+1:02d}.txt").read_text('utf-8'))
        check(f'BC {i} aliases remain audit only',s['audit']==read(base/'audit/aliases.json'))
        check(f'BC {i} exact native entry',entry==read(base/'audit/approved-entry.json'))
        check(f'BC {i} ledger/manifest backlink',source_backlink(entry)==read(base/'audit/source.json'))
        group=list(range(len(chunks),len(chunks)+len(plan)));groups.append(group);chunks.extend(plan)
        check(f'BC {i} vector row and chunk mapping',row['bc_vector_row']==i and group==row['chunk_vector_rows'] and row['chunk_count']==len(plan) and row['token_counts']==[c['model_token_count'] for c in plan])
    arrays=[np.load(path/n,allow_pickle=False) for n in ['chunk_vectors.npy','bc_raw_means.npy','bc_vectors.npy']]
    cv,raw,z=arrays
    check('vector shapes and finite float32',cv.shape==(len(chunks),768) and raw.shape==z.shape==(3,768) and
        all(a.dtype==np.float32 and np.isfinite(a).all() for a in arrays))
    # Recompute without using production aggregate().
    expected=np.stack([np.sum(cv[g],axis=0,dtype=np.float32)/np.float32(len(g)) for g in groups])
    norms=np.sqrt(np.sum(expected.astype(np.float64)**2,axis=1))
    check('unweighted raw chunk means',np.array_equal(raw,expected))
    check('L2 only after raw mean',np.all(norms>config.norm_epsilon) and np.array_equal(z,(expected/norms[:,None]).astype(np.float32)))
    check('unit vector norms',np.allclose(np.linalg.norm(z.astype(np.float64),axis=1),1,rtol=0,atol=1e-6))
    runtime=read(path/'runtime.json');run=read(path/'run.json')
    check('no generation/KB or evaluation',run['generative_llm_calls']==0 and not run['knowledge_base_built'] and
        not run['quality_evaluation_performed'] and not runtime['generative_head_instantiated'])
    if reencode:
        encoder=BertEncoder(model_dir,lock,config);again=encoder.encode(chunks)
        check('offline CPU reencoding byte identical',np.array_equal(cv,again))
        check('runtime reproduced',encoder.runtime==runtime)
    return {'schema_version':'bc-encoding-verification.v1','status':'passed','checks':checks,'bc_count':3,
        'chunk_count':len(chunks),'dimensions':768,'excluded_candidates':10,'reencoded':reencode,
        'generative_llm_calls':0,'semantic_accuracy_or_retrieval_quality_claimed':False,
        'exact_legacy_rule_profile_replayed':legacy_rules,'archived_python_executed':False}
