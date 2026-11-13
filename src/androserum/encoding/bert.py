"""Local pinned BERT inference and lossless semantic-record packing."""
from pathlib import Path
import hashlib,importlib.metadata,json,platform
from androserum.facts.identity import sha256_file

RUNTIME={'torch':'2.8.0+cpu','numpy':'2.2.6','transformers':'4.57.1','tokenizers':'0.22.1',
    'huggingface-hub':'0.36.0','safetensors':'0.6.2'}


def verify_model_files(directory,lock):
    directory=Path(directory);files={}
    for name,item in lock['files'].items():
        path=directory/name
        if path.stat().st_size!=item['bytes']:raise ValueError('Pinned BERT file size differs: '+name)
        digest=sha256_file(path)
        if item.get('sha256') and digest!=item['sha256']:raise ValueError('Pinned BERT weight hash differs')
        if not item.get('sha256'):
            data=path.read_bytes();git=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if git!=item['git_blob_sha1']:raise ValueError('Pinned BERT config/tokenizer hash differs: '+name)
        files[name]={'sha256':digest,'bytes':item['bytes']}
    config=json.loads((directory/'config.json').read_text('utf-8'))
    if config['model_type']!='bert' or config['hidden_size']!=768 or config['max_position_embeddings']!=512:
        raise ValueError('Unexpected natural-language BERT architecture')
    return {'repository':lock['repository'],'revision':lock['revision'],'files':files,'config':config}


def tokenizer_for(directory,config):
    from transformers import BertTokenizerFast
    tokenizer=BertTokenizerFast.from_pretrained(str(directory),local_files_only=True)
    if not tokenizer.is_fast or not tokenizer.do_lower_case:raise ValueError('Unexpected pinned uncased tokenizer')
    if config.max_tokens>tokenizer.model_max_length:raise ValueError('Token budget exceeds pretrained position budget')
    return tokenizer


def chunk_records(serialized,tokenizer,config):
    chunks=[];current=[]
    def build(records):
        start=records[0]['char_start'];end=records[-1]['char_end'];text=serialized['text'][start:end]
        ids=tokenizer.encode(text,add_special_tokens=False,truncation=False,verbose=False)
        inputs=tokenizer(text,add_special_tokens=True,return_special_tokens_mask=True,
            return_attention_mask=True,truncation=False,verbose=False)
        if len(inputs['input_ids'])>config.max_tokens:raise ValueError('Semantic record exceeds token budget; no silent truncation: '+records[0]['key'])
        return {'chunk_index':len(chunks),'char_start':start,'char_end':end,'text':text,
            'record_keys':[r['key'] for r in records],
            'records':[{'key':r['key'],'source_char_start':r['char_start'],'source_char_end':r['char_end'],
                'chunk_char_start':r['char_start']-start,'chunk_char_end':r['char_end']-start} for r in records],
            'content_token_ids':ids,'content_tokens':tokenizer.convert_ids_to_tokens(ids),
            'model_inputs':dict(inputs),'content_token_count':len(ids),'model_token_count':len(inputs['input_ids']),
            'truncated':False}
    for record in serialized['records']:
        # Fail on an oversized indivisible record before publishing any plan.
        build([record])
        try:candidate=build([*current,record])
        except ValueError:
            chunks.append(build(current));current=[record]
        else:current.append(record)
    if current:chunks.append(build(current))
    if [key for c in chunks for key in c['record_keys']]!=[r['key'] for r in serialized['records']]:
        raise ValueError('Semantic record coverage differs')
    for c in chunks:
        for r in c['records']:
            if c['text'][r['chunk_char_start']:r['chunk_char_end']]!=serialized['text'][r['source_char_start']:r['source_char_end']]:
                raise ValueError('Chunk/source text mapping differs')
    return chunks


def aggregate(chunk_vectors,groups,config):
    import numpy as np
    vectors=np.asarray(chunk_vectors,dtype=np.float32)
    if vectors.ndim!=2 or vectors.shape[1]!=768 or not np.isfinite(vectors).all():raise ValueError('Invalid chunk vectors')
    raw=[];normalized=[]
    for indexes in groups:
        if not indexes:raise ValueError('Empty BC cannot be encoded')
        mean=vectors[indexes].mean(axis=0,dtype=np.float32)
        norm=float(np.linalg.norm(mean.astype(np.float64)))
        if not np.isfinite(norm) or norm<=config.norm_epsilon:raise ValueError('BC mean is zero or nonfinite')
        raw.append(mean);normalized.append((mean.astype(np.float64)/norm).astype(np.float32))
    return np.stack(raw),np.stack(normalized)


class BertEncoder:
    def __init__(self,directory,lock,config):
        self.config=config;self.artifacts=verify_model_files(directory,lock)
        if (lock['repository'],lock['revision'])!=(config.repository,config.revision):raise ValueError('Encoder revision differs from policy')
        versions={name:importlib.metadata.version(name) for name in RUNTIME}
        if versions!=RUNTIME:raise ValueError('Encoding runtime differs from pinned versions: '+repr(versions))
        import torch
        from transformers import BertModel
        torch.set_num_threads(config.threads);torch.manual_seed(config.seed);torch.use_deterministic_algorithms(True)
        self.torch=torch;self.tokenizer=tokenizer_for(directory,config)
        self.model,info=BertModel.from_pretrained(str(directory),local_files_only=True,use_safetensors=True,
            add_pooling_layer=False,attn_implementation=config.attention,dtype=torch.float32,output_loading_info=True)
        if info['missing_keys'] or info.get('mismatched_keys') or info.get('error_msgs'):raise ValueError('Encoder has missing/random or mismatched weights')
        if any(not k.startswith(('cls.','pooler.','bert.pooler.')) for k in info['unexpected_keys']):raise ValueError('Unexpected pretrained weight family')
        self.model.to('cpu').eval();self.model.requires_grad_(False)
        if any(m.training for m in self.model.modules()):raise ValueError('Dropout/training remains enabled')
        self.runtime={'versions':versions,'python':platform.python_version(),'platform':platform.platform(),
            'device':'cpu','cuda_used':False,'dtype':'float32','attention':'eager','threads':config.threads,
            'deterministic_algorithms':True,'training':False,'generative_head_instantiated':False,
            'missing_weights':info['missing_keys'],'unused_pretraining_head_weights':info['unexpected_keys'],
            'pooling':'attention-masked last-layer mean; added CLS/SEP and padding excluded; content UNK retained',
            'bc_mean_dtype':'float32','normalization_norm_dtype':'float64','generative_llm_calls':0,'network_during_encoding':False}

    def encode(self,chunks):
        import numpy as np
        torch=self.torch;result=[]
        with torch.inference_mode():
            for start in range(0,len(chunks),self.config.batch_size):
                batch=chunks[start:start+self.config.batch_size]
                inputs=self.tokenizer.pad([c['model_inputs'] for c in batch],padding='max_length',
                    max_length=self.config.max_tokens,return_tensors='pt')
                special=inputs.pop('special_tokens_mask')
                hidden=self.model(**inputs).last_hidden_state
                pooled=masked_mean(hidden,inputs['attention_mask'],special)
                result.append(pooled.cpu().numpy().astype(np.float32))
        vectors=np.concatenate(result,axis=0)
        if not np.isfinite(vectors).all():raise ValueError('Nonfinite BERT output')
        return vectors


def masked_mean(hidden,attention_mask,special_mask):
    """Pool content, retaining UNK but excluding added CLS/SEP and padding."""
    import torch
    mask=(attention_mask*(1-special_mask)).to(torch.float32)
    denominator=mask.sum(dim=1)
    if (denominator<=0).any():raise ValueError('No non-special content tokens to pool')
    return (hidden*mask.unsqueeze(-1)).sum(dim=1)/denominator.unsqueeze(-1)
