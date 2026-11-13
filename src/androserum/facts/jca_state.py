"""Finite, conditional JCA state contracts over existing contextual graphs.

Only a single factory identity and a branch-free normal corridor are supported.
These model-assisted edges do not claim runtime success, byte copying, Android
reachability, general alias precision or a complete cryptographic protocol.
"""
from collections import defaultdict, deque
import hashlib
import json
from pathlib import Path
from typing import Literal
from pydantic import Field
from androserum import __version__
from .context_heap import ContextHeapReport, entry_for
from .identity import canonical_json, fingerprint, record_id
from .io import loads_facts
from .models import (AnalysisNodeRecord, AnalysisScope, AnalysisStatus, BindingRecord,
    ConditionRecord, Endpoint, ModelPosition, ProgramSlot, Provenance, StrictModel,
    ToolVersion, ValueInfo, VersionedArtifact)

TOOL='tool:jca-state'; RULE='rule:jca-state'; MODEL='model:jca-selected-android9-v1'
ENTRY='analysis/jca-state/report.json'
MD='Ljava/security/MessageDigest;'; CIPHER='Ljavax/crypto/Cipher;'
FACTORIES={MD+'->getInstance(Ljava/lang/String;)'+MD, CIPHER+'->getInstance(Ljava/lang/String;)'+CIPHER}
PAIRS={MD+'->update([B)V':(MD+'->digest()[B',0,'digest_accumulation'),
       CIPHER+'->init(ILjava/security/Key;)V':(CIPHER+'->doFinal([B)[B',1,'cipher_initialization')}
UPSTREAM={'MessageDigest.java':'c9a1c7bab5fc59b257d19b2de19518cfac531a156a809f0087cdb816052a08c4',
          'Cipher.java':'10023ca09c0079a08cf73978e7994f5e600d35e7b62634bb616ad5104f2052a5'}
MODEL_SPEC={'version':'1','android_revision':'android-9.0.0_r1','upstream':UPSTREAM,
 'pairs':{k:list(v) for k,v in PAIRS.items()},
 'object_policy':'One nonrepeated getInstance result identity, same full invocation frame',
 'order_policy':'Branch-free acyclic normal CFG corridor; reject intervening invokes/stores; only String.getBytes() is permitted before the writer',
 'precondition':'Documented provider semantics, nonconcurrent use, non-null valid arguments and successful normal completion of factory, writer and consumer; not observed execution',
 'state_semantics':'update contributes bytes to digest state; init establishes selected key/mode state consumed by doFinal; state finalization is not a fine-grained byte-copy path',
 'unsupported':['other overloads','arbitrary object/escape analysis','branched writer-consumer corridors',
                'repeated factory allocations','concurrent mutation','complete exceptional propagation','provider-specific byte semantics']}


class JCAConfig(StrictModel):
    schema_version:Literal['jca-state-config.v1']='jca-state-config.v1'
    max_effects:int=Field(default=128,ge=1,le=2048)
    max_visits:int=Field(default=100000,ge=1,le=1000000)


def _key(p): return canonical_json(p.model_dump(mode='json'))


def analyze_jca(facts,read,config):
    run=facts.run.run_id; effects=[];decisions=[];issues=[];visits=0
    roots=sorted({e.method_ref for e in facts.elements if getattr(e,'node_kind',None)=='state'
        and e.provenance.tool_ref=='tool:context-heap' and getattr(e.position,'position_label',None)=='context-heap'})
    def budget():
        nonlocal visits
        visits+=1
        if visits>config.max_visits:raise OverflowError('JCA origin/normal-corridor visit budget exhausted')
    for root in roots:
        report=ContextHeapReport.model_validate_json(read(entry_for(root)))
        if report.state!='complete' or report.projection is None:
            issues.append({'root_ref':root,'state':report.state,'reason':'Context projection unavailable'});continue
        p=report.projection; nodes=p.nodes;units=p.method.units; by_ref={n.node_ref:n for n in nodes}
        incoming=defaultdict(list); source_roots=defaultdict(list); succ=defaultdict(list)
        for link in report.scalar.links:incoming[_key(link.target)].append(link.source)
        for value in report.scalar.roots:source_roots[_key(value.endpoint)].append(value)
        for a,b in p.cfg.normal_edges:succ[a].append(b)
        point=lambda i,kind,index=None:Endpoint(element_ref=nodes[i].node_ref,position_label=f'unit:{i}',slot_kind=kind,slot_index=index)
        cache={}
        def origins(endpoint):
            key=_key(endpoint)
            if key not in cache:
                queue=deque([endpoint]);seen=set();out=[]
                while queue:
                    budget();value=queue.popleft();k=_key(value)
                    if k in seen:continue
                    seen.add(k);out.extend(source_roots[k]);queue.extend(incoming[k])
                cache[key]=out
            return cache[key]
        def identity(i,kind='receiver',index=None):
            values=origins(point(i,kind,index))
            if len(values)!=1 or values[0].kind!='call_result':return None
            value=values[0]; signature=value.details.get('signature')
            if signature not in FACTORIES or value.endpoint.element_ref not in by_ref:return None
            factory=by_ref[value.endpoint.element_ref]
            if factory.frame_ref!=nodes[i].frame_ref:return None
            return value.endpoint.element_ref
        def literal(i,index):
            values=origins(point(i,'argument',index))
            if len(values)!=1 or values[0].kind!='constant':return None
            operand=values[0].details.get('operand',{})
            return operand.get('constant') if operand.get('constant_kind')=='int' else None
        def corridor(start,end,obj,allow_getbytes=False):
            path=[start];current=start;seen={start}
            while current!=end:
                budget();next_nodes=list(dict.fromkeys(succ[current]))
                if len(next_nodes)!=1:return None,'nonlinear_or_missing_normal_corridor'
                current=next_nodes[0]
                if current in seen:return None,'cyclic_normal_corridor'
                seen.add(current);path.append(current)
                if nodes[current].frame_ref!=nodes[start].frame_ref:return None,'different_invocation_frame'
                if current==end:break
                if getattr(units[current],'operation',None) in {'field_write','array_write'} or getattr(getattr(units[current],'left',None),'kind',None) in {'JInstanceFieldRef','JStaticFieldRef','JArrayRef'}:
                    return None,'intervening_store_or_object_escape_unknown'
                invoke=units[current].invoke
                if invoke:
                    if identity(current)==obj:return None,'intervening_object_state_call'
                    for index in range(len(invoke.arguments)):
                        if identity(current,'argument',index)==obj:return None,'intervening_object_escape_or_state_call'
                    if not (allow_getbytes and invoke.signature=='Ljava/lang/String;->getBytes()[B'):
                        return None,'intervening_invoke_alias_or_state_unknown'
            return path,None
        try:
            for writer,unit in enumerate(units):
                if not unit.invoke or unit.invoke.signature not in PAIRS:continue
                target_sig,input_index,family=PAIRS[unit.invoke.signature]
                obj=identity(writer)
                consumers=[i for i,u in enumerate(units) if u.invoke and u.invoke.signature==target_sig]
                for consumer in consumers:
                    budget();row={'root_ref':root,'writer_ref':nodes[writer].node_ref,'consumer_ref':nodes[consumer].node_ref,
                        'writer_signature':unit.invoke.signature,'consumer_signature':target_sig,'state':'not_adapted','reason':None,
                        'writer_object_ref':obj,'consumer_object_ref':identity(consumer),'normal_witness':[]}
                    decisions.append(row)
                    if obj is None or row['consumer_object_ref'] is None:row['reason']='factory_identity_unknown_or_ambiguous';continue
                    if obj!=row['consumer_object_ref']:row.update(state='rejected',reason='different_factory_object');continue
                    factory_invoke=units[by_ref[obj].index].invoke
                    if factory_invoke is None:
                        row['reason']='factory_invocation_metadata_unavailable';continue
                    factory_signature=factory_invoke.signature
                    if factory_signature.split('->',1)[0]!=unit.invoke.signature.split('->',1)[0]:
                        row.update(state='rejected',reason='factory_family_mismatch');continue
                    if nodes[writer].frame_ref!=nodes[consumer].frame_ref:row.update(state='rejected',reason='different_invocation_frame');continue
                    inputs=origins(point(writer,'argument',input_index))
                    if inputs and all(v.kind=='constant' and v.details.get('operand',{}).get('constant_kind')=='null' for v in inputs):
                        row.update(state='rejected',reason='known_null_writer_input');continue
                    mode=literal(writer,0) if family=='cipher_initialization' else None
                    if family=='cipher_initialization' and mode not in {1,2}:
                        row['reason']='cipher_mode_outside_encrypt_decrypt_scope';continue
                    factory=by_ref[obj].index
                    # A cyclic factory may denote more than one allocation. A
                    # finite traversal deliberately rejects, rather than merges.
                    queue=deque(succ[factory]);seen=set();repeated=False
                    while queue:
                        budget();i=queue.popleft()
                        if i==factory:repeated=True;break
                        if i not in seen:seen.add(i);queue.extend(succ[i])
                    if repeated:row['reason']='factory_repeated_by_normal_cycle';continue
                    _,prefix_reason=corridor(factory,writer,obj,allow_getbytes=True)
                    if prefix_reason:
                        row.update(state='rejected',reason='factory_to_writer_'+prefix_reason);continue
                    path,reason=corridor(writer,consumer,obj)
                    if reason:row.update(state='rejected',reason=reason);continue
                    if len(effects)>=config.max_effects:raise OverflowError('JCA effect budget exhausted')
                    ref=record_id(run,'analysis',['jca-state',root,writer,consumer])
                    condition=record_id(run,'condition',['jca-normal-success',ref])
                    edge_ids=[record_id(run,'relation',['jca-state',ref,role]) for role in ['write','consume','finalize']]
                    effect={'effect_ref':ref,'owner_projection_ref':nodes[writer].node_ref,'consumer_projection_ref':nodes[consumer].node_ref,
                        'root_ref':root,'context_ref':nodes[writer].frame_ref,'object_ref':obj,'family':family,'cipher_mode':mode,
                        'writer_endpoint':point(writer,'argument',input_index).model_dump(mode='json'),
                        'writer_receiver':point(writer,'receiver').model_dump(mode='json'),
                        'consumer_endpoint':point(consumer,'receiver').model_dump(mode='json'),
                        'consumer_result':point(consumer,'result').model_dump(mode='json'),
                        'state_endpoint':Endpoint(element_ref=ref,position_label=ref,slot_kind='state',slot_label='conditional_jca_state').model_dump(mode='json'),
                        'condition_ref':condition,'relation_refs':edge_ids,'normal_witness':[nodes[i].node_ref for i in path],
                        'original_writer_ref':nodes[writer].origin_ref,'original_consumer_ref':nodes[consumer].origin_ref,
                        'success_proven':False,'fine_grained_byte_path':False,'rule_ref':MODEL,
                        'precondition':MODEL_SPEC['precondition']}
                    effects.append(effect);row.update(state='included_conditional',reason=None,normal_witness=effect['normal_witness'],effect_ref=ref)
        except OverflowError as error:
            issues.append({'root_ref':root,'state':'truncated','reason':str(error)});break
    return {'schema_version':'jca-state-evidence.v1','run_ref':run,'configuration':config.model_dump(mode='json'),
        'effects':effects,'decisions':decisions,'issues':issues,'visits':visits,'execution_claim':'possible_only',
        'path_feasibility_checked':False,'complete_crypto_behavior_claimed':False,'exceptional_state_propagation':False}


def _emit(facts,report):
    from .models import RelationRecord
    run=facts.run.run_id;elements=[];bindings=[];edges=[]
    for index,effect in enumerate(report['effects']):
        ref=effect['effect_ref'];condition=effect['condition_ref']
        support=list(dict.fromkeys([effect['owner_projection_ref'],effect['consumer_projection_ref'],effect['object_ref'],
            effect['original_writer_ref'],effect['original_consumer_ref'],*effect['normal_witness']]))
        support=[s for s in support if s]
        prov=Provenance(kind='model_assisted',tool_ref=TOOL,rule_ref=MODEL,support_refs=support)
        state=Endpoint(**effect['state_endpoint']);value=Endpoint(element_ref=ref,position_label=ref,slot_kind='value')
        elements.append(AnalysisNodeRecord(id=ref,run_ref=run,kind='analysis_node',node_kind='state',method_ref=effect['root_ref'],
            position=ModelPosition(kind='model',model_ref=MODEL,position_label=ref),provenance=prov,
            text='Conditional JCA '+effect['family']+' state; mode='+str(effect['cipher_mode'])+'. '+effect['precondition'],
            slots=[ProgramSlot(slot_kind='state',slot_label='conditional_jca_state',value=ValueInfo(status='unknown',reason='Conditional provider state, successful execution unproven')),
                   ProgramSlot(slot_kind='value',value=ValueInfo(status='unknown',reason='Model precondition; no observed runtime guard'))]))
        elements.append(ConditionRecord(id=condition,run_ref=run,kind='condition',branch_ref=effect['owner_projection_ref'],
            branch_label='MODEL PRECONDITION: '+effect['precondition'],value_endpoint=value,
            expected_value=ValueInfo(status='known',value=True),provenance=prov))
        binding=record_id(run,'binding',['jca-object',ref])
        factory=next(e for e in facts.elements if e.id==effect['object_ref'])
        bindings.append(BindingRecord(id=binding,run_ref=run,binding_kind='object',context_ref=effect['context_ref'],condition_refs=[condition],
            endpoints=[Endpoint(element_ref=factory.id,position_label=factory.position.position_label,slot_kind='result'),
                       Endpoint(**effect['writer_receiver']),Endpoint(**effect['consumer_endpoint'])],provenance=prov))
        for edge_id,source,target,role in zip(effect['relation_refs'],
                [Endpoint(**effect['writer_endpoint']),state,state],
                [state,Endpoint(**effect['consumer_endpoint']),Endpoint(**effect['consumer_result'])],['state_write','state_consumption','state_finalization']):
            edges.append(RelationRecord(id=edge_id,run_ref=run,relation_kind='state_dependency',source=source,target=target,
                context_ref=effect['context_ref'],binding_refs=[binding],condition_refs=[condition],resolution='partial',
                unresolved_reason='Conditional '+role+' under fixed JCA contract; not a fine-grained byte-copy path or execution guarantee',
                provenance=prov,source_selector=ENTRY+f'#/effects/{index}'))
    return elements,bindings,edges


def extend_jca_state(result,config=None):
    config=config or JCAConfig();facts=result.facts
    if any(t.tool_id==TOOL for t in facts.run.tools):raise ValueError('JCA model requires a new run; duplicate application refused')
    report=analyze_jca(facts,lambda e:result.blobs[result.entry_digests[e]],config)
    facts.run.configuration.options['jca_state']=config.model_dump(mode='json')
    facts.run.config_fingerprint=fingerprint(facts.run.configuration.model_dump(mode='json'))
    assets=[(ENTRY,canonical_json(report).encode(),None,None),
            ('analysis/rules/jca_state.py',Path(__file__).read_bytes(),RULE,'rule'),
            ('analysis/rules/jca-state.json',canonical_json(MODEL_SPEC).encode(),MODEL,'summary')]
    for name,digest in UPSTREAM.items():
        raw=(Path(__file__).parents[3]/'.resources/jca-state'/name).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('Pinned JCA contract changed')
        assets.append(('analysis/models/jca/'+name,raw,'model:jca-source-'+name,'summary'))
    for entry,raw,ref,kind in assets:
        digest=hashlib.sha256(raw).hexdigest();result.blobs[digest]=raw;result.entry_digests[entry]=digest
        if ref:facts.run.artifacts.append(VersionedArtifact(artifact_id=ref,kind=kind,name='finite JCA state contract',version='1',sha256=digest,location=entry))
    facts.run.tools.append(ToolVersion(tool_id=TOOL,name='finite conditional JCA state',version=__version__))
    elements,bindings,edges=_emit(facts,report);facts.elements.extend(elements);facts.bindings.extend(bindings);facts.relations.extend(edges)
    for effect in report['effects']:
        facts.statuses.append(AnalysisStatus(id=record_id(facts.run.run_id,'status',['jca-state',effect['effect_ref']]),run_ref=facts.run.run_id,
            capability='objects',scope=AnalysisScope(kind='element',element_ref=effect['effect_ref']),tool_ref=TOOL,state='partial',
            reason='Finite conditional provider contract; normal execution, keys and runtime values not established'))
    result.facts=loads_facts(facts.model_dump_json());verify_jca_state(result.facts,lambda e:result.blobs[result.entry_digests[e]])
    result.summary['jca_state']={'conditional_effects':len(report['effects']),'relations':len(edges),'decisions':len(report['decisions']),
                               'issues':report['issues'],'complete_crypto_claimed':False}
    return result


def verify_jca_state(facts,read):
    actual=[{e.id:e for e in rows if e.provenance.tool_ref==TOOL} for rows in [facts.elements,facts.bindings,facts.relations]]
    if not any(t.tool_id==TOOL for t in facts.run.tools):
        if any(actual):raise ValueError('JCA facts lack provider metadata')
        return
    if read('analysis/rules/jca-state.json')!=canonical_json(MODEL_SPEC).encode():raise ValueError('JCA contract differs from pinned scope')
    for name,digest in UPSTREAM.items():
        if hashlib.sha256(read('analysis/models/jca/'+name)).hexdigest()!=digest:raise ValueError('Pinned JCA source contract changed')
    report=json.loads(read(ENTRY));config=JCAConfig.model_validate(facts.run.configuration.options['jca_state'])
    if report!=analyze_jca(facts,read,config):raise ValueError('JCA state evidence differs from original projection/model')
    if actual!=[{e.id:e for e in rows} for rows in _emit(facts,report)]:raise ValueError('Forged JCA object, context, normal order, condition or dependency')


def jca_evidence(facts,read,refs=()):
    if not any(t.tool_id==TOOL for t in facts.run.tools):return {'schema_version':'jca-state-query.v1','state':'not_started','effects':[],'decisions':[]}
    report=json.loads(read(ENTRY));selected=set(refs)
    return {**report,'schema_version':'jca-state-query.v1','state':'partial',
        'effects':[e for e in report['effects'] if not selected or selected & {e['root_ref'],e['owner_projection_ref'],e['consumer_projection_ref'],e['effect_ref']}],
        'decisions':[e for e in report['decisions'] if not selected or selected & {e['root_ref'],e['writer_ref'],e['consumer_ref']}]}
