"""Prewritten protocol controls, explicitly synthetic rather than APK claims."""
from copy import deepcopy
from androserum.facts.identity import fingerprint
from .checker import path_metadata
from .views import make_request


def toy_side(namespace,*,reverse=False,truth=True,purpose='audit',summary=False,gap=False,chain=False):
    h=lambda kind,key:kind+'_'+fingerprint([namespace,key])[:12]
    registry={};actions={};root='synthetic-root:'+namespace;context='synthetic-context:'+namespace
    nodes=['left','right',*(['tail'] if chain else [])]
    for key in nodes:
        op=h('op',key);inp=h('ep',key+'_in');out=h('ep',key+'_out')
        registry[op]={'handle':op,'category':'operation','root_ref':root,'context_ref':context,'operation':'invoke',
            'text':'Synthetic bidirectional value interface for '+purpose,'condition_refs':[],'endpoint_refs':[inp,out]}
        for ep,slot in [(inp,'receiver'),(out,'result')]:registry[ep]={'handle':ep,'category':'endpoint','owner_operation_ref':op,
            'root_ref':root,'context_ref':context,'endpoint':{'element_ref':'synthetic:'+key,'position_label':'synthetic:'+key,'slot_kind':slot}}
        field=lambda desc,ep:{'availability':'supported','description':desc,'endpoint_refs':[ep]}
        actions[key]={'action_id':key,'function':'Receive or forward controlled values at '+key,'operation_refs':[op],
            'objects':field('Controlled value interface',inp),'inputs':field('Controlled value',inp),'outputs':field('Controlled output',out),
            'condition_status':'unknown','condition_refs':[],'effect_refs':[],'support_relation_refs':[],'support_fact_refs':[],
            'limitation_notes':['Synthetic protocol fixture only; not an APK or a model inference.']}
    cond=h('cond','enabled');registry[cond]={'handle':cond,'category':'condition','expected_value':{'status':'known','value':truth},
        'scope':'synthetic_relation_precondition'}
    pairs=[('right','left')] if reverse else [('left','right'),*([('right','tail')] if chain else [])]
    links=[]
    for i,(a,b) in enumerate(pairs):
        source=h('ep',a+('_in' if chain and i==1 else '_out'));target=h('ep',b+'_in');rel=h('rel',str(i))
        registry[rel]={'handle':rel,'category':'relation','kind':'information_flow' if summary else 'data_dependency',
            'source_endpoint_ref':source,'target_endpoint_ref':target,'root_ref':root,'context_ref':context,'binding_refs':[],
            'condition_refs':[cond],'unresolved_condition_refs':[],'role':'information_flow_summary' if summary else 'program_dependency',
            'resolution':'partial' if summary else 'resolved','provenance_kind':'static_analysis','fine_grained_path_claimed':False}
        links.append({'link_id':'flow'+str(i),'from_action':a,'to_action':b,'relation_kind':'information_flow' if summary else 'data_transfer',
            'source_endpoint_ref':source,'target_endpoint_ref':target,'support_path':[rel],
            'evidence_strength':'information_flow_summary' if summary else 'recorded_dependency_path','binding_refs':[],'condition_refs':[cond],
            'execution_claim':'possible_only'})
    if gap:
        links=[];registry={k:v for k,v in registry.items() if v['category']!='relation'}
    return {'schema_version':'match-side.v1','instance_ref':'synthetic:'+namespace,
        'origin':{'material_kind':'synthetic_protocol','apk_sha256':None,'ledger_ref':None,'ledger_revision':None,'evidence_kind':'synthetic_protocol'},
        'bc':{'bc_id':'fixture','description':'Synthetic controlled value transfer','action_ids':nodes,'relations':links,
            'boundary':{'inputs':{'availability':'unknown','description':'Unknown fixture boundary','endpoint_refs':[]},
                'outputs':{'availability':'unknown','description':'Unknown fixture boundary','endpoint_refs':[]},
                'potential_effects':'Unknown controlled transfer','condition_refs':[]},'limitation_notes':['Synthetic test'],'execution_claim':'possible_only'},
        'actions':actions,'registry':registry,
        'condition_semantics':{cond:{'predicate_key':'synthetic:user_enabled','expected_value':{'status':'known','value':truth},
            'scope':'synthetic_relation_precondition','basis':'Prewritten synthetic condition'}},
        'purpose_claims':{n:purpose for n in nodes},'source_limits':[{'synthetic':True,'gap':'missing path' if gap else 'none'}],
        'limitations':['Synthetic only; execution remains unknown.']}


def support_response(request,*,action_groups=None,query_links=None,reference_links=None):
    q,r=request['sides']['query'],request['sides']['reference']
    action_groups=action_groups or [([a],[a]) for a in q['actions']]
    groups=[{'mapping_id':'actions'+str(i),'query_actions':a,'reference_actions':b,
        'object_and_io_correspondence':'Selected receiver/value roles correspond within this bounded comparison.',
        'functional_basis':'Prewritten engineering comparison; no model-quality inference.','limitations':['Natural-language equivalence is not proved by structural checking.']}
        for i,(a,b) in enumerate(action_groups)]
    qlinks=query_links if query_links is not None else [x['link_id'] for x in q['bc']['relations']]
    rlinks=reference_links if reference_links is not None else [x['link_id'] for x in r['bc']['relations']]
    qp,kind,strength=path_metadata(q,qlinks);rp,_,_=path_metadata(r,rlinks)
    group_for=lambda side,action:next(g['mapping_id'] for g in groups if action in g[side+'_actions'])
    qnative={x['link_id']:x for x in q['bc']['relations']}
    relation={'mapping_id':'path','from_mapping':group_for('query',qnative[qlinks[0]]['from_action']),
        'to_mapping':group_for('query',qnative[qlinks[-1]]['to_action']),'query':qp,'reference':rp,'direction':'aligned',
        'endpoint_correspondence':[{'query_role':role,'query_endpoint':qp[role+'_endpoint'],'reference_endpoint':rp[role+'_endpoint']} for role in ['source','target']],
        'binding_basis':'The path endpoints carry the corresponding value roles. Each side retains its own invocation/object/state bindings and contexts; no equality of raw IDs or runtime objects across APKs is asserted.',
        'relation_kind':kind,'evidence_strength':strength,'claims_complete_fine_path':False,
        'explanation':'Correspondence cites actual directed program paths; successful execution is not established.'}
    conditions=[]
    if len(qp['condition_refs'])==len(rp['condition_refs']):
        for i,(a,b) in enumerate(zip(qp['condition_refs'],rp['condition_refs'])):
            conditions.append({'mapping_id':'condition'+str(i),'query_condition':a,'reference_condition':b,'comparison':'equivalent',
                'affected_mappings':['path'],'explanation':'Same normalized bounded predicate and required truth, scoped to this relationship.'})
    usedq={a for g in groups for a in g['query_actions']};usedr={a for g in groups for a in g['reference_actions']}
    unmapped={'query_actions':sorted(set(q['actions'])-usedq),'reference_actions':sorted(set(r['actions'])-usedr),
        'query_links':sorted({x['link_id'] for x in q['bc']['relations']}-set(qlinks)),
        'reference_links':sorted({x['link_id'] for x in r['bc']['relations']}-set(rlinks))}
    return {'schema_version':'behavior-match-proposal.v1','request_id':request['request_id'],'pair_sha256':request['pair_sha256'],
        'decision':'\u652f\u6301\u5339\u914d','scope':'partial' if any(unmapped.values()) else 'full','action_mappings':groups,
        'relation_mappings':[relation],'condition_mappings':conditions,'differences':[],'unmapped':unmapped,
        'limitations':['Static possible relationships only; partial, unknown and non-executed program evidence retain their original scope.',
            'Unmapped actions and links are outside the applicable reference.'],'unresolved':[],
        'rationale':'Fixed engineering response used to validate the matching protocol; not an actual LLM result.',
        'execution_claim':'possible_only','unconditional_execution_claimed':False}


def negative_response(request,kind):
    if kind=='evidence':
        q,r=request['sides']['query'],request['sides']['reference']
        return {'schema_version':'behavior-match-proposal.v1','request_id':request['request_id'],'pair_sha256':request['pair_sha256'],
            'decision':'\u8bc1\u636e\u4e0d\u8db3','scope':'none','action_mappings':[],'relation_mappings':[],'condition_mappings':[],
            'differences':[{'difference_id':'gap','kind':'evidence','impact':'unresolved','citations':[
                {'side':'query','kind':'action','ref':next(iter(q['actions']))},{'side':'reference','kind':'action','ref':next(iter(r['actions']))}],
                'explanation':'The reference lacks a supported connecting relationship; missing evidence does not prove absence.'}],
            'unmapped':{'query_actions':list(q['actions']),'reference_actions':list(r['actions']),
                'query_links':[x['link_id'] for x in q['bc']['relations']],'reference_links':[x['link_id'] for x in r['bc']['relations']]},
            'limitations':['Evidence gap remains; no benign verdict.'],'unresolved':['Connecting reference path is missing.'],
            'rationale':'Prewritten evidence-insufficient protocol response.','execution_claim':'possible_only','unconditional_execution_claimed':False}
    response=support_response(request);response['decision']='\u884c\u4e3a\u4e0d\u540c'
    if kind=='direction':
        mapping=response['relation_mappings'][0];mapping['direction']='reversed'
        mapping['endpoint_correspondence']=[{'query_role':role,'query_endpoint':mapping['query'][role+'_endpoint'],
            'reference_endpoint':mapping['reference'][('target' if role=='source' else 'source')+'_endpoint']} for role in ['source','target']]
    if kind=='condition':response['condition_mappings'][0]['comparison']='conflict'
    citation_kind='condition' if kind=='condition' else 'link' if kind=='direction' else 'action'
    def cited(side):
        s=request['sides'][side]
        if citation_kind=='condition':return response['relation_mappings'][0][side]['condition_refs'][0]
        if citation_kind=='link':return s['bc']['relations'][0]['link_id']
        return 'right'
    response['differences']=[{'difference_id':'different','kind':kind,'impact':'blocks_selected_scope',
        'citations':[{'side':s,'kind':citation_kind,'ref':cited(s)} for s in ['query','reference']],
        'explanation':'The predefined '+kind+' difference blocks reference support for the selected scope.'}]
    return response


def protocol_cases():
    cases=[]
    for kind,kwargs in [('equivalent',{}),('direction',{'reverse':True}),('condition',{'truth':False}),('purpose',{'purpose':'authentication'}),('evidence',{'gap':True})]:
        request=make_request(toy_side('query_'+kind),toy_side('reference_'+kind,**kwargs))
        response=support_response(request) if kind=='equivalent' else negative_response(request,kind)
        cases.append({'case':kind,'request':request,'response':response,'expected_valid':True,
            'expected_decision':response['decision'],'material_kind':'synthetic_protocol'})
        if kind in {'direction','condition','purpose'}:
            wrong=support_response(request)
            cases.append({'case':kind+'_concealed_support','request':request,'response':wrong,'expected_valid':False,'expected_decision':None,'material_kind':'synthetic_protocol'})
    summary=make_request(toy_side('query_summary',summary=True),toy_side('reference_summary',summary=True));p=support_response(summary)
    cases.append({'case':'summary_preserved','request':summary,'response':p,'expected_valid':True,'expected_decision':'\u652f\u6301\u5339\u914d','material_kind':'synthetic_protocol'})
    upgrade=deepcopy(p);upgrade['relation_mappings'][0]['claims_complete_fine_path']=True
    cases.append({'case':'summary_upgrade','request':summary,'response':upgrade,'expected_valid':False,'expected_decision':None,'material_kind':'synthetic_protocol'})
    many=make_request(toy_side('query_many'),toy_side('reference_many',chain=True));p=support_response(many,action_groups=[(['left'],['left']),(['right'],['right','tail'])])
    cases.append({'case':'one_to_many','request':many,'response':p,'expected_valid':True,'expected_decision':'\u652f\u6301\u5339\u914d','material_kind':'synthetic_protocol'})
    reverse_many=make_request(toy_side('query_many_to_one',chain=True),toy_side('reference_many_to_one'))
    p=support_response(reverse_many,action_groups=[(['left'],['left']),(['right','tail'],['right'])])
    cases.append({'case':'many_to_one','request':reverse_many,'response':p,'expected_valid':True,'expected_decision':'\u652f\u6301\u5339\u914d','material_kind':'synthetic_protocol'})
    p=support_response(many,action_groups=[(['left'],['left']),(['right'],['right'])],reference_links=['flow0'])
    cases.append({'case':'partial_scope','request':many,'response':p,'expected_valid':True,'expected_decision':'\u652f\u6301\u5339\u914d','material_kind':'synthetic_protocol'})
    p=deepcopy(p);p['scope']='full'
    cases.append({'case':'partial_claimed_full','request':many,'response':p,'expected_valid':False,'expected_decision':None,'material_kind':'synthetic_protocol'})
    request=cases[0]['request'];base=cases[0]['response']
    for name,change in [('missing_conditions',lambda p:p.update(condition_mappings=[])),('empty_support',lambda p:p.update(scope='none'))]:
        p=deepcopy(base);change(p)
        cases.append({'case':name,'request':request,'response':p,'expected_valid':False,'expected_decision':None,'material_kind':'synthetic_protocol'})
    request=cases[0]['request'];base=cases[0]['response']
    for kind in ['fabricated_ref','wrong_binding','wrong_context','wrong_type','condition_scope','silent_unmapped','wrong_pair','certain_execution']:
        p=deepcopy(base)
        if kind=='fabricated_ref':p['relation_mappings'][0]['query']['support_path']=['rel_000000000000']
        elif kind=='wrong_binding':p['relation_mappings'][0]['query']['binding_refs']=['bind_000000000000']
        elif kind=='wrong_context':p['relation_mappings'][0]['query']['context_refs']=['synthetic:other_frame']
        elif kind=='wrong_type':p['relation_mappings'][0]['relation_kind']='control_constraint'
        elif kind=='condition_scope':p['condition_mappings'][0]['affected_mappings']=['actions0']
        elif kind=='silent_unmapped':p['unmapped']['query_actions']=['left']
        elif kind=='wrong_pair':p['request_id']='other-request'
        else:p['execution_claim']='executed'
        cases.append({'case':kind,'request':request,'response':p,'expected_valid':False,'expected_decision':None,'material_kind':'synthetic_protocol'})
    return cases
