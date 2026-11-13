"""Deterministic native-BC -> semantics -> text, with a separate source map.

Only semantic fields and explicitly supported condition/effect models enter
text. Registry records, original endpoints and locators stay in the audit map.
"""
from copy import deepcopy
import json,re
from androserum.facts.identity import canonical_json
from androserum.mining.models import Action,BehaviorChain

REF=re.compile(r'\b(?:analysis|instruction|method|class|dex|field|parameter|context|relation|binding|condition|status|resource|configuration|run|snapshot|bu|bu-task|bu-run|qualified|request|attempt|mining-run):[A-Za-z0-9_.-]+')
HANDLE=re.compile(r'\b(?:op|ep|rel|cond|bind|effect|fact)_[0-9a-f]{12}\b')
ADDRESS=re.compile(r'\b(?:code\+|DEX\s*(?:offset\s*)?|byte\s*(?:offset\s*)?)?0x[0-9a-fA-F]+\b',re.I)
RESOURCE_NUMBER=re.compile(r'\b(resource\s+(?:selector|id))\s+(?:0x[0-9a-f]+|[0-9]{6,})\b',re.I)
API_MODEL='model:audiorecord-short-buffer-v1';RANGE_MODEL='model:audio-read-sites-v1'
DATA={'data_dependency','field_dependency','array_dependency'}


def _tail(text):
    start=(text or '').find('{')
    if start<0:raise ValueError('Supported semantic model lacks its structured payload')
    return json.loads(text[start:])


class Projector:
    def __init__(self,entry):
        self.entry=entry;self.registry=entry['model_visible_evidence']['registry']
        self.bc=BehaviorChain.model_validate({k:entry['bc'][k] for k in BehaviorChain.model_fields}).model_dump(mode='json')
        self.actions={k:Action.model_validate({f:entry['actions'][k][f] for f in Action.model_fields}).model_dump(mode='json') for k in self.bc['action_ids']}
        self.action_alias={key:'Action'+str(i+1) for i,key in enumerate(self.bc['action_ids'])}
        self.facts={e['record_ref']:e['record'] for e in self.registry.values() if e['category']=='fact'}
        self.conditions={};self.effects={};self.endpoints={};self.extra_endpoint_count={};self.audit={'actions':{},'endpoints':{},'conditions':{},'effects':{},'relations':{}}
        self.internal_names=set();self.class_names=set()
        for record in self.facts.values():
            if record.get('kind')=='method' and record.get('body_status')=='available':
                sig=record['signature'];owner,name=sig.split('->',1);name=name.split('(',1)[0]
                if re.fullmatch(r'[A-Za-z_$][\w$]*',name):self.internal_names.add(name)
                self.class_names.add(owner[1:-1].split('/')[-1])
        self.range_conditions={}
        for h,e in self.registry.items():
            if e['category']!='condition':continue
            record=self.facts.get(e['record_ref'],{})
            if record.get('provenance',{}).get('rule_ref')==RANGE_MODEL:
                node=self.facts.get(record['value_endpoint']['element_ref'])
                if node is None:raise ValueError('Selected element condition is not visible')
                self.range_conditions[h]=_tail(node['text'])
        # A recorded loop guard can be interpreted only through the selected,
        # already checked finite-range model that explicitly cites that guard.
        self.loop_conditions=set()
        for e in self.registry.values():
            if e['category']!='relation':continue
            raw=self.facts.get(e['record_ref'],{})
            if raw.get('provenance',{}).get('rule_ref')==RANGE_MODEL:
                if not set(e['condition_refs']) & set(self.range_conditions):raise ValueError('Selected range relation has no visible element condition')
                self.loop_conditions.update(h for h in e['condition_refs'] if self.registry[h]['scope']=='local_operation_only')

    def clean(self,text):
        text=RESOURCE_NUMBER.sub(r'\1 [resource identity in audit]',text)
        text=REF.sub('[program locator in audit]',text);text=HANDLE.sub('[evidence locator in audit]',text)
        text=ADDRESS.sub('[program location in audit]',text)
        for name in sorted(self.class_names,key=lambda x:(-len(x),x)):
            text=re.sub(r'(?<![\w$])'+re.escape(name)+r'(?![\w$])','application object',text)
        for name in sorted(self.internal_names,key=lambda x:(-len(x),x)):
            text=re.sub(r'(?<![\w$])'+re.escape(name)+r'(?![\w$])','application helper',text)
        text=re.sub(r'application object\.application helper\([^)]*\)','application helper',text)
        return re.sub(r'\s+',' ',text).strip()

    def get(self,handle,category):
        value=self.registry.get(handle)
        if value is None or value['category']!=category:raise ValueError('Missing/wrong visible evidence category: '+str(handle))
        return value

    def endpoint(self,action_id,handle,role='internal value'):
        e=self.get(handle,'endpoint');key=(action_id,handle)
        if key not in self.endpoints:
            alias=self.action_alias[action_id]
            n=self.extra_endpoint_count.get((action_id,role),0)+1;self.extra_endpoint_count[action_id,role]=n
            label=alias+'.'+role.replace(' ','_')+str(n)
            self.endpoints[key]=label
            self.audit['endpoints'][label]={'handle':handle,'record_endpoint':deepcopy(e['endpoint']),
                'owner_operation_ref':e['owner_operation_ref'],'action_id':action_id}
        return self.endpoints[key]

    def field(self,field,action_id=None,role=None):
        result={'availability':field['availability'],'description':self.clean(field['description'])}
        if action_id is not None:
            result['semantic_endpoints']=[self.endpoint(action_id,h,role) for h in field['endpoint_refs']]
        return result

    def expression(self,value):
        kind=value['kind']
        if kind=='constant':return {'kind':'constant','value':value['value']}
        if kind=='recorded_symbol':return {'kind':'unknown numeric symbol','origin':value['origin_kind'].replace('_',' '),'concrete_value':'unknown'}
        if kind=='java_int_subtract_one':return {'kind':'integer subtraction by one','input':self.expression(value['input']),
            'arithmetic':'signed int32 wrap; concrete value unknown'}
        raise ValueError('Unsupported semantic expression model')

    def range_semantics(self,payload):
        r=payload['ranges']
        if r['all_iterations_written_claimed'] or r['separate_field_reads_equal_assumed']:
            raise ValueError('Selected range proof cannot claim all elements written or equal field reads')
        result={'symbols':{
            'L':{'meaning':'buffer allocation length','expression':self.expression(r['allocation_length']['expression'])},
            'C':{'meaning':'requested read count','expression':self.expression(r['requested_count']['expression'])},
            'n':{'meaning':'actual count returned by this read','value':'unknown'},
            'i':{'meaning':'selected loop index'}},'offset':r['offset'],
            'actual_written_range':self.clean(r['actual_written']),'loop_index_domain':self.clean(r['loop_reads']),
            'eligible_written_subset':self.clean(r['eligible_written_subset']),
            'required_predicates':[self.clean(x) for x in r['element_preconditions']],
            'all_loop_iterations_written':False,'equality_of_separate_field_reads_assumed':False,
            'actual_return_count_known':payload['return_evidence']['runtime_value_known']}
        if result['actual_return_count_known']:raise ValueError('This selected model does not observe a runtime return count')
        # If a caller tested n, keep that predicate too. Only its semantic
        # operator/literal/truth are copied, never the original branch endpoint.
        result['normal_witness_return_predicates']=[{'operator':p['normalized_operator'],'constant':p['constant'],
            'meaning':'actual returned n must satisfy this recorded path predicate'} for p in payload.get('normal_witness_return_predicates',[])]
        return result

    def condition(self,handle):
        if handle in self.conditions:return self.conditions[handle]['alias']
        e=self.get(handle,'condition');record=self.facts.get(e['record_ref'])
        if record is None:raise ValueError('Missing visible condition fact')
        expected=e['expected_value']
        if expected['status']!='known' or type(expected['value']) is not bool:raise ValueError('Unsupported condition truth representation')
        alias='Condition'+str(len(self.conditions)+1);model=record.get('provenance',{}).get('rule_ref')
        if e['scope']=='model_relation_precondition_not_execution_guard':
            if model==API_MODEL:
                value={'alias':alias,'kind':'model precondition','predicate':'Applicable framework implementation, valid request and normal return n > 0',
                    'predicate_required':expected['value'],'runtime_established':False,
                    'scope':'only the attached modeled state relationship; not a program execution guard'}
            elif model==RANGE_MODEL:
                value={'alias':alias,'kind':'model precondition','predicate':'Selected element satisfies i < n; i < L alone is insufficient',
                    'predicate_required':expected['value'],'runtime_established':False,
                    'scope':'only the attached selected element transfer','range':self.range_semantics(self.range_conditions[handle])}
            else:raise ValueError('Unsupported condition model; refusing to omit it')
        elif e['scope']=='local_operation_only' and handle in self.loop_conditions and model=='rule:control':
            if not expected['value']:raise ValueError('Frozen strict-less-than loop guard truth is inconsistent')
            value={'alias':alias,'kind':'recorded local control predicate','predicate':'selected loop index i < buffer length L',
                'predicate_required':True,'runtime_established':False,'scope':'only the attached loop operations; not the entire behavior'}
        else:raise ValueError('Unsupported local condition; refusing raw-code dumping or silent omission')
        self.conditions[handle]=value
        self.audit['conditions'][alias]={'handle':handle,'record_ref':e['record_ref'],'branch_ref':e['branch_ref'],
            'scope':e['scope'],'original_condition':deepcopy(record)}
        return alias

    def effect(self,handle):
        if handle in self.effects:return self.effects[handle]['alias']
        e=self.get(handle,'effect');raw=self.facts.get(e['record_ref'],{})
        if raw.get('provenance',{}).get('rule_ref')!=API_MODEL:raise ValueError('Unsupported state effect model')
        payload=_tail(raw['text']);alias='Effect'+str(len(self.effects)+1)
        value={'alias':alias,'kind':'conditional modeled short-buffer write','execution':'possible only',
            'required':'applicable framework implementation, valid request and normal positive return',
            'written_extent':'[offset, offset+n), not the entire requested range',
            'offset':payload['offset'],'requested_count':payload['requested_count'] if payload['requested_count'] is not None else 'unknown concrete count',
            'allocation_length':payload['allocation_length'] if payload['allocation_length'] is not None else 'unknown concrete length',
            'actual_count':'unknown','sample_values':'unknown','success_established':False}
        if payload['known_invalid_request']:raise ValueError('Invalid request cannot supply a successful write effect')
        self.effects[handle]=value;self.audit['effects'][alias]={'handle':handle,'record_ref':e['record_ref'],'record':deepcopy(raw)}
        return alias

    def validate_link(self,link):
        path=[self.get(h,'relation') for h in link['support_path']]
        if not path or path[0]['source_endpoint_ref']!=link['source_endpoint_ref'] or path[-1]['target_endpoint_ref']!=link['target_endpoint_ref']:
            raise ValueError('Broken relation endpoints')
        if any(a['target_endpoint_ref']!=b['source_endpoint_ref'] for a,b in zip(path,path[1:])):raise ValueError('Disconnected support path')
        if any(e['unresolved_condition_refs'] for e in path):raise ValueError('Unexposed relation conditions cannot be dropped')
        if set(link['condition_refs'])!={h for e in path for h in e['condition_refs']}:raise ValueError('Relation conditions differ from evidence')
        if set(link['binding_refs'])!={h for e in path for h in e['binding_refs']}:raise ValueError('Relation bindings differ from evidence')
        kinds={e['kind'] for e in path};modeled=any(e['provenance_kind']=='model_assisted' for e in path)
        if kinds<=DATA:kind,strength='data_transfer','model_assisted_relation' if modeled else 'recorded_dependency_path'
        elif kinds<=DATA|{'state_dependency'}:kind,strength='state_transfer','model_assisted_relation'
        elif 'information_flow' in kinds:kind,strength='information_flow','information_flow_summary'
        else:raise ValueError('Unsupported semantic relationship profile')
        if link['relation_kind']!=kind or link['evidence_strength']!=strength:raise ValueError('Relationship type/strength cannot be upgraded')
        return path

    def project(self):
        actions=[]
        # Populate endpoint aliases from semantic fields before relationship
        # endpoints. No alias ordering depends on program IDs or addresses.
        for key in self.bc['action_ids']:
            a=self.actions[key];alias=self.action_alias[key]
            self.audit['actions'][alias]={'action_id':key,'operation_refs':a['operation_refs']}
            fields={f:self.field(a[f],key,role) for f,role in [('objects','object'),('inputs','input'),('outputs','output')]}
            conditions=[self.condition(h) for h in a['condition_refs']]
            if (a['condition_status']=='recorded_local')!=bool(conditions):raise ValueError('Local guard availability is inconsistent')
            actions.append({'alias':alias,'function':self.clean(a['function']),**fields,
                'local_guard_availability':a['condition_status'],'local_conditions':conditions,
                'effects':[self.effect(h) for h in a['effect_refs']],
                'limits':[self.clean(x) for x in a['limitation_notes']]})
        relations=[]
        for i,link in enumerate(self.bc['relations']):
            self.validate_link(link);alias='Relation'+str(i+1)
            if link['from_action'] not in self.actions or link['to_action'] not in self.actions:raise ValueError('Relationship references missing semantic action')
            bindings=[self.get(h,'binding') for h in link['binding_refs']]
            value={'alias':alias,'from_action':self.action_alias[link['from_action']],
                'to_action':self.action_alias[link['to_action']],
                'source':self.endpoint(link['from_action'],link['source_endpoint_ref']),
                'target':self.endpoint(link['to_action'],link['target_endpoint_ref']),
                'kind':link['relation_kind'],'evidence_basis':link['evidence_strength'],
                'execution':'possible only','conditions':[self.condition(h) for h in link['condition_refs']],
                'binding_kinds':sorted({b['binding_kind'] for b in bindings}),
                'binding_scope':'same selected buffer through recorded bound calls' if link['relation_kind']=='state_transfer' else
                    'recorded operation values in their own bound invocation contexts; no guaranteed execution order'}
            relations.append(value);self.audit['relations'][alias]={'link_id':link['link_id'],'source_link':deepcopy(link)}
        scopes=[];seen=set()
        for source in self.entry['bc'].get('source_limits',[]):
            status=source['status'];coverage=dict(sorted(status['coverage'].items()))
            item={'state':status['state'],'coverage':coverage,'complete_behavior_claimed':False}
            key=canonical_json(item)
            if key not in seen:scopes.append(item);seen.add(key)
        projection={'schema_version':'bc-semantics.v1','behavior':self.clean(self.bc['description']),'execution':'possible only',
            'boundary':{'inputs':self.field(self.bc['boundary']['inputs']),'outputs':self.field(self.bc['boundary']['outputs']),
                'potential_effects':self.clean(self.bc['boundary']['potential_effects']),
                'conditions':[self.condition(h) for h in self.bc['boundary']['condition_refs']],
                'absence_of_common_conditions_is_unconditional':False},
            'actions':actions,'relations':relations,'conditions':list(self.conditions.values()),'effects':list(self.effects.values()),
            'limits':[self.clean(x) for x in self.bc['limitation_notes']],'analysis_scope':scopes}
        return projection,self.audit


def semantic_records(projection):
    """Records are the indivisible packing units. They contain no audit refs."""
    records=[]
    def add(key,title,value):
        # JSON here serializes the *whitelisted semantic projection*, never a
        # native program fact or a source registry dump.
        text=title+'\n'+json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)
        records.append({'key':key,'text':text})
    add('behavior','Behavior and boundary (possible only)',{k:projection[k] for k in ['behavior','execution','boundary']})
    for a in projection['actions']:add(a['alias'],a['alias']+' local function',a)
    for c in projection['conditions']:add(c['alias'],c['alias']+' required condition; not observed execution',c)
    for e in projection['effects']:add(e['alias'],e['alias']+' potential state effect',e)
    for r in projection['relations']:add(r['alias'],r['alias']+' possible typed relationship',r)
    for i,limit in enumerate(projection['limits']):add('Limit'+str(i+1),'Behavior limitation',{'description':limit})
    for i,scope in enumerate(projection['analysis_scope']):add('Scope'+str(i+1),'Analysis coverage and unknown scope',scope)
    return records


def serialize_entry(entry):
    projection,audit=Projector(entry).project();units=semantic_records(projection)
    text='';spans=[]
    for unit in units:
        if text:text+='\n\n'
        start=len(text);text+=unit['text'];spans.append({**unit,'char_start':start,'char_end':len(text)})
    if REF.search(text) or HANDLE.search(text) or ADDRESS.search(text):raise ValueError('Program locator leaked into semantic text')
    return {'projection':projection,'text':text+'\n','records':spans,'audit':audit}
