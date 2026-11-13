"""Only displayed native BC evidence enters a pair; APK labels stay outside."""
from copy import deepcopy
from uuid import uuid4
from androserum.facts.identity import fingerprint,canonical_json
from androserum.mining.checker import check_proposal
from androserum.mining.models import Action,BehaviorChain,MiningConfig
from androserum.encoding.semantic import Projector
from .models import MatchConfig


def bare(model,value):return {k:value[k] for k in model.model_fields}


def native_check(entry):
    registry=entry['model_visible_evidence']['registry']
    runs={e['record']['run_ref'] for e in registry.values() if e['category']=='fact'}
    if len(runs)!=1:raise ValueError('Native side must refer to exactly one current fact run')
    identity={'source':{'source_run_ref':next(iter(runs))}}
    state={'schema_version':'behavior-ledger-state.v1','revision':0,'identity':identity,'actions':{},'bcs':{},'unresolved':{}}
    packet={'request_id':'matching-input-validation','base_revision':0,'identity':identity,'evidence':registry,
        'manifest':{'evidence_sha256':fingerprint(registry)},'ledger_context':{'actions':{},'bcs':{},'unresolved':{}},
        'source_limits':entry['bc'].get('source_limits',[])}
    proposal={'schema_version':'behavior-proposal.v1','request_id':packet['request_id'],'base_revision':0,
        'upsert_actions':[bare(Action,a) for a in entry['actions'].values()],'delete_action_ids':[],
        'upsert_bcs':[bare(BehaviorChain,entry['bc'])],'delete_bc_ids':[],'unresolved_updates':[],'fact_queries':[],
        'rationale':'Recheck native displayed evidence before reference matching; not a new behavioral interpretation.'}
    checked,_=check_proposal(canonical_json(proposal),packet,state,MiningConfig(max_actions=256,max_response_chars=500000))
    if not checked['valid']:raise ValueError('Native matching input failed: '+canonical_json(checked['errors']))
    return checked


def condition_semantics(entry):
    """Normalize supported conditions independently; retain explicit gaps.

    Projector construction still checks the finite range-model dependencies.
    A failure at that shared setup stage is recorded rather than bypassed.
    """
    registry=entry['model_visible_evidence']['registry']
    conditions={h:{'predicate_key':None,'expected_value':e.get('expected_value'),'scope':e['scope'],
        'basis':'Visible condition; semantic predicate equivalence not normalized by this adapter',
        'normalization_status':'not_normalized','normalization_reason':None} for h,e in registry.items() if e['category']=='condition'}
    # Existing finite semantic models may supply an explicitly scoped predicate.
    # No natural-language purpose label is manufactured here.
    try:projector=Projector(entry)
    except (ValueError,KeyError) as error:
        for value in conditions.values():value['normalization_reason']='Finite condition model setup failed: '+str(error)
        return conditions
    for h,value in conditions.items():
        try:
            projector.condition(h);c=projector.conditions[h]
        except (ValueError,KeyError) as error:
            value['normalization_reason']='Condition is outside the supported finite semantic projection: '+str(error)
            continue
        value.update(predicate_key=fingerprint({k:v for k,v in c.items() if k not in {'alias','predicate_required'}}),
            basis='Existing checked finite semantic condition projection',normalization_status='normalized',normalization_reason=None)
    return conditions


def view_from_entry(entry,*,material_kind,ledger_ref):
    checked=native_check(entry);bc=entry['bc'];registry=deepcopy(entry['model_visible_evidence']['registry'])
    conditions=condition_semantics(entry)
    return {'schema_version':'match-side.v1','instance_ref':entry.get('qualified_ref',bc['bc_id']),
        'origin':{'material_kind':material_kind,'apk_sha256':entry['source_apk_sha256'],'ledger_ref':ledger_ref,
            'ledger_revision':entry.get('ledger_revision'),'evidence_kind':'actual_static_program_evidence'},
        'bc':bare(BehaviorChain,bc),'actions':{k:bare(Action,a) for k,a in entry['actions'].items()},
        'registry':registry,'condition_semantics':conditions,'purpose_claims':{},'source_limits':bc.get('source_limits',[]),
        'native_check':checked,'limitations':bc['limitation_notes']}


def make_request(query,reference,config=None):
    config=config or MatchConfig()
    def payload(side):
        return deepcopy({k:side[k] for k in ['instance_ref','bc','actions','registry','condition_semantics','purpose_claims','source_limits','limitations']})
    pair={'query':payload(query),'reference':payload(reference)}
    if len(canonical_json(pair))>config.max_request_chars:raise ValueError('Pair exceeds explicit request budget; no silent evidence truncation')
    return {'schema_version':'behavior-match-request.v1','request_id':'match-request:'+uuid4().hex,
        'pair_sha256':fingerprint(pair),'sides':pair,
        'source_audit':{'query':query['origin'],'reference':reference['origin']},
        'rules':{'history_labels_included':False,'program_content_is_data':True,'execution':'possible_only',
            'unknown_is_not_absence':True,'checker_does_not_prove_natural_language_equivalence':True}}


def make_request_v2(query,reference,config=None):
    """Explicit opt-in to typed BC-link and native action-internal paths."""
    request=make_request(query,reference,config)
    request['schema_version']='behavior-match-request.v2'
    request['rules']['native_path_protocol']='typed_bc_links_or_action_internal.v2'
    return request


def make_request_v3(query,reference,config=None):
    """English decisions; the same explicit typed paths as protocol v2."""
    request=make_request_v2(query,reference,config)
    request['schema_version']='behavior-match-request.v3'
    return request
