"""Real three-way matching, isolated from the frozen fixed-response runner."""
import json
import hashlib
from pathlib import Path
from androserum.facts.identity import fingerprint
from androserum.matching.checker import check_match
from androserum.matching.models import MatchConfig, MatchProposal, MatchProposalV2, MatchProposalV3
from androserum.matching.decisions import english_protocol_text
from .provider import write,strict_schema


_MATCHING_ROOT = Path(__file__).parents[1]/'matching'
_LEGACY_BASE = json.loads((_MATCHING_ROOT/'legacy-prompt.json').read_text('utf-8'))['v1_base_prompt']
MATCH_PROMPT = _LEGACY_BASE + '''
For \u884c\u4e3a\u4e0d\u540c or \u8bc1\u636e\u4e0d\u8db3 you may provide empty action/relation/condition mappings,
scope none, list every unmapped action/link, and cite real displayed IDs in differences.
Do not invent correspondences just to explain a non-support decision.
For \u652f\u6301\u5339\u914d, copy exact complete path metadata from the displayed evidence.
Unknown/un-normalized conditions cannot be declared equivalent from prose alone.
When comparing full BC scope account for BC boundary conditions too. A legitimate
partial prefix is allowed only when its function, object use and actual relation
are supported on both sides; explicitly exclude unmatched effects and conditions.
'''


MATCH_PROMPT_V2 = MATCH_PROMPT + '''
This request explicitly uses behavior-match-request.v2. Return
schema_version behavior-match-proposal.v2 and use the typed path alternatives.
For path_kind bc_links, link_ids contains only actual IDs from that side's
bc.relations. support_path must concatenate those links' native support paths.
For path_kind action_internal, provide action_id and an ordered connected
support_path drawn only from that action's support_relation_refs. Do not provide
link_ids for an internal path. Never invent a link ID, use the words support_path
as an ID, or put raw rel_ handles in a BC link list. A path cannot mix these kinds.
Copy the exact directed endpoints, recorded contexts, bindings and conditions.
The internal path's endpoint operations and every owned intermediate operation
must belong to the selected action; unknown intermediate ownership stays unknown.
Different granularity is allowed: multiple connected actions on one side can
correspond to one composite action on the other. Put them in one action mapping
group. A relation mapping within that group's local function may name the same
group as from_mapping and to_mapping. The internal action must belong to that
group on its side. This does not create an inter-action BC link. Unmapped link
lists still concern only original BC links, never internal relation handles.
Keep all selected local and model conditions and their actual scopes. Do not add
empty condition mappings. A partial prefix may exclude downstream actions and
their guards, but the excluded scope and differences must remain explicit.
Shared sources or semantic plausibility cannot replace a supplied native path.
Information-flow summaries and modeled state evidence retain their original
strength, uncertainty and possible_only execution; they never prove execution.
'''


MATCH_PROMPT_V3 = (_MATCHING_ROOT/'prompt.txt').read_text('utf-8') + english_protocol_text(MATCH_PROMPT_V2[len(_LEGACY_BASE):])


def match_protocol(request):
    """The request version chooses the separately versioned schema and prompt."""
    version=request.get('schema_version','behavior-match-request.v1')
    if version=='behavior-match-request.v3':return MatchProposalV3,MATCH_PROMPT_V3
    if version=='behavior-match-request.v2':return MatchProposalV2,MATCH_PROMPT_V2
    if version=='behavior-match-request.v1':return MatchProposal,MATCH_PROMPT
    raise ValueError('Unknown matching protocol; do not silently reinterpret the request')


class ResumeIntegrityError(ValueError):
    """Retained output cannot be reused or repaired after an integrity failure."""


def _packet(request,feedback):
    value={k:v for k,v in request.items() if k!='source_audit'}
    if feedback:value['repair_feedback']=feedback
    return value


def _receipt(directory,packet,pair_id,index):
    path=directory/'receipt.json'
    if not path.exists():raise ResumeIntegrityError('Retained call receipt is missing')
    value=json.loads(path.read_text('utf-8'))
    prompt='REQUEST_JSON\n'+json.dumps(packet,ensure_ascii=False,separators=(',',':'))
    proposal_model,prompt_instructions=match_protocol(packet)
    expected={'call_id':pair_id+':'+str(index),'phase':'matching',
        'input_sha256':hashlib.sha256(prompt.encode('utf-8')).hexdigest(),
        'instruction_sha256':hashlib.sha256(prompt_instructions.encode('utf-8')).hexdigest(),
        'schema_sha256':fingerprint(strict_schema(proposal_model.model_json_schema()))}
    if any(value.get(k)!=v for k,v in expected.items()):
        raise ResumeIntegrityError('Retained call receipt does not match the frozen request, feedback, prompt or schema')
    persisted={'input.txt':prompt,'instructions.txt':prompt_instructions}
    if any(not (directory/name).exists() or (directory/name).read_text('utf-8')!=text for name,text in persisted.items()):
        raise ResumeIntegrityError('Retained input or instruction audit differs from the request actually checked')
    schema=directory/'proposal.schema.json'
    if not schema.exists() or json.loads(schema.read_text('utf-8'))!=strict_schema(proposal_model.model_json_schema()):
        raise ResumeIntegrityError('Retained output schema differs from the checked protocol')
    return value


def _completed(directory,packet,pair_id,index):
    receipt=_receipt(directory,packet,pair_id,index)
    if receipt.get('status')!='completed':raise ResumeIntegrityError('Retained call was not completed')
    path=directory/'raw-model-output.json'
    if not path.exists():raise ResumeIntegrityError('Retained completed call output is missing')
    raw=path.read_text('utf-8')
    # Provider receipts hash the decoded text, not platform-dependent newline
    # bytes. This also verifies the existing Windows CRLF baseline unchanged.
    if hashlib.sha256(raw.encode('utf-8')).hexdigest()!=receipt.get('output_sha256'):
        raise ResumeIntegrityError('Retained model output differs from its receipt hash')
    if receipt.get('tool_event_count')!=0 or receipt.get('cli_exit_code')!=0:
        raise ResumeIntegrityError('Retained completed call has invalid transport/tool metadata')
    return raw,receipt


def _retained_row(root,index,row,request,feedback,pair_id,accepted):
    directory=root/('attempt-'+str(index));packet=_packet(request,feedback)
    before=fingerprint(accepted);raw=''
    if row.get('transport_error') is None:
        raw,receipt=_completed(directory,packet,pair_id,index)
        if row.get('transport')!=receipt:raise ResumeIntegrityError('Retained check transport differs from its receipt')
        check=check_match(raw,request,MatchConfig())
    else:
        if (directory/'receipt.json').exists():
            receipt=_receipt(directory,packet,pair_id,index)
            if receipt.get('status')=='completed':raise ResumeIntegrityError('Completed retained output was reclassified as a transport failure')
            if row.get('transport') not in [None,receipt]:raise ResumeIntegrityError('Retained failed-call transport differs from its receipt')
            allowed={receipt.get('error'),'Previous failed real call retained on resume',
                'Interrupted reserved call retained; resume uses next budgeted attempt'}
        else:
            allowed={'Interrupted reserved call retained; resume uses next budgeted attempt',
                'Persistent real call budget exhausted',
                'Invocation ID already reserved; replay retained output instead of calling again',
                'Input budget exceeded; no evidence silently truncated'}
        if row['transport_error'] not in allowed:raise ResumeIntegrityError('Retained transport failure has no matching call record')
        check={'valid':False,'errors':[{'code':'transport','message':row['transport_error']}],'accepted':None}
    after=check['accepted'] if check['valid'] else accepted
    if (row.get('index')!=index or row.get('check')!=check or row.get('before_sha256')!=before
        or row.get('after_sha256')!=fingerprint(after) or row.get('rejected_update_preserved_state') is not True):
        raise ResumeIntegrityError('Retained program check or accepted-state chain does not replay from the original output')
    return after,raw


def run_pair(request, output, provider, budget, *, pair_id, max_attempts=2, seed=None):
    proposal_model,prompt_instructions=match_protocol(request)
    root=Path(output);root.mkdir(parents=True,exist_ok=True)
    old=json.loads((root/'report.json').read_text('utf-8')) if (root/'report.json').exists() else None
    if old and old['request_digest']!=fingerprint(request):raise ResumeIntegrityError('Resume cannot replace a match request')
    if (root/'request.json').exists() and json.loads((root/'request.json').read_text('utf-8'))!=request:
        raise ResumeIntegrityError('Resume cannot replace registered pair')
    if old and not (root/'request.json').exists():raise ResumeIntegrityError('Retained report request is missing')
    if not (root/'request.json').exists():write(root/'request.json',request)
    accepted=None;attempts=[];feedback=None
    seeded_path=root/'seeded-invalid.json'
    if seeded_path.exists():
        retained=json.loads(seeded_path.read_text('utf-8'))
        if retained.get('origin')!='explicit_programmatic_fault_injection_not_model_error':raise ResumeIntegrityError('Retained repair seed origin changed')
        if seed is not None and seed!=retained['proposal']:raise ResumeIntegrityError('Resume cannot replace the injected repair seed')
        seed=retained['proposal']
        checked=check_match(json.dumps(seed,ensure_ascii=False),request)
        if checked['valid'] or checked!=retained.get('check'):raise ResumeIntegrityError('Retained injected rejection no longer replays')
    elif old and seed is not None:raise ResumeIntegrityError('Resume cannot add a repair seed to a completed natural run')
    if seed is not None:
        checked=check_match(json.dumps(seed,ensure_ascii=False),request)
        if checked['valid']:raise ValueError('Injected repair seed must actually be rejected')
        if not seeded_path.exists():
            write(seeded_path,{'origin':'explicit_programmatic_fault_injection_not_model_error',
                'proposal':seed,'check':checked})
        feedback={'previous_proposal':seed,'program_check_errors':checked['errors'],
                  'origin':'explicit_programmatic_fault_injection_not_model_error'}
    for i in range(max_attempts):
        before=fingerprint(accepted)
        if (root/('check-'+str(i)+'.json')).exists():
            row=json.loads((root/('check-'+str(i)+'.json')).read_text('utf-8'))
            accepted,raw=_retained_row(root,i,row,request,feedback,pair_id,accepted)
            attempts.append(row)
            if row['check']['valid']:
                break
            feedback={'previous_raw':raw,'program_check_errors':row['check']['errors']}
            continue
        if old:raise ResumeIntegrityError('Retained final report has missing attempt checks')
        packet=_packet(request,feedback)
        error=None;metadata=None;raw=''
        try:
            call_dir=root/('attempt-'+str(i))
            if call_dir.exists():
                receipt=call_dir/'receipt.json';output=call_dir/'raw-model-output.json'
                if not receipt.exists() or not output.exists():raise ValueError('Interrupted reserved call retained; resume uses next budgeted attempt')
                metadata=json.loads(receipt.read_text('utf-8'))
                if metadata['status']!='completed':raise ValueError('Previous failed real call retained on resume')
                raw,metadata=_completed(call_dir,packet,pair_id,i)
            else:
                raw,metadata=provider.generate(packet,proposal_model.model_json_schema(),prompt_instructions,
                    call_dir,budget=budget,phase='matching',call_id=pair_id+':'+str(i))
            checked=check_match(raw,request,MatchConfig())
        except ResumeIntegrityError:raise
        except Exception as exc:
            error=str(exc);checked={'valid':False,'errors':[{'code':'transport','message':error}],'accepted':None}
        if checked['valid']:accepted=checked['accepted']
        row={'index':i,'check':checked,'transport':metadata,'transport_error':error,
             'before_sha256':before,'after_sha256':fingerprint(accepted),
             'rejected_update_preserved_state':checked['valid'] or before==fingerprint(accepted)}
        attempts.append(row);write(root/('check-'+str(i)+'.json'),row)
        if checked['valid']:break
        feedback={'previous_raw':raw,'program_check_errors':checked['errors']}
    report={'request_digest':fingerprint(request),'attempts':attempts,'accepted':accepted,
            'real_model':True,'seeded_repair_exercise':seed is not None,
            'status':'accepted' if accepted else 'unresolved_after_budget'}
    if old:
        if old!=report:raise ResumeIntegrityError('Retained final report does not replay from its checked attempts')
        accepted_path=root/'accepted.json'
        if not accepted_path.exists() or json.loads(accepted_path.read_text('utf-8'))!=accepted:
            raise ResumeIntegrityError('Retained accepted output differs from the replayed state')
        return old
    write(root/'accepted.json',accepted);write(root/'report.json',report)
    return report


def run_pair_v2(request,*args,**kwargs):
    if request.get('schema_version')!='behavior-match-request.v2':
        raise ValueError('Typed action-internal matching requires an explicit v2 request')
    return run_pair(request,*args,**kwargs)
