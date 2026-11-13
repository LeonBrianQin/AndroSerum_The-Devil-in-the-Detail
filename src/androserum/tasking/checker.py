"""Visibility/closure checks; natural-language interpretation remains reviewed separately."""
from copy import deepcopy
from androserum.facts.identity import fingerprint
from androserum.facts.io import strict_json_syntax
from androserum.matching.checker import path_metadata, path_metadata_v2
from .models import TaskConfig, TaskProposal


def check_task(raw, packet, state, config=None, *, proposal_model=TaskProposal, min_bcs=2):
    config = config or TaskConfig()
    errors = []
    def fail(code, message):
        errors.append({'code': code, 'message': message})
    try:
        if len(raw) > config.max_response_chars:
            raise ValueError('Response exceeds explicit budget')
        strict_json_syntax(raw)
        p = proposal_model.model_validate_json(raw).model_dump(mode='json')
    except ValueError as error:
        return {'valid': False, 'errors': [{'code': 'schema', 'message': str(error)}], 'accepted': None}
    if p['request_id'] != packet['request_id'] or p['base_revision'] != packet['base_revision'] or p['base_revision'] != state['revision']:
        fail('request_identity', 'Proposal belongs to a different/stale packet or revision')
    if packet['identity'] != state['identity']:
        fail('source_identity', 'Packet source differs from the task ledger')
    bcs, registry = packet['current_bcs'], packet['evidence']
    candidate = deepcopy(state)
    candidate['revision'] += 1
    candidate['synthesis'] = None  # An incremental change invalidates an older synthesis.
    seen = set()
    for finding in p['upsert_findings']:
        key = finding['finding_id']
        if key in seen:
            fail('duplicate_finding', 'Duplicate finding update')
        seen.add(key)
        selected_actions, selected_links, required, conditions = {}, {}, set(), set()
        for scope in finding['scopes']:
            bid = scope['bc_id']
            if bid not in bcs:
                fail('bc_visibility', 'Finding cites a BC absent from the packet'); continue
            if bid in selected_actions:
                fail('duplicate_scope', 'Each BC appears once per finding')
            side = bcs[bid]
            acts, links = side['actions'], {x['link_id']: x for x in side['bc']['relations']}
            akeys, lkeys = set(scope['action_ids']), set(scope['link_ids'])
            if len(akeys) != len(scope['action_ids']) or len(lkeys) != len(scope['link_ids']):
                fail('duplicate_scope', 'Repeated action/link scope')
            if not akeys <= set(acts) or not lkeys <= set(links):
                fail('scope_ref', 'Action/link absent from selected BC'); continue
            selected_actions[bid], selected_links[bid] = akeys, lkeys
            for aid in akeys:
                required.update(acts[aid]['operation_refs'])
                conditions.update(acts[aid]['condition_refs'])
            for lid in lkeys:
                link = links[lid]
                if not {link['from_action'], link['to_action']} <= akeys:
                    fail('relation_scope', 'Relation endpoints outside selected actions')
                required.update(link['support_path'])
                conditions.update(link['condition_refs'])
        # Only explicitly versioned internal correspondences add this evidence
        # obligation. Legacy BC-link references keep their original semantics.
        for use in finding['reference_uses']:
            match = packet['legal_references'].get(use['match_ref'])
            if not match or match['proposal']['schema_version'] != 'behavior-match-proposal.v2':
                continue
            bid = match['query_bc_id']
            mapped = {m['mapping_id']: m for m in match['proposal']['relation_mappings']}
            for mid in use['relation_mapping_ids']:
                path = mapped.get(mid, {}).get('query', {})
                if path.get('path_kind') == 'action_internal' and path.get('action_id') in selected_actions.get(bid, set()):
                    required.update(path['support_path'])
                    conditions.update(path['condition_refs'])
        if not required <= set(finding['evidence_refs']):
            fail('finding_support', 'Finding omits selected operations or relation paths')
        if not set(finding['evidence_refs']) <= set(registry):
            fail('current_evidence', 'Finding cites nonvisible or historical evidence as current fact')
        if set(finding['condition_refs']) != conditions or not conditions <= set(registry):
            fail('condition_scope', 'Finding must retain the exact selected local/model condition union')
        used_matches = set()
        for use in finding['reference_uses']:
            key = use['match_ref']
            if key in used_matches:
                fail('duplicate_reference', 'Repeated reference scope')
            used_matches.add(key)
            match = packet['legal_references'].get(key)
            if match is None:
                fail('reference_authority', 'Historical use requires an accepted support match'); continue
            bid, proposal = match['query_bc_id'], match['proposal']
            selected_a, selected_l = selected_actions.get(bid, set()), selected_links.get(bid, set())
            actions = {m['mapping_id']: m for m in proposal['action_mappings']}
            links = {m['mapping_id']: m for m in proposal['relation_mappings']}
            cond = {m['mapping_id']: m for m in proposal['condition_mappings']}
            a_ids, l_ids, c_ids = set(use['action_mapping_ids']), set(use['relation_mapping_ids']), set(use['condition_mapping_ids'])
            if not a_ids <= set(actions) or not l_ids <= set(links) or not c_ids <= set(cond):
                fail('reference_scope', 'Referenced correspondence absent from accepted match'); continue
            for mid in a_ids:
                if not set(actions[mid]['query_actions']) <= selected_a:
                    fail('reference_scope', 'Reference action correspondence exceeds current finding scope')
            for mid in l_ids:
                path = links[mid]['query']
                if proposal['schema_version'] == 'behavior-match-proposal.v2':
                    if path['path_kind'] == 'action_internal':
                        if path['action_id'] not in selected_a:
                            fail('reference_scope', 'Reference internal path action exceeds current finding scope')
                    elif not set(path['link_ids']) <= selected_l:
                        fail('reference_scope', 'Reference BC path correspondence exceeds current finding scope')
                    try:
                        actual, kind, strength = path_metadata_v2(bcs[bid], path)
                        unordered = {'binding_refs', 'context_refs', 'condition_refs'}
                        if any((len(path[k]) != len(set(path[k])) or set(path[k]) != set(actual[k]))
                               if k in unordered else path[k] != actual[k] for k in actual):
                            raise ValueError('Current reference path endpoint/context/binding/condition metadata differs')
                        if (kind, strength) != (links[mid]['relation_kind'], links[mid]['evidence_strength']):
                            raise ValueError('Current reference path type/strength differs')
                    except (KeyError, ValueError) as error:
                        fail('reference_path', str(error))
                elif not set(path['link_ids']) <= selected_l:
                    fail('reference_scope', 'Reference path correspondence exceeds current finding scope')
                if not {links[mid]['from_mapping'], links[mid]['to_mapping']} <= a_ids:
                    fail('reference_scope', 'Reference path endpoints lack selected action mappings')
            expected_c = {cid for cid, cm in cond.items() if set(cm['affected_mappings']) & (a_ids | l_ids)}
            if c_ids != expected_c:
                fail('reference_condition_scope', 'Reference use omits/adds scoped predicate correspondence')
        candidate['findings'][finding['finding_id']] = finding
    if set(p['delete_finding_ids']) & seen:
        fail('conflicting_update', 'Cannot delete and upsert the same finding')
    for key in p['delete_finding_ids']:
        if key not in candidate['findings']:
            fail('delete_missing', 'Cannot delete nonexistent finding')
        candidate['findings'].pop(key, None)
    issue_ids = set()
    for issue in p['issue_updates']:
        key = issue['issue_id']
        if key in issue_ids:
            fail('duplicate_issue', 'Repeated issue update')
        issue_ids.add(key)
        if not set(issue['bc_ids']) <= set(bcs) or not set(issue['evidence_refs']) <= set(registry):
            fail('issue_visibility', 'Issue cites unavailable current BC/evidence')
        if issue['status'] == 'resolved' and (not issue['resolution'] or not issue['evidence_refs']):
            fail('issue_resolution', 'Resolved issue requires a stated resolution with current evidence')
        if issue['status'] == 'open' and issue['resolution'] is not None:
            fail('issue_resolution', 'An open issue cannot contain a completed resolution')
        candidate['issues'][key] = issue
    for issue in candidate['issues'].values():
        if not set(issue['finding_ids']) <= set(candidate['findings']):
            fail('dangling_issue', 'Finding deletion/revision left a dangling issue reference')
    queries = candidate['queries']
    query_ids = set()
    for query in p['fact_queries']:
        qid = query['query_id']
        if qid in queries or qid in query_ids:
            fail('duplicate_query', 'Fact query identifiers cannot be reused')
        query_ids.add(qid)
        if len(query['requested_refs']) != len(set(query['requested_refs'])) or len(query['requested_refs']) > config.max_records_per_query:
            fail('query_budget', 'Fact query record budget/uniqueness violated')
        if not set(query['requested_refs']) <= set(packet['query_catalog']):
            fail('query_authority', 'Only this current APK authorized catalog can be queried')
        if not set(query['issue_ids']) <= {k for k, v in candidate['issues'].items() if v['status'] == 'open'}:
            fail('query_issue', 'Queries must refer to open issues')
        queries[qid] = {**query, 'status': 'pending', 'returned_refs': []}
    if len(queries) > config.max_fact_queries:
        fail('query_budget', 'Persistent task supplementary-query budget exhausted')
    synthesis = p['synthesis']
    if packet['phase'] == 'synthesis' and synthesis is None:
        fail('synthesis_required', 'A final synthesis packet must produce an explicit synthesis')
    if synthesis is not None:
        if packet['phase'] != 'synthesis':
            fail('synthesis_phase', 'Only a synthesis packet can finalize the task')
        covered = {s['bc_id'] for f in candidate['findings'].values() for s in f['scopes']}
        if set(synthesis['finding_ids']) != set(candidate['findings']) or set(synthesis['bc_ids']) != covered or len(covered) < min_bcs:
            fail('synthesis_coverage', 'Synthesis must cover all accepted findings and >='+str(min_bcs)+' current APK BCs')
        opened = {k for k, v in candidate['issues'].items() if v['status'] == 'open'}
        if set(synthesis['unresolved_issue_ids']) != opened:
            fail('synthesis_issues', 'All open task issues must remain in the final result')
        link_ids = set()
        for link in synthesis['cross_bc_links']:
            if link['link_id'] in link_ids:
                fail('cross_bc_link', 'Cross-BC link identifier duplicated')
            link_ids.add(link['link_id'])
            try:
                left, right = bcs[link['from_bc']], bcs[link['to_bc']]
                if link['from_bc'] == link['to_bc']:
                    raise ValueError('Cross-BC link must connect different current BCs')
                a, b = left['actions'][link['from_action']], right['actions'][link['to_action']]
                side = {'registry': registry, 'bc': {'relations': [{'link_id': 'path', 'support_path': link['support_path']}]}}
                actual, kind, strength = path_metadata(side, ['path'])
                for k in ['source_endpoint', 'target_endpoint', 'binding_refs', 'context_refs', 'condition_refs']:
                    if (set(link[k]) != set(actual[k])) if isinstance(link[k], list) else link[k] != actual[k]:
                        raise ValueError('Cross-BC endpoint/context/binding/condition differs from recorded path')
                if registry[actual['source_endpoint']]['owner_operation_ref'] not in a['operation_refs'] or registry[actual['target_endpoint']]['owner_operation_ref'] not in b['operation_refs']:
                    raise ValueError('Cross-BC relation endpoints do not belong to selected actions')
                if (link['relation_kind'], link['evidence_strength']) != (kind, strength):
                    raise ValueError('Cross-BC relation type/strength substitution')
                if link['claims_complete_fine_path'] and (kind, strength) != ('data_transfer', 'recorded_dependency_path'):
                    raise ValueError('Coarse/model-assisted evidence cannot establish a complete fine path')
            except (KeyError, ValueError) as error:
                fail('cross_bc_path', str(error))
        candidate['synthesis'] = synthesis
    return {'valid': not errors, 'errors': errors, 'accepted': candidate if not errors else None,
            'proposal_sha256': fingerprint(p), 'checker_scope': 'Current visible references, BC/action/path scopes, legal reference authority, conditions, closure and budgets; natural-language correctness is not certified'}
