"""Generalized v2 APK task ledger, separate from the frozen two-BC v1 trial.

The transaction, source-authority and query machinery is reused unchanged.
Single-BC final synthesis is permitted; zero approved BCs have an explicit
deterministic insufficient-evidence outcome instead of a fabricated finding.
"""
from copy import deepcopy
from typing import Literal

from pydantic import Field

from androserum.facts.identity import canonical_json, fingerprint
from androserum.tasking.checker import check_task
from androserum.tasking.ledger import TaskLedger, _source_check
from androserum.tasking.models import Synthesis, TaskConfig, TaskProposal
from androserum.tasking.prompt import TASK_PROMPT


class GeneralSynthesis(Synthesis):
    bc_ids: list[str] = Field(min_length=1)


class GeneralTaskProposal(TaskProposal):
    schema_version: Literal['apk-task-proposal.v2']
    synthesis: GeneralSynthesis | None


def proposal_schema():
    return GeneralTaskProposal.model_json_schema()


PROMPT = TASK_PROMPT.replace('at least two current BCs', 'at least one current BC') + '''
This is the generalized v2 task protocol. Return schema_version apk-task-proposal.v2.
The approved current BC list is specific to this APK and this frozen run; no fixed
BC identities or count are assumed. A final report can cover one BC and then has
no cross-BC link. Cover every accepted finding, preserve all known limitations and
open issues, and do not invent a second BC to satisfy an older trial's constraint.
Zero approved BCs are handled by the deterministic insufficient-evidence terminal
path outside model generation; absence of an approved BC proves no benignness.
'''


MATCHING_V2_REFERENCE_INSTRUCTIONS = '''
An accepted matching v2 reference may use an action_internal path. This is not a
BC link: do not invent a link_id or add internal relation handles to scope.link_ids.
Select its actual current action in the finding, cite every current support_path
record in evidence_refs, and retain its exact current condition_refs in addition
to the selected action/BC-link conditions. Use only authorized accepted mapping
IDs and their scoped condition mappings. Historical endpoints and evidence never
become current evidence. Do not expand the accepted functional or path scope.
'''


class GeneralTaskLedger(TaskLedger):
    """V2 source-bound task revisions with explicit 0/1/many-BC behavior."""

    def _protocol_contract(self):
        return {'schema_version': 'apk-task-ledger-protocol.v2',
                'proposal_schema_version': 'apk-task-proposal.v2',
                'proposal_schema_sha256': fingerprint(proposal_schema()),
                'minimum_synthesis_bcs': 1,
                'empty_catalog_policy': 'deterministic_evidence_insufficient'}

    def _validate_source(self, identity, catalog, config):
        return _source_check(identity, catalog, config, allow_empty=True)

    def _shape_packet(self, packet):
        packet['schema_version'] = 'apk-task-request.v2'
        packet['proposal_contract'] = self._protocol_contract()
        return packet

    def prepare_packet(self, *args, **kwargs):
        if not self.catalog['bcs']:
            raise ValueError('No approved BCs: use finalize_empty for an evidence_insufficient outcome; no model proposal is required')
        if self.state().get('empty_result') is not None:
            raise ValueError('An insufficient-evidence terminal ledger cannot accept further proposals')
        return super().prepare_packet(*args, **kwargs)

    def check_proposal(self, raw, packet, state):
        return check_task(raw, packet, state, self.config,
                          proposal_model=GeneralTaskProposal, min_bcs=1)

    def finalize_empty(self, reason, *, source_limits=(), coverage=None):
        """Audit an empty extraction/approval result without any model call.

        ``coverage`` records upstream counts/statuses; it cannot become an action,
        finding or proof that behavior is absent. Replaying the same terminal
        result is idempotent. A changed result requires a new frozen run/ledger.
        """
        if self.catalog['bcs']:
            raise ValueError('Nonempty approved catalog requires checked model task analysis')
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError('Insufficient-evidence result requires the concrete upstream reason')
        if any(not isinstance(value, str) for value in source_limits):
            raise ValueError('Source limitations must be explicit strings')
        result = {'schema_version': 'apk-task-empty-result.v2',
                  'status': 'evidence_insufficient', 'identity': deepcopy(self.identity),
                  'approved_bc_count': 0, 'findings': [], 'synthesis': None,
                  'reason': reason, 'source_limits': list(source_limits),
                  'upstream_coverage': deepcopy(coverage or {}),
                  'limitations': ['No approved behavior representation is available in this frozen run.',
                                  'Missing or unapproved evidence does not establish behavior absence or benignness.'],
                  'unresolved': ['Behavior interpretation cannot be completed from the current approved BC list.'],
                  'execution_claim': 'possible_only', 'absence_proves_benign': False,
                  'llm_calls_for_empty_finalization': 0}
        # Reject non-JSON coverage before opening a transaction.
        canonical_json(result)
        self.db.execute('BEGIN IMMEDIATE')
        try:
            state = self.state()
            existing = state.get('empty_result')
            if existing is not None:
                if existing != result:
                    raise ValueError('Frozen insufficient-evidence outcome cannot change on resume')
                self.db.execute('COMMIT')
                return deepcopy(existing)
            if state['findings'] or state['synthesis'] is not None:
                raise ValueError('An empty outcome cannot replace accepted behavior findings')
            before = fingerprint(state)
            state['revision'] += 1
            state['empty_result'] = deepcopy(result)
            self._insert_state(state, before)
            self._audit({'kind': 'empty_finalization', 'result': deepcopy(result),
                         'before_sha256': before, 'after_sha256': fingerprint(state),
                         'model_generation_used': False})
            self.db.execute('COMMIT')
            return deepcopy(result)
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def report(self):
        report = super().report()
        report['proposal_contract'] = self._protocol_contract()
        state = report['state']
        report['outcome'] = (deepcopy(state['empty_result']) if state.get('empty_result') is not None else
                             {'status': 'completed' if state['synthesis'] else 'incomplete',
                              'approved_bc_count': len(self.catalog['bcs']),
                              'absence_proves_benign': False,
                              'synthesis': deepcopy(state['synthesis'])})
        return report


__all__ = ['GeneralTaskLedger', 'GeneralTaskProposal', 'GeneralSynthesis',
           'TaskConfig', 'proposal_schema', 'PROMPT', 'MATCHING_V2_REFERENCE_INSTRUCTIONS']
