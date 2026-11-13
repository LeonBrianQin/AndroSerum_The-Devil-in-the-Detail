"""Model-facing proposal contract; actual program references use shown handles."""
from typing import Literal
from pydantic import Field, StringConstraints
from typing_extensions import Annotated
from androserum.facts.models import StrictModel

Name = Annotated[str, StringConstraints(pattern=r'^[a-z][a-z0-9_]{0,63}$')]
Handle = Annotated[str, StringConstraints(pattern=r'^(op|ep|rel|cond|bind|effect|fact)_[0-9a-f]{12}$')]
Description = Annotated[str, StringConstraints(min_length=1, max_length=3000)]


class SemanticField(StrictModel):
    availability: Literal['supported', 'unknown', 'not_applicable']
    description: Description
    endpoint_refs: list[Handle]


class Action(StrictModel):
    action_id: Name
    function: Description
    operation_refs: list[Handle] = Field(min_length=1, max_length=32)
    objects: SemanticField
    inputs: SemanticField
    outputs: SemanticField
    condition_status: Literal['recorded_local', 'unknown']
    condition_refs: list[Handle]
    effect_refs: list[Handle]
    support_relation_refs: list[Handle]
    support_fact_refs: list[Handle] = Field(default_factory=list)
    limitation_notes: list[Description]


class ActionLink(StrictModel):
    link_id: Name
    from_action: Name
    to_action: Name
    relation_kind: Literal['data_transfer', 'information_flow', 'state_transfer', 'icc_data', 'control_constraint', 'event_context', 'component_target']
    source_endpoint_ref: Handle
    target_endpoint_ref: Handle
    support_path: list[Handle] = Field(min_length=1, max_length=64)
    evidence_strength: Literal['recorded_dependency_path', 'information_flow_summary', 'model_assisted_relation']
    binding_refs: list[Handle]
    condition_refs: list[Handle]
    execution_claim: Literal['possible_only']


class Boundary(StrictModel):
    inputs: SemanticField
    outputs: SemanticField
    potential_effects: Description
    condition_refs: list[Handle]


class BehaviorChain(StrictModel):
    bc_id: Name
    description: Description
    action_ids: list[Name] = Field(min_length=1, max_length=64)
    relations: list[ActionLink]
    boundary: Boundary
    limitation_notes: list[Description]
    execution_claim: Literal['possible_only']


class UnresolvedItem(StrictModel):
    issue_id: Name
    subject_ids: list[Name]
    description: Description
    evidence_refs: list[Handle]
    status: Literal['open', 'resolved', 'unsupported', 'budget_exhausted']


class FactQuery(StrictModel):
    query_id: Name
    record_refs: list[str] = Field(min_length=1, max_length=16)
    reason: Description


class Proposal(StrictModel):
    schema_version: Literal['behavior-proposal.v1']
    request_id: str
    base_revision: int = Field(ge=0)
    upsert_actions: list[Action]
    delete_action_ids: list[Name]
    upsert_bcs: list[BehaviorChain]
    delete_bc_ids: list[Name]
    unresolved_updates: list[UnresolvedItem]
    fact_queries: list[FactQuery]
    rationale: Description


class MiningConfig(StrictModel):
    schema_version: Literal['mining-config.v1'] = 'mining-config.v1'
    max_bu: int = Field(default=4, ge=1, le=256)
    max_chunks: int = Field(default=24, ge=1, le=10000)
    max_request_chars: int = Field(default=100000, ge=4000, le=1000000)
    max_chunk_chars: int = Field(default=28000, ge=2000, le=500000)
    max_ledger_context_chars: int = Field(default=20000, ge=0, le=500000)
    max_model_calls: int = Field(default=32, ge=1, le=10000)
    max_repairs_per_chunk: int = Field(default=1, ge=0, le=8)
    max_supplement_rounds: int = Field(default=1, ge=0, le=16)
    max_supplement_records: int = Field(default=8, ge=0, le=1000)
    max_response_chars: int = Field(default=60000, ge=1000, le=1000000)
    model_timeout_seconds: int = Field(default=180, ge=1, le=1800)
    max_actions: int = Field(default=256, ge=1, le=10000)
    max_bcs: int = Field(default=128, ge=1, le=10000)
    max_queries_per_proposal: int = Field(default=4, ge=0, le=100)


def strict_model_schema(protocol=None):
    """Responses structured output requires every object property to be required."""
    schema = (CurrentProposal if protocol == 'current_facts.v1' else Proposal).model_json_schema()
    def visit(value):
        if isinstance(value, dict):
            if value.get('type') == 'object' and 'properties' in value:
                value['additionalProperties'] = False
                value['required'] = list(value['properties'])
            value.pop('default', None)
            for item in list(value.values()): visit(item)
        elif isinstance(value, list):
            for item in value: visit(item)
    visit(schema)
    return schema


# Versioned opt-in. The original proposal/config stay byte-compatible for
# historical replay; current-APK selectors are not silently granted to v1.
from androserum.facts.queries import CurrentFactQuery


class CurrentProposal(Proposal):
    fact_queries: list[CurrentFactQuery]


class CurrentMiningConfig(MiningConfig):
    schema_version: Literal['mining-config.v2'] = 'mining-config.v2'
    max_bu: int = Field(default=100000, ge=1, le=100000)
    max_chunks: int = Field(default=10000, ge=1, le=1000000)
    fact_query_protocol: Literal['current_facts.v1'] = 'current_facts.v1'
    max_query_return_chars: int = Field(default=150000, ge=0, le=5000000)
