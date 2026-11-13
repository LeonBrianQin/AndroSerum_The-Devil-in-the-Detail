"""Bounded current-APK task analysis, separate from behavioral mining."""
from typing import Literal
from pydantic import Field
from androserum.facts.models import StrictModel


class TaskConfig(StrictModel):
    schema_version: Literal['apk-task-config.v1'] = 'apk-task-config.v1'
    task: Literal['evidence_supported_behavior_report'] = 'evidence_supported_behavior_report'
    max_attempts: int = Field(default=8, ge=1, le=10000)
    max_fact_queries: int = Field(default=2, ge=0, le=16)
    max_records_per_query: int = Field(default=4, ge=1, le=32)
    max_response_chars: int = Field(default=100000, ge=1000, le=1000000)
    max_packet_chars: int = Field(default=2000000, ge=10000, le=10000000)
    allow_synthetic_protocol: bool = False


class Scope(StrictModel):
    bc_id: str
    action_ids: list[str] = Field(min_length=1)
    link_ids: list[str]


class ReferenceUse(StrictModel):
    match_ref: str
    action_mapping_ids: list[str] = Field(min_length=1)
    relation_mapping_ids: list[str]
    condition_mapping_ids: list[str]
    scope_description: str = Field(min_length=1)
    limitations: list[str] = Field(min_length=1)


class Finding(StrictModel):
    finding_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    scopes: list[Scope] = Field(min_length=1)
    evidence_refs: list[str] = Field(min_length=1)
    condition_refs: list[str]
    reference_uses: list[ReferenceUse]
    limitations: list[str] = Field(min_length=1)
    execution_claim: Literal['possible_only']


class Issue(StrictModel):
    issue_id: str = Field(min_length=1)
    description: str = Field(min_length=1)
    bc_ids: list[str]
    finding_ids: list[str]
    evidence_refs: list[str]
    status: Literal['open', 'resolved']
    resolution: str | None


class FactQuery(StrictModel):
    query_id: str = Field(min_length=1)
    requested_refs: list[str] = Field(min_length=1)
    purpose: str = Field(min_length=1)
    issue_ids: list[str] = Field(min_length=1)


class CrossBCLink(StrictModel):
    link_id: str
    from_bc: str
    from_action: str
    to_bc: str
    to_action: str
    support_path: list[str] = Field(min_length=1)
    source_endpoint: str
    target_endpoint: str
    binding_refs: list[str]
    context_refs: list[str]
    condition_refs: list[str]
    relation_kind: Literal['data_transfer', 'information_flow', 'state_transfer', 'icc_data', 'control_constraint', 'event_context', 'component_target']
    evidence_strength: Literal['recorded_dependency_path', 'information_flow_summary', 'model_assisted_relation']
    claims_complete_fine_path: bool
    explanation: str = Field(min_length=1)


class Synthesis(StrictModel):
    summary: str = Field(min_length=1)
    finding_ids: list[str] = Field(min_length=1)
    bc_ids: list[str] = Field(min_length=2)
    cross_bc_links: list[CrossBCLink]
    unresolved_issue_ids: list[str]
    limitations: list[str] = Field(min_length=1)
    execution_claim: Literal['possible_only']
    absence_proves_benign: Literal[False]


class TaskProposal(StrictModel):
    schema_version: Literal['apk-task-proposal.v1']
    request_id: str
    base_revision: int = Field(ge=0)
    upsert_findings: list[Finding]
    delete_finding_ids: list[str]
    issue_updates: list[Issue]
    fact_queries: list[FactQuery]
    synthesis: Synthesis | None
    rationale: str = Field(min_length=1)


def proposal_schema():
    return TaskProposal.model_json_schema()
