"""Three-way matching proposals; every correspondence is explicitly scoped."""
from typing import Literal
from pydantic import Field
from androserum.facts.models import StrictModel
from androserum.mining.models import Name,Handle,Description


class Citation(StrictModel):
    side:Literal['query','reference']
    kind:Literal['action','link','condition','evidence']
    ref:str=Field(min_length=1)


class ActionMapping(StrictModel):
    mapping_id:Name
    query_actions:list[Name]=Field(min_length=1,max_length=64)
    reference_actions:list[Name]=Field(min_length=1,max_length=64)
    object_and_io_correspondence:Description
    functional_basis:Description
    limitations:list[Description]


class PathSide(StrictModel):
    link_ids:list[Name]=Field(min_length=1,max_length=64)
    support_path:list[Handle]=Field(min_length=1,max_length=128)
    source_endpoint:Handle
    target_endpoint:Handle
    binding_refs:list[Handle]
    context_refs:list[str]
    condition_refs:list[Handle]


class EndpointCorrespondence(StrictModel):
    query_endpoint:Handle
    reference_endpoint:Handle
    query_role:Literal['source','target']


class RelationMapping(StrictModel):
    mapping_id:Name
    from_mapping:Name
    to_mapping:Name
    query:PathSide
    reference:PathSide
    endpoint_correspondence:list[EndpointCorrespondence]=Field(min_length=2,max_length=2)
    binding_basis:Description
    direction:Literal['aligned','reversed']
    relation_kind:Literal['data_transfer','information_flow','state_transfer','icc_data','control_constraint','event_context','component_target']
    evidence_strength:Literal['recorded_dependency_path','information_flow_summary','model_assisted_relation']
    claims_complete_fine_path:bool
    explanation:Description


class ConditionMapping(StrictModel):
    mapping_id:Name
    query_condition:Handle|None
    reference_condition:Handle|None
    comparison:Literal['equivalent','compatible_with_limits','conflict','unknown']
    affected_mappings:list[Name]
    explanation:Description


class Difference(StrictModel):
    difference_id:Name
    kind:Literal['direction','condition','purpose','function','evidence','coverage']
    impact:Literal['blocks_selected_scope','limits_reference_scope','unresolved']
    citations:list[Citation]=Field(min_length=1,max_length=64)
    explanation:Description


class Unmapped(StrictModel):
    query_actions:list[Name]
    reference_actions:list[Name]
    query_links:list[Name]
    reference_links:list[Name]


class MatchProposal(StrictModel):
    schema_version:Literal['behavior-match-proposal.v1']
    request_id:str
    pair_sha256:str
    decision:Literal['\u652f\u6301\u5339\u914d','\u884c\u4e3a\u4e0d\u540c','\u8bc1\u636e\u4e0d\u8db3']
    scope:Literal['full','partial','none']
    action_mappings:list[ActionMapping]=Field(max_length=64)
    relation_mappings:list[RelationMapping]=Field(max_length=64)
    condition_mappings:list[ConditionMapping]=Field(max_length=128)
    differences:list[Difference]=Field(max_length=128)
    unmapped:Unmapped
    limitations:list[Description]
    unresolved:list[Description]
    rationale:Description
    execution_claim:Literal['possible_only']
    unconditional_execution_claimed:Literal[False]


class BCLinkPathSideV2(PathSide):
    """Existing native BC links; action-internal selectors are forbidden."""
    path_kind:Literal['bc_links']


class ActionInternalPathSideV2(StrictModel):
    """A path explicitly supported inside one visible native action."""
    path_kind:Literal['action_internal']
    action_id:Name
    support_path:list[Handle]=Field(min_length=1,max_length=128)
    source_endpoint:Handle
    target_endpoint:Handle
    binding_refs:list[Handle]
    context_refs:list[str]
    condition_refs:list[Handle]


TypedPathSideV2 = BCLinkPathSideV2 | ActionInternalPathSideV2


class RelationMappingV2(RelationMapping):
    query:TypedPathSideV2
    reference:TypedPathSideV2


class MatchProposalV2(MatchProposal):
    schema_version:Literal['behavior-match-proposal.v2']
    relation_mappings:list[RelationMappingV2]=Field(max_length=64)


class MatchProposalV3(MatchProposalV2):
    """English wire decisions with the unchanged typed-path evidence rules."""
    schema_version:Literal['behavior-match-proposal.v3']
    decision:Literal['supported_match','different_behavior','insufficient_evidence']


class MatchConfig(StrictModel):
    schema_version:Literal['behavior-match-config.v1']='behavior-match-config.v1'
    max_pair_attempts:int=Field(default=2,ge=1,le=4)
    max_response_chars:int=Field(default=120000,ge=1000,le=500000)
    max_request_chars:int=Field(default=1000000,ge=10000,le=5000000)
    provider:Literal['fixed_responses_only']='fixed_responses_only'
