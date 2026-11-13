"""Per-round bounded policy; datasets and historical labels are not inference inputs."""
from pydantic import Field
from androserum.facts.models import StrictModel
from androserum.mining.models import MiningConfig, CurrentMiningConfig


class PipelineConfig(StrictModel):
    schema_version: str = 'apk-behavior-pipeline-config.v1'
    max_sapi_roots: int = Field(default=32,ge=1,le=1000)
    max_bu: int = Field(default=64,ge=1,le=100000)
    max_bu_tasks: int = Field(default=2000,ge=1,le=100000)
    top_k: int = Field(default=2,ge=1,le=10)
    max_matches_per_sample: int = Field(default=8,ge=0,le=10000)
    max_task_attempts: int = Field(default=6,ge=1,le=10000)
    max_task_queries: int = Field(default=2,ge=0,le=16)
    max_response_chars: int = Field(default=60000,ge=1000,le=120000)
    max_compact_request_chars: int = Field(default=400000,ge=10000,le=1000000)
    timeout_seconds: int = Field(default=300,ge=1,le=1800)
    mining: MiningConfig | CurrentMiningConfig = Field(default_factory=lambda:MiningConfig(
        max_bu=64,max_chunks=24,max_request_chars=350000,max_chunk_chars=65000,
        max_ledger_context_chars=140000,max_model_calls=16,max_repairs_per_chunk=1,
        max_supplement_rounds=1,max_supplement_records=4,max_response_chars=60000,
        model_timeout_seconds=300,max_actions=96,max_bcs=32,max_queries_per_proposal=2))
