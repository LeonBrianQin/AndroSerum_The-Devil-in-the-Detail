"""Encoding policy is explicit and immutable for a published run."""
from typing import Literal
from pydantic import Field
from androserum.facts.models import StrictModel


class EncodingConfig(StrictModel):
    schema_version:Literal['bc-encoding-config.v1']='bc-encoding-config.v1'
    serializer_version:Literal['bc-semantics.v1','bc-semantics.v2']='bc-semantics.v1'
    repository:Literal['google-bert/bert-base-uncased']='google-bert/bert-base-uncased'
    revision:Literal['86b5e0934494bd15c9632b12f734a8a67f723594']='86b5e0934494bd15c9632b12f734a8a67f723594'
    max_tokens:int=Field(default=512,ge=64,le=512)
    oversize_unit:Literal['reject_without_truncation']='reject_without_truncation'
    chunk_boundary:Literal['semantic_record']='semantic_record'
    token_pooling:Literal['last_hidden_mean_without_padding_or_special']='last_hidden_mean_without_padding_or_special'
    bc_pooling:Literal['unweighted_mean_of_raw_chunk_vectors']='unweighted_mean_of_raw_chunk_vectors'
    normalization:Literal['l2_after_chunk_mean']='l2_after_chunk_mean'
    device:Literal['cpu']='cpu'
    dtype:Literal['float32']='float32'
    attention:Literal['eager']='eager'
    batch_size:int=Field(default=4,ge=1,le=16)
    threads:int=Field(default=4,ge=1,le=16)
    seed:int=Field(default=0,ge=0)
    norm_epsilon:float=Field(default=1e-12,gt=0)
