"""English decisions for new runs and exact legacy wire compatibility."""
from typing import Literal

EnglishDecision = Literal['supported_match','different_behavior','insufficient_evidence']
LEGACY_TO_ENGLISH = {
    '\u652f\u6301\u5339\u914d':'supported_match',
    '\u884c\u4e3a\u4e0d\u540c':'different_behavior',
    '\u8bc1\u636e\u4e0d\u8db3':'insufficient_evidence',
}


def decision_kind(value):
    return LEGACY_TO_ENGLISH.get(value,value)


def is_supported(value):
    return decision_kind(value)=='supported_match'


def english_protocol_text(text):
    for legacy,english in LEGACY_TO_ENGLISH.items():text=text.replace(legacy,english)
    return text.replace('behavior-match-proposal.v1','behavior-match-proposal.v3').replace(
        'behavior-match-proposal.v2','behavior-match-proposal.v3').replace(
        'behavior-match-request.v2','behavior-match-request.v3')
