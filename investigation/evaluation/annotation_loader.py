"""Load and cross-check frozen evaluation labels outside the agent package."""

from pathlib import Path

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.content import load_json, require_text, validate_document
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import require_known_references, require_unique

from .contracts import CaseEvaluationAnnotation, EvaluationAnnotationSet, OracleCase


def load_annotations(path: str | Path) -> EvaluationAnnotationSet:
    document = load_json(path)
    validate_document(EvaluationAnnotationSet, document)
    result = decode(EvaluationAnnotationSet, document)
    if encode(result) != document:
        raise ProtocolViolation("invalid_annotation_structure", "annotations must use typed fields")
    require_text(result.annotation_version, "annotation_version")
    require_text(result.rubric_version, "rubric_version")
    require_unique(tuple(item.case_id for item in result.cases), "annotation case_id")
    return result


def annotation_for_case(annotation_set: EvaluationAnnotationSet, oracle: OracleCase,
                        budget) -> CaseEvaluationAnnotation:
    if annotation_set.rubric_version != oracle.rubric_version:
        raise ProtocolViolation("annotation_rubric_mismatch", "annotation and oracle rubric differ")
    if encode(annotation_set.budget_profile) != encode(budget):
        raise ProtocolViolation("annotation_budget_mismatch", "labels do not apply to this exact budget")
    matches = [item for item in annotation_set.cases if item.case_id == oracle.case_id]
    if len(matches) != 1:
        raise ProtocolViolation("annotation_case_missing", "case requires exactly one evaluation annotation")
    item = matches[0]
    for name in ("case_id", "rationale"):
        require_text(getattr(item, name), "annotation." + name)
    observable = set(oracle.observable_fact_keys)
    for name in ("discriminating_fact_keys", "risk_clue_fact_keys"):
        keys = getattr(item, name)
        require_unique(keys, name)
        require_known_references(keys, observable, name)
    if item.required_abstention and item.avoidable_abstention:
        raise ProtocolViolation("conflicting_abstention_annotation",
                                "abstention cannot be both required and avoidable")
    if item.required_abstention and not item.required_human_review:
        raise ProtocolViolation("invalid_abstention_annotation",
                                "required abstention must require human review")
    return item
