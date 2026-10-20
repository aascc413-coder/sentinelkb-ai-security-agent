"""Frozen family rubric loader; descriptions are not an implemented evaluator.

Both runtime and offline evaluators may consume this specification. Neither can
accept a model's ``met`` merely because its output matches a JSON structure.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
import re

from .errors import ProtocolViolation

RUBRIC_VERSION = "powershell-v1"
# Semantic digest freezes the rule, independent of whitespace and object order.
FROZEN_CANONICAL_SHA256 = "5f45cdd8de85bdf93c72f20ddd657a21606accb8f9a4adc011b951a66a3dce39"
CRITERION_IDS = ("G0", "G1", "G2", "G3", "G4", "B1", "B2", "B3")
COLUMNS = ("required_observations", "program_checks", "model_explanation",
           "conflict_handling", "unverifiable")


@dataclass(frozen=True)
class RubricCriterion:
    criterion_id: str
    required_observations: tuple[str, ...]
    program_checks: tuple[str, ...]
    model_explanation: tuple[str, ...]
    conflict_handling: tuple[str, ...]
    unverifiable: tuple[str, ...]


@dataclass(frozen=True)
class RiskPattern:
    pattern_id: str
    required_observations: tuple[str, ...]
    program_checks: tuple[str, ...]
    excluded_observations: tuple[str, ...]


@dataclass(frozen=True)
class OutcomePolicy:
    tp_required: tuple[str, ...]
    fp_required: tuple[str, ...]
    criterion_outcomes: tuple[str, ...]
    hard_stops: tuple[str, ...]
    suspicious_allowed_stops: tuple[str, ...]
    decision_rules: tuple[str, ...]


@dataclass(frozen=True)
class FamilyRubric:
    rubric_version: str
    family: str
    criteria: tuple[RubricCriterion, ...]
    policy: OutcomePolicy
    suspicious_patterns: tuple[RiskPattern, ...]
    scope: tuple[str, ...]
    sha256: str
    canonical_sha256: str


def _closed(value: object, keys: tuple[str, ...], where: str) -> dict:
    if type(value) is not dict or set(value) != set(keys):
        raise ProtocolViolation("invalid_rubric", f"{where}: requires exactly {keys}")
    return value


def _strings(value: object, where: str) -> tuple[str, ...]:
    if type(value) is not list or not value or any(type(x) is not str or not x.strip() for x in value):
        raise ProtocolViolation("invalid_rubric", f"{where}: nonempty string array required")
    if len(set(value)) != len(value):
        raise ProtocolViolation("invalid_rubric", f"{where}: duplicate entry")
    return tuple(value)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolViolation("invalid_rubric", f"duplicate JSON key {key}")
        result[key] = value
    return result


def load_rubric(path: str | Path, *, expected_sha256: str | None = None) -> FamilyRubric:
    """Load closed, frozen powershell-v1, optionally checking exact file bytes.

    A change to these semantics needs a new reviewed version and digest. An
    expected hash cannot override the frozen semantic digest.
    """
    raw = Path(path).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise ProtocolViolation("rubric_hash_mismatch", "file byte hash differs")
    try:
        data = json.loads(raw, object_pairs_hook=_unique_pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (ValueError, UnicodeError) as exc:
        raise ProtocolViolation("invalid_rubric", "invalid finite UTF-8 JSON") from exc
    data = _closed(data, ("rubric_version", "family", "criteria", "policy",
                          "suspicious_patterns", "scope"), "rubric")
    if data["rubric_version"] != RUBRIC_VERSION or data["family"] != "powershell_execution":
        raise ProtocolViolation("invalid_rubric", "unsupported family/version")
    text = json.dumps(data, ensure_ascii=False)
    if re.search(r"\bC[1-5]\b|\b(?:WS|OPS)-\d+\b|\bp-\d+\b|\bJ-\d+\b", text):
        raise ProtocolViolation("invalid_rubric", "case-specific identifier in family rule")
    if type(data["criteria"]) is not list:
        raise ProtocolViolation("invalid_rubric", "criteria must be an array")
    criteria = []
    for entry in data["criteria"]:
        entry = _closed(entry, ("criterion_id", *COLUMNS), "criterion")
        criteria.append(RubricCriterion(entry["criterion_id"],
                                       *(_strings(entry[c], c) for c in COLUMNS)))
    if tuple(c.criterion_id for c in criteria) != CRITERION_IDS:
        raise ProtocolViolation("invalid_rubric", "criteria must be ordered G0-G4, B1-B3")
    policy = _closed(data["policy"], ("tp_required", "fp_required", "criterion_outcomes",
                                     "hard_stops", "suspicious_allowed_stops", "decision_rules"), "policy")
    policy = OutcomePolicy(*(_strings(policy[k], k) for k in OutcomePolicy.__dataclass_fields__))
    if policy.tp_required != CRITERION_IDS[:5] or policy.fp_required != ("G0", "G1", "B1", "B2", "B3"):
        raise ProtocolViolation("invalid_rubric", "required gate groups changed")
    if policy.criterion_outcomes != ("met", "unmet", "unknown"):
        raise ProtocolViolation("invalid_rubric", "three-valued gate outcomes required")
    if type(data["suspicious_patterns"]) is not list or not data["suspicious_patterns"]:
        raise ProtocolViolation("invalid_rubric", "risk patterns required")
    patterns = []
    for entry in data["suspicious_patterns"]:
        entry = _closed(entry, ("pattern_id", "required_observations", "program_checks", "excluded_observations"), "risk pattern")
        if type(entry["pattern_id"]) is not str or not entry["pattern_id"].strip():
            raise ProtocolViolation("invalid_rubric", "risk pattern ID required")
        patterns.append(RiskPattern(entry["pattern_id"], *(_strings(entry[k], k) for k in
                         ("required_observations", "program_checks", "excluded_observations"))))
    if len({p.pattern_id for p in patterns}) != len(patterns):
        raise ProtocolViolation("invalid_rubric", "duplicate risk pattern ID")
    scope = _strings(data["scope"], "scope")
    canonical = hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    if canonical != FROZEN_CANONICAL_SHA256:
        raise ProtocolViolation("rubric_hash_mismatch", "frozen powershell-v1 semantics changed")
    return FamilyRubric(data["rubric_version"], data["family"], tuple(criteria), policy,
                        tuple(patterns), scope, digest, canonical)
