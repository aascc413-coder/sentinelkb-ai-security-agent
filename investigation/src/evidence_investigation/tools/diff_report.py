"""Frozen comparison policy for actual ToolResult envelopes (M3/A3).

Only the two named envelope fields are normalized. Nested fields with the same
names remain business content. Records, ordering, coverage, simulated cost and
latency, source identity, and timestamps are compared without normalization.
This report proves response equality under this policy, not model-input equality.
"""

from __future__ import annotations

from hashlib import sha256
import json

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import JsonValue, ToolResult
from evidence_investigation.state.errors import ProtocolViolation


NORMALIZATION_VERSION = "tool-result-envelope-v2"
_RULES = (
    ("/call_id", "Opaque invocation identity, only when neither identifier is referenced in business fields."),
    ("/actual_duration_ms", "Measured wall duration varies with local scheduling."),
)


def normalization_policy() -> dict[str, JsonValue]:
    """Return the predeclared whitelist and its canonical fingerprint."""
    policy = {
        "version": NORMALIZATION_VERSION,
        "rules": [{"path": path, "reason": reason} for path, reason in _RULES],
        "object_key_order": "preserved",
    }
    fingerprint = sha256(json.dumps(policy, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()
    return {**policy, "sha256": fingerprint}


def _validate_json_keys(value: JsonValue) -> None:
    # codec.encode stringifies dictionary keys; reject them before that happens.
    if isinstance(value, dict):
        if not all(type(key) is str for key in value):
            raise ProtocolViolation("invalid_json_key", "Response JSON keys must be strings")
        for child in value.values():
            _validate_json_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _validate_json_keys(child)


def _encoded(result: ToolResult) -> dict[str, JsonValue]:
    if type(result) is not ToolResult:
        raise ProtocolViolation("invalid_tool_result", "Expected an exact ToolResult envelope")
    # Walk the dict-bearing fields before encode, which otherwise coerces keys.
    try:
        _validate_json_keys(result.coverage.scope)
        for record in result.records:
            _validate_json_keys(record.payload)
    except (AttributeError, TypeError) as exc:
        raise ProtocolViolation("invalid_tool_result", "Invalid nested response structure") from exc
    data = encode(result)
    decode(ToolResult, data)  # Closed schema: unknown subclass fields fail here.
    for field in ("simulated_cost_units", "simulated_latency_ms", "actual_duration_ms"):
        if data[field] < 0:
            raise ProtocolViolation("invalid_usage", f"{field} must be non-negative")
    return data


def _pointer(parent: str, key: str | int) -> str:
    token = str(key).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{token}"


def _differences(left: JsonValue, right: JsonValue, path: str = "") -> list[dict]:
    if type(left) is not type(right):
        return [{"path": path, "kind": "type", "left": left, "right": right,
                 "left_present": True, "right_present": True}]
    if isinstance(left, dict):
        differences = []
        if list(left) != list(right):
            differences.append({"path": path, "kind": "object_key_order",
                                "left": list(left), "right": list(right),
                                "left_present": True, "right_present": True})
        for key in sorted(left.keys() | right.keys()):
            child = _pointer(path, key)
            if key not in left or key not in right:
                differences.append({"path": child, "kind": "missing_field",
                                    "left": left.get(key), "right": right.get(key),
                                    "left_present": key in left, "right_present": key in right})
            else:
                differences.extend(_differences(left[key], right[key], child))
        return differences
    if isinstance(left, list):
        differences = []
        for index in range(max(len(left), len(right))):
            child = _pointer(path, index)
            if index >= len(left) or index >= len(right):
                differences.append({"path": child, "kind": "missing_item",
                                    "left": left[index] if index < len(left) else None,
                                    "right": right[index] if index < len(right) else None,
                                    "left_present": index < len(left),
                                    "right_present": index < len(right)})
            else:
                differences.extend(_differences(left[index], right[index], child))
        return differences
    if left != right:
        return [{"path": path, "kind": "value", "left": left, "right": right,
                 "left_present": True, "right_present": True}]
    return []


def _reference_paths(value: JsonValue, identifiers: set[str], path: str = "") -> list[str]:
    """Conservatively retain identifiers used anywhere outside dynamic fields.

    A string equal to an invocation identifier may be a reference even if its
    key is unfamiliar. Keys themselves may encode identities too. Keeping a
    coincidental match is safer than merging two distinct identity relations.
    """
    if isinstance(value, dict):
        paths = []
        for key, child in value.items():
            child_path = _pointer(path, key)
            if path == "" and key in {"call_id", "actual_duration_ms"}:
                continue
            if key in identifiers:
                paths.append(child_path)
            paths.extend(_reference_paths(child, identifiers, child_path))
        return paths
    if isinstance(value, list):
        return [found for index, child in enumerate(value)
                for found in _reference_paths(child, identifiers, _pointer(path, index))]
    return [path] if isinstance(value, str) and value in identifiers else []


def compare_responses(left: ToolResult, right: ToolResult) -> dict[str, JsonValue]:
    """Compare two responses using only the frozen envelope whitelist.

    Returns JSON-compatible equality, recursive JSON Pointer differences, policy
    fingerprint, and every applied normalization with original values/reasons.
    Input objects are neither modified nor used to broaden the whitelist.
    Invalid response schemas fail rather than being declared equivalent.
    """
    first, second = _encoded(left), _encoded(right)
    normalized = []
    exclusions = []
    identifiers = {first["call_id"], second["call_id"]}
    references = {"left": _reference_paths(first, identifiers),
                  "right": _reference_paths(second, identifiers)}
    for path, reason in _RULES:
        field = path[1:]
        if field == "call_id" and any(references.values()):
            exclusions.append({"path": path,
                               "reason": "Business references anchor invocation identity; no normalization applied.",
                               "reference_paths": references,
                               "left": first[field], "right": second[field]})
            continue
        normalized.append({"path": path, "reason": reason,
                           "left": first[field], "right": second[field],
                           "changed": first[field] != second[field]})
        first[field] = second[field] = None
    differences = _differences(first, second)
    policy = normalization_policy()
    return {"equal": not differences, "differences": differences,
            "difference_count": len(differences),
            "normalization_version": NORMALIZATION_VERSION,
            "normalization_sha256": policy["sha256"],
            "normalized_fields": normalized,
            "normalization_exclusions": exclusions,
            "reasons": [reason for _, reason in _RULES]}
