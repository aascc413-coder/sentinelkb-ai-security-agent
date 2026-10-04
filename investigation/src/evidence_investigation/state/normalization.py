"""Versioned whitelist for paired-input checks; never removes business fields.

Static equivalence is not equivalence of actual tool responses or model requests.
Object key order is deliberately checked because serialized order can be visible.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, fields, is_dataclass
import hashlib
import json

from .codec import encode
from .errors import ProtocolViolation

NORMALIZATION_VERSION = "visible-metadata-v1"
_WHITELIST = {
    "public": {"/alert/alert_id": "identity", "/alert/raw_reference/record_id": "identity"},
    "environment": {"/environment_id": "identity"},
    "tool_result": {"/call_id": "identity", "/actual_duration_ms": "duration"},
    "message": {"/call_id": "identity", "/run_id": "identity",
                "/returned_at": "actual_timestamp", "/usage/wall_time_ms": "duration"},
}
NORMALIZATION_SHA256 = hashlib.sha256(json.dumps(_WHITELIST, sort_keys=True,
                                   separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class NormalizedPath:
    path: str
    reason: str


@dataclass(frozen=True)
class NormalizedVisible:
    value: dict
    normalized_paths: tuple[NormalizedPath, ...]
    normalization_version: str = NORMALIZATION_VERSION
    normalization_sha256: str = NORMALIZATION_SHA256


@dataclass(frozen=True)
class StaticComparison:
    equal: bool
    differences: tuple[str, ...]
    normalized_paths: tuple[NormalizedPath, ...]
    normalization_version: str = NORMALIZATION_VERSION
    normalization_sha256: str = NORMALIZATION_SHA256


def _business_strings(value: object, allowed: dict[str, str], path: str = "") -> set[str]:
    if path in allowed:
        return set()
    if type(value) is str:
        return {value}
    if type(value) is dict:
        # JSON object keys can themselves index a record/subject identity.
        # Preserve those references just as strictly as string-valued links.
        return set(value) | (set().union(*(_business_strings(v, allowed, path + "/" + _escape(k))
                             for k, v in value.items())) if value else set())
    if type(value) is list:
        return set().union(*(_business_strings(v, allowed, path + "/" + str(i))
                             for i, v in enumerate(value))) if value else set()
    return set()


def _validate_input_keys(value: object, path: str = "", active: set[int] | None = None) -> None:
    """Reject invalid mappings before codec.encode can coerce their keys.

    Dataclass datetime/tuple fields remain legal codec inputs. Ancestor tracking
    rejects cycles while allowing repeated references to an ordinary value.
    """
    active = set() if active is None else active
    structured = isinstance(value, (dict, list, tuple)) or (is_dataclass(value) and not isinstance(value, type))
    if not structured:
        return
    identity = id(value)
    if identity in active:
        raise ProtocolViolation("invalid_normalization", f"{path}: cyclic input is not JSON")
    active.add(identity)
    try:
        if isinstance(value, dict):
            for key, item in value.items():
                if type(key) is not str:
                    raise ProtocolViolation("invalid_normalization", f"{path}: JSON object keys must be strings")
                _validate_input_keys(item, path + "/" + _escape(key), active)
        elif isinstance(value, (list, tuple)):
            for index, item in enumerate(value):
                _validate_input_keys(item, path + "/" + str(index), active)
        else:
            for field in fields(value):
                _validate_input_keys(getattr(value, field.name), path + "/" + field.name, active)
    finally:
        active.remove(identity)


def normalize_visible(data: object, *, surface: str, _anchored: set[str] | None = None) -> NormalizedVisible:
    """Normalize exact envelope paths only; equal IDs remain equal by bijection.

    Static alert identifiers are metadata, but record IDs inside environment
    records, record references, payloads or scopes are compared without change.
    Duration normalization only concerns measured execution, never simulated cost
    or simulated latency. No suffix or recursive key-name matching is used.
    """
    if surface not in _WHITELIST:
        raise ProtocolViolation("invalid_normalization", "unknown visible surface")
    _validate_input_keys(data)
    value = copy.deepcopy(encode(data))
    if type(value) is not dict:
        raise ProtocolViolation("invalid_normalization", "visible surface must be an object")
    # Validate finite JSON without canonicalizing object order.
    json.dumps(value, allow_nan=False)
    anchored = _business_strings(value, _WHITELIST[surface]) | (_anchored or set())
    identities: dict[str, str] = {}
    changed = []
    for path, kind in _WHITELIST[surface].items():
        keys = path[1:].split("/")
        parent = value
        for key in keys[:-1]:
            if type(parent) is not dict or key not in parent:
                parent = None
                break
            parent = parent[key]
        if type(parent) is not dict or keys[-1] not in parent:
            continue
        original = parent[keys[-1]]
        if kind == "identity":
            if type(original) is not str or not original:
                raise ProtocolViolation("invalid_normalization", f"{path}: nonempty ID required")
            if original in anchored:
                # An ID referenced in a record/claim is no longer mere metadata.
                continue
            parent[keys[-1]] = identities.setdefault(original, f"@metadata-id-{len(identities)}")
            reason = "Opaque envelope ID bijection; repeated identifiers retain their relationship."
        elif kind == "duration":
            if type(original) is not int or original < 0:
                raise ProtocolViolation("invalid_normalization", f"{path}: nonnegative measured milliseconds required")
            parent[keys[-1]] = 0
            reason = "Measured wall duration varies with the execution host; simulated latency/cost remain exact."
        else:
            if type(original) is not str or not original:
                raise ProtocolViolation("invalid_normalization", f"{path}: actual return timestamp required")
            parent[keys[-1]] = "@actual-return-time"
            reason = "Actual return timestamp varies between runs; event/as_of/publication timestamps remain exact."
        changed.append(NormalizedPath(path, reason))
    return NormalizedVisible(value, tuple(changed))


def _escape(key: str) -> str:
    return key.replace("~", "~0").replace("/", "~1")


def _diff(left: object, right: object, path: str) -> list[str]:
    if type(left) is not type(right):
        return [path + ": type mismatch"]
    if type(left) is dict:
        differences = []
        if list(left) != list(right):
            differences.append(path + ": object keys/order mismatch")
        for key in left:
            if key in right:
                differences.extend(_diff(left[key], right[key], path + "/" + _escape(key)))
        return differences
    if type(left) is list:
        differences = []
        if len(left) != len(right):
            differences.append(path + ": array length mismatch")
        for index, (a, b) in enumerate(zip(left, right)):
            differences.extend(_diff(a, b, path + "/" + str(index)))
        return differences
    return [] if left == right else [path + ": value mismatch"]


def compare_static(public1: object, env1: object, public2: object, env2: object) -> StaticComparison:
    """Compare full public/environment documents before any tool or model call."""
    pairs = ((public1, "public"), (env1, "environment"),
             (public2, "public"), (env2, "environment"))
    for data, _ in pairs:
        _validate_input_keys(data)
    # Preserve even cross-document business references to an envelope identity.
    anchors = set().union(*(_business_strings(encode(data), _WHITELIST[surface])
                            for data, surface in pairs))
    normalized = [normalize_visible(data, surface=surface, _anchored=anchors)
                  for data, surface in pairs]
    differences = tuple(_diff(normalized[0].value, normalized[2].value, "/public") +
                        _diff(normalized[1].value, normalized[3].value, "/environment"))
    paths = tuple(NormalizedPath(f"/{label}{entry.path}", entry.reason)
                  for label, result in zip(("left/public", "left/environment", "right/public", "right/environment"), normalized)
                  for entry in result.normalized_paths)
    return StaticComparison(not differences, differences, paths)
