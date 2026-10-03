"""Deterministic tool-query identity and isolated in-memory response caching.

Host, user, process and command identifiers retain their original case/content.
TI domains use IDNA ASCII, lower case and remove a single DNS trailing dot;
IP addresses use ipaddress canonical form (scoped IPv6 is not an IOC here).
Only conventional hexadecimal digest lengths are lowercased. Synthetic digest
labels such as ``h7`` remain opaque and case sensitive. ATT&CK filters are exact,
case-sensitive sets. No call/run identifiers or timeout enter the signature.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from hashlib import sha256
import ipaddress
import json
import re

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, HistoryQuery, SIEMQuery, TIQuery,
    ToolArguments, ToolName, ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import (
    require_non_negative, require_utc, validate_query,
)

_QUERY_TYPES = {
    "siem": SIEMQuery, "threat_intel": TIQuery, "asset": AssetQuery,
    "history": HistoryQuery, "attack": AttackQuery,
}
_CACHEABLE = frozenset({"ok", "empty", "partial", "unavailable"})
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HEX_DIGEST = re.compile(r"[0-9a-fA-F]+\Z")


def validate_call(tool: ToolName, query: ToolArguments) -> None:
    """Enforce tool/argument correlation plus strict M1 type/range validation."""
    if not isinstance(tool, str) or tool not in _QUERY_TYPES:
        raise ProtocolViolation("unknown_tool", "Unknown tool name")
    expected = _QUERY_TYPES[tool]
    if type(query) is not expected:
        raise ProtocolViolation(
            "tool_argument_mismatch", f"{tool} requires {expected.__name__}"
        )
    # Dataclass construction itself permits wrong nested types and literals.
    decoded = decode(expected, encode(query))
    if decoded != query:
        raise ProtocolViolation("invalid_query_structure", "Use typed dataclass query fields")
    validate_query(decoded)


def canonical_query(query: ToolArguments) -> ToolArguments:
    """Return a validated query with only documented semantic normalization."""
    tool = next((name for name, tp in _QUERY_TYPES.items() if type(query) is tp), None)
    if tool is None:
        raise ProtocolViolation("unknown_query", "Unsupported query class")
    validate_call(tool, query)
    if isinstance(query, AttackQuery):
        return replace(
            query, behavior_terms=tuple(sorted(set(query.behavior_terms))),
            technique_ids=tuple(sorted(set(query.technique_ids))),
        )
    if not isinstance(query, TIQuery):
        return query
    value = query.value
    if query.indicator_type == "ip":
        try:
            if "%" in value:
                raise ValueError("Scoped IP addresses are not supported")
            value = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ProtocolViolation("invalid_indicator", "Invalid IP indicator") from exc
    elif query.indicator_type == "domain":
        try:
            value = value.removesuffix(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ProtocolViolation("invalid_indicator", "Invalid domain indicator") from exc
        if len(value) > 253 or not all(_DOMAIN_LABEL.fullmatch(label) for label in value.split(".")):
            raise ProtocolViolation("invalid_indicator", "Invalid domain indicator")
    else:
        # Fixtures deliberately use readable opaque hash labels, not just digests.
        if any(char.isspace() for char in value) or not value.isprintable():
            raise ProtocolViolation("invalid_indicator", "Invalid hash indicator")
        if len(value) in {32, 40, 64, 128} and _HEX_DIGEST.fullmatch(value):
            value = value.lower()
    return replace(query, value=value)


def request_signature(
    tool: ToolName, query: ToolArguments, as_of: datetime, snapshot_version: str,
) -> str:
    """Versioned SHA-256 query identity, scoped to frozen world/time snapshot."""
    validate_call(tool, query)
    require_utc(as_of, "signature.as_of")
    if not isinstance(snapshot_version, str) or not snapshot_version.strip():
        raise ProtocolViolation("invalid_snapshot", "snapshot_version must be nonempty")
    payload = {
        "signature_version": 1, "tool": tool,
        "arguments": encode(canonical_query(query)),
        "as_of": as_of.isoformat(), "snapshot_version": snapshot_version,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return sha256(encoded.encode("utf-8")).hexdigest()


class QueryCache:
    """Caller-owned cache. Permanent unavailable is stable; retryable is not.

    Both writes and reads copy nested records/coverage so callers cannot mutate
    a cached fact. Runtime substitutes the current call_id on every cache hit.
    """

    def __init__(self) -> None:
        self._results: dict[str, ToolResult] = {}

    def get(self, key: str) -> ToolResult | None:
        result = self._results.get(key)
        return deepcopy(result) if result is not None else None

    def put(self, key: str, result: ToolResult) -> None:
        if not isinstance(key, str) or not key:
            raise ProtocolViolation("invalid_cache_key", "Cache key must be nonempty")
        if type(result) is not ToolResult:
            raise ProtocolViolation("invalid_cache_result", "Cache requires ToolResult")
        decode(ToolResult, encode(result))
        require_non_negative(result.simulated_cost_units, "simulated_cost_units")
        require_non_negative(result.simulated_latency_ms, "simulated_latency_ms")
        require_non_negative(result.actual_duration_ms, "actual_duration_ms")
        if result.retryable or result.status not in _CACHEABLE:
            return
        self._results[key] = deepcopy(result)

    def __len__(self) -> int:
        return len(self._results)
