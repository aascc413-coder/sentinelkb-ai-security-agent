"""Fixture-backed investigation tools, independent of the M2 dataset layout.

Only an explicit EnvironmentFixture is consumed; no case IDs or oracle files
are read. Record field conventions are documented in selection.py and must be
adapted/tested against the eventual frozen M2 fixtures before M3 acceptance.
Windows are half-open. An uncovered query is unavailable, never complete empty.
Costs are synthetic backend units: cache attempts count, but cost/latency are 0.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass, fields, replace
from datetime import datetime
from hashlib import sha256
import json
import time
from typing import Awaitable, Callable

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, Coverage, HistoryQuery, SIEMQuery, TIQuery,
    ToolArguments, ToolContext, ToolName, ToolRecord, ToolResult,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import (
    require_non_negative, require_time_window, require_unique, require_utc,
)
from .contracts import EnvironmentFixture, FixtureRule
from .selection import matches_constraints, select_records
from .signatures import QueryCache, canonical_query, request_signature, validate_call


@dataclass(frozen=True)
class ToolProfile:
    cost_units: float
    latency_ms: int


# Phase 1 section 7, frozen mock values; not provider currency or production time.
DEFAULT_PROFILES: dict[ToolName, ToolProfile] = {
    "siem": ToolProfile(2.0, 200), "threat_intel": ToolProfile(3.0, 300),
    "asset": ToolProfile(1.0, 50), "history": ToolProfile(2.0, 150),
    "attack": ToolProfile(1.0, 20),
}
_QUERY_TYPES = {
    "siem": SIEMQuery, "threat_intel": TIQuery, "asset": AssetQuery,
    "history": HistoryQuery, "attack": AttackQuery,
}
_STATUSES = {"ok", "empty", "partial", "unavailable", "timeout", "error"}


def content_hash(payload: dict) -> str:
    """Canonical JSON: UTF-8, sorted keys, compact separators, finite numbers."""
    def check(value):
        if isinstance(value, dict):
            if not all(isinstance(key, str) for key in value):
                raise ProtocolViolation("invalid_json_key", "Payload keys must be strings")
            for child in value.values():
                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise ProtocolViolation("invalid_json_value", "Payload must contain JSON values")
    check(payload)
    try:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise ProtocolViolation("invalid_json_value", "Payload cannot be hashed") from exc
    return sha256(raw).hexdigest()


@dataclass(frozen=True)
class ToolServerStats:
    attempts: int
    backend_calls: int
    cache_hits: int


class MockToolServer:
    """Implements all five InvestigationTools methods with an owned snapshot.

    Matching rules with the most constraints win; equally specific matches are
    rejected. Server calls are serialized so concurrent duplicate requests have
    one backend execution. Time spent waiting for this lock consumes timeout.
    simulate_latency=False is an explicit fast test mode; declared simulated
    latency still participates in timeout admission and remains in the result.
    This is not the runtime budget controller or entity authorization layer.
    """

    def __init__(
        self, fixture: EnvironmentFixture, *, simulate_latency: bool = True,
        profiles: dict[ToolName, ToolProfile] | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        if type(simulate_latency) is not bool:
            raise ProtocolViolation("invalid_mode", "simulate_latency must be bool")
        # Validate original JSON before encode can stringify non-string keys.
        for records in fixture.records_by_tool.values():
            for record in records:
                content_hash(record.payload)
        owned = decode(EnvironmentFixture, encode(fixture))
        if owned != fixture:
            raise ProtocolViolation("invalid_fixture_structure", "Use typed fixture fields")
        require_utc(owned.as_of, "fixture.as_of")
        if not owned.environment_id or not owned.fixture_version:
            raise ProtocolViolation("invalid_fixture", "Fixture identifiers must be nonempty")
        all_ids = []
        for tool, records in owned.records_by_tool.items():
            for record in records:
                all_ids.append(record.record_id)
                if not all((record.record_id, record.source_system, record.independence_group)):
                    raise ProtocolViolation("invalid_record", "Record provenance must be nonempty")
                if record.content_sha256 != content_hash(record.payload):
                    raise ProtocolViolation("content_hash_mismatch", "Record hash does not match payload")
        require_unique(all_ids, "fixture records")
        for rule in owned.query_rules:
            self._validate_rule(rule, owned.records_by_tool.get(rule.tool, ()))
        self._fixture = owned
        self._profiles = deepcopy(DEFAULT_PROFILES if profiles is None else profiles)
        if set(self._profiles) != set(_QUERY_TYPES):
            raise ProtocolViolation("invalid_profiles", "Exactly five tool profiles are required")
        for profile in self._profiles.values():
            if type(profile) is not ToolProfile:
                raise ProtocolViolation("invalid_profile", "Tool profiles must be typed")
            require_non_negative(profile.cost_units, "profile.cost_units")
            if type(profile.latency_ms) is not int or profile.latency_ms < 0:
                raise ProtocolViolation("invalid_profile", "Latency must be a nonnegative integer")
        self._snapshot_key = content_hash(encode(owned))
        self._records = {tool: {r.record_id: r for r in records}
                         for tool, records in owned.records_by_tool.items()}
        self._cache = QueryCache()
        self._lock = asyncio.Lock()
        self._simulate_latency, self._sleep, self._clock = simulate_latency, sleeper, clock
        self._attempts = self._backend_calls = self._cache_hits = 0

    @staticmethod
    def _validate_rule(rule: FixtureRule, records: tuple[ToolRecord, ...]) -> None:
        if rule.status not in _STATUSES:
            raise ProtocolViolation("invalid_status", "Unknown fixture rule status")
        allowed = {f.name for f in fields(_QUERY_TYPES[rule.tool])}
        if set(rule.argument_constraints) - allowed:
            raise ProtocolViolation("unknown_constraint", "Unknown rule argument constraint")
        require_unique(rule.record_ids, "rule record IDs")
        known = {r.record_id for r in records}
        if set(rule.record_ids) - known:
            raise ProtocolViolation("dangling_reference", "Rule references another/missing tool record")
        if rule.coverage.window is not None:
            require_time_window(rule.coverage.window, "coverage.window")
        if rule.coverage.completeness == "complete" and (
            rule.coverage.truncated or rule.coverage.missing_sources
        ):
            raise ProtocolViolation("invalid_coverage", "Complete coverage cannot be truncated/missing")
        if rule.status in {"unavailable", "timeout", "error"}:
            if rule.record_ids or rule.coverage.completeness == "complete" or not rule.error_code:
                raise ProtocolViolation("invalid_failure", "Failed sources cannot assert complete evidence")
        if rule.status == "empty" and rule.record_ids:
            raise ProtocolViolation("invalid_empty", "Empty rules cannot carry records")
        if rule.status == "partial" and rule.coverage.completeness == "complete":
            raise ProtocolViolation("invalid_coverage", "Partial status requires incomplete coverage")
        if rule.status in {"ok", "empty", "partial"} and (rule.error_code or rule.retryable):
            raise ProtocolViolation("invalid_success", "Data responses cannot be retryable failures")
        if "window" in rule.argument_constraints:
            from evidence_investigation.state.contracts import TimeWindow
            require_time_window(decode(TimeWindow, rule.argument_constraints["window"]), "rule.window")

    def stats(self) -> ToolServerStats:
        return ToolServerStats(self._attempts, self._backend_calls, self._cache_hits)

    async def siem(self, query: SIEMQuery, ctx: ToolContext) -> ToolResult:
        return await self._invoke("siem", query, ctx)

    async def threat_intel(self, query: TIQuery, ctx: ToolContext) -> ToolResult:
        return await self._invoke("threat_intel", query, ctx)

    async def asset(self, query: AssetQuery, ctx: ToolContext) -> ToolResult:
        return await self._invoke("asset", query, ctx)

    async def history(self, query: HistoryQuery, ctx: ToolContext) -> ToolResult:
        return await self._invoke("history", query, ctx)

    async def attack(self, query: AttackQuery, ctx: ToolContext) -> ToolResult:
        return await self._invoke("attack", query, ctx)

    async def _invoke(self, tool: ToolName, query: ToolArguments, ctx: ToolContext) -> ToolResult:
        start = self._clock()
        self._attempts += 1
        validate_call(tool, query)
        query = canonical_query(query)
        decoded_ctx = decode(ToolContext, encode(ctx))
        if decoded_ctx != ctx or not ctx.run_id or not ctx.call_id:
            raise ProtocolViolation("invalid_context", "Use typed, nonempty runtime context")
        require_utc(ctx.as_of, "context.as_of")
        if ctx.as_of != self._fixture.as_of or ctx.remaining_timeout_ms < 0:
            raise ProtocolViolation("invalid_context", "Context must use frozen as_of and nonnegative timeout")
        if hasattr(query, "window") and query.window.end > ctx.as_of:
            raise ProtocolViolation("future_query", "Query window ends after frozen as_of")
        if hasattr(query, "as_of") and query.as_of > ctx.as_of:
            raise ProtocolViolation("future_query", "Query as_of exceeds frozen as_of")
        key = request_signature(tool, query, ctx.as_of, self._snapshot_key)
        remaining = max(0, ctx.remaining_timeout_ms - self._duration(start))
        if remaining == 0:
            return self._failure(tool, ctx, "timeout", "deadline_exhausted", True, start, 0, 0)
        try:
            await asyncio.wait_for(self._lock.acquire(), remaining / 1000)
        except TimeoutError:
            return self._failure(tool, ctx, "timeout", "deadline_exhausted", True, start, 0, 0)
        try:
            remaining = max(0, ctx.remaining_timeout_ms - self._duration(start))
            if remaining == 0:
                return self._failure(tool, ctx, "timeout", "deadline_exhausted", True, start, 0, 0)
            cached = self._cache.get(key)
            if cached is not None:
                self._cache_hits += 1
                return replace(cached, call_id=ctx.call_id, actual_duration_ms=self._duration(start),
                               simulated_cost_units=0.0, simulated_latency_ms=0)
            self._backend_calls += 1
            profile = self._profiles[tool]
            latency = min(profile.latency_ms, remaining)
            if self._simulate_latency and latency:
                try:
                    await asyncio.wait_for(self._sleep(latency / 1000), remaining / 1000)
                except TimeoutError:
                    return self._failure(tool, ctx, "timeout", "tool_timeout", True, start,
                                         profile.cost_units, latency)
            if profile.latency_ms >= remaining or self._duration(start) >= ctx.remaining_timeout_ms:
                return self._failure(tool, ctx, "timeout", "tool_timeout", True, start,
                                     profile.cost_units, latency)
            matching = [r for r in self._fixture.query_rules
                        if r.tool == tool and matches_constraints(query, r.argument_constraints)]
            if not matching:
                result = self._failure(tool, ctx, "unavailable", "no_matching_rule", False,
                                       start, profile.cost_units, profile.latency_ms)
            else:
                best_count = max(len(r.argument_constraints) for r in matching)
                best = [r for r in matching if len(r.argument_constraints) == best_count]
                if len(best) != 1:
                    raise ProtocolViolation("ambiguous_fixture_rule", "Equally specific fixture rules match")
                result = self._response(tool, query, ctx, best[0], start, profile)
            self._cache.put(key, result)
            return deepcopy(result)
        finally:
            self._lock.release()

    def _duration(self, start: float) -> int:
        return max(0, int((self._clock() - start) * 1000))

    def _failure(self, tool, ctx, status, code, retryable, start, cost, latency) -> ToolResult:
        return ToolResult(ctx.call_id, tool, status, (), Coverage({}, None, "unknown", False,
                          (f"{tool}.source",)), self._fixture.fixture_version, code, retryable,
                          cost, latency, self._duration(start))

    def _response(self, tool, query, ctx, rule, start, profile) -> ToolResult:
        if rule.status in {"unavailable", "timeout", "error"}:
            return ToolResult(ctx.call_id, tool, rule.status, (), deepcopy(rule.coverage),
                              self._fixture.fixture_version, rule.error_code, rule.retryable,
                              profile.cost_units, profile.latency_ms, self._duration(start))
        original = tuple(self._records[tool][rid] for rid in rule.record_ids)
        selected = select_records(query, original, ctx.as_of)
        coverage = deepcopy(rule.coverage)
        requested = encode(query)
        anchors = (
            ("user", "view") if isinstance(query, SIEMQuery) and query.view == "user_events"
            else ("host", "view") if isinstance(query, SIEMQuery)
            else ("entity_type", "entity") if isinstance(query, HistoryQuery)
            else ("indicator_type", "value") if isinstance(query, TIQuery)
            else ("host",) if isinstance(query, AssetQuery)
            else ("snapshot_version",)
        )
        # A source restricted to one user/process cannot prove absence for a
        # different user/process or for an unfiltered query. None is unrestricted.
        allowed_scope = set(requested)
        covered = not (set(coverage.scope) - allowed_scope)
        covered &= all(coverage.scope.get(key) is not None for key in anchors)
        constraints = {k: v for k, v in coverage.scope.items()
                       if k in allowed_scope and k not in {"window", "limit", "as_of"} and v is not None}
        try:
            covered &= matches_constraints(query, constraints)
            if "as_of" in coverage.scope and coverage.scope["as_of"] is not None:
                source_time = decode(datetime, coverage.scope["as_of"])
                require_utc(source_time, "coverage.as_of")
                requested_time = getattr(query, "as_of", ctx.as_of)
                covered &= requested_time <= source_time <= ctx.as_of
        except ProtocolViolation:
            covered = False
        query_window = getattr(query, "window", None)
        if query_window is not None:
            covered &= coverage.window is not None and (
                coverage.window.start <= query_window.start and coverage.window.end >= query_window.end
            )
        limit = getattr(query, "limit", len(selected.records))
        truncated = coverage.truncated or len(selected.records) > limit
        incomplete = (selected.incomplete or not covered or truncated or
                      coverage.completeness != "complete" or rule.status == "partial")
        missing = set(coverage.missing_sources) | set(selected.missing_fields)
        if not covered:
            missing.add("coverage_scope")
        missing = tuple(sorted(missing))
        # Scope reports the actual request; no unproven wider absence claims.
        scope = {k: v for k, v in requested.items() if k not in {"window", "limit"}}
        scope["source_scope"] = deepcopy(rule.coverage.scope)
        coverage = Coverage(scope, query_window or coverage.window,
                            "partial" if incomplete else "complete", truncated, missing)
        records = selected.records[:limit]
        status = "partial" if incomplete else "ok" if records else "empty"
        return ToolResult(ctx.call_id, tool, status, deepcopy(records), coverage,
                          self._fixture.fixture_version, None, False, profile.cost_units,
                          profile.latency_ms, self._duration(start))
