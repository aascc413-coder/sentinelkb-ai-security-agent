"""Strict environment fixture loading; never reads evaluation annotations."""

from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import get_type_hints

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.content import (
    content_hash, load_json, opaque_id, reject_hidden_metadata, require_text, validate_document,
)
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, HistoryQuery, SIEMQuery, TIQuery,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import (
    require_known_references, require_not_after, require_time_window, require_unique, require_utc,
)

from .contracts import EnvironmentFixture

_QUERY_TYPES = {"siem": SIEMQuery, "threat_intel": TIQuery, "asset": AssetQuery,
                "history": HistoryQuery, "attack": AttackQuery}
_STATUSES = {"ok", "empty", "partial", "unavailable", "timeout", "error"}


def _constraints(tool: str, constraints: dict, as_of: datetime, *, coverage: bool = False) -> None:
    hints = get_type_hints(_QUERY_TYPES[tool])
    # Coverage may record publication cutoff for window-based SIEM/history sources.
    allowed = set(hints) | ({"as_of"} if coverage else set())
    if set(constraints) - allowed:
        raise ProtocolViolation("unknown_constraint", "Unknown query/coverage constraint")
    for name, value in constraints.items():
        tp = datetime if name == "as_of" else hints[name]
        decoded = decode(tp, value)
        if name == "window":
            require_time_window(decoded, "rule.window")
            require_not_after(decoded.end, as_of, "rule.window.end")
        elif name == "as_of":
            require_utc(decoded, "rule.as_of")
            require_not_after(decoded, as_of, "rule.as_of")
        elif name == "limit" and not 1 <= decoded <= 50:
            raise ProtocolViolation("invalid_limit", "Rule limit must be in 1..50")
        elif isinstance(decoded, str):
            require_text(decoded, "rule." + name)


def _record_times(payload: dict, as_of: datetime) -> None:
    # Publication/occurrence govern observability. Prospective approval expiry is valid.
    values = {}
    for key in ("occurred_at", "observed_at", "published_at"):
        if key in payload and payload[key] is not None:
            dt = decode(datetime, payload[key])
            require_utc(dt, "record." + key)
            require_not_after(dt, as_of, "record." + key)
            values[key] = dt
    occurred = values.get("occurred_at")
    if occurred is not None:
        for key in ("observed_at", "published_at"):
            if key in values and values[key] < occurred:
                raise ProtocolViolation("invalid_publication_order", "Record published before occurrence")


def validate_environment(fixture: EnvironmentFixture) -> EnvironmentFixture:
    validate_document(EnvironmentFixture, encode(fixture))
    if decode(EnvironmentFixture, encode(fixture)) != fixture:
        raise ProtocolViolation("invalid_dataset_structure", "EnvironmentFixture must use typed contract fields")
    require_utc(fixture.as_of, "environment.as_of")
    require_text(fixture.environment_id, "environment_id")
    require_text(fixture.fixture_version, "fixture_version")
    all_ids = []
    for tool, records in fixture.records_by_tool.items():
        for record in records:
            all_ids.append(record.record_id)
            for name in ("record_id", "source_system", "independence_group"):
                require_text(getattr(record, name), "record." + name)
            require_text(record.reliability.basis, "record.reliability.basis")
            require_text(record.reliability.policy_version, "record.reliability.policy_version")
            reject_hidden_metadata(record.payload)
            if record.content_sha256 != content_hash(record.payload):
                raise ProtocolViolation("content_hash_mismatch", "Record hash does not match payload")
            _record_times(record.payload, fixture.as_of)
    require_unique(all_ids, "environment record IDs")
    rule_keys = set()
    for rule in fixture.query_rules:
        if rule.status not in _STATUSES:
            raise ProtocolViolation("invalid_status", "Unknown fixture status")
        _constraints(rule.tool, rule.argument_constraints, fixture.as_of)
        _constraints(rule.tool, rule.coverage.scope, fixture.as_of, coverage=True)
        key = (rule.tool, content_hash(rule.argument_constraints))
        if key in rule_keys:
            raise ProtocolViolation("duplicate_rule", "Rules with identical matching constraints are ambiguous")
        rule_keys.add(key)
        require_unique(rule.record_ids, "rule.record_ids")
        require_known_references(rule.record_ids,
                                 (r.record_id for r in fixture.records_by_tool.get(rule.tool, ())),
                                 "rule.record_ids")
        if rule.coverage.window is not None:
            require_time_window(rule.coverage.window, "coverage.window")
            require_not_after(rule.coverage.window.end, fixture.as_of, "coverage.window.end")
        require_unique(rule.coverage.missing_sources, "coverage.missing_sources")
        for source in rule.coverage.missing_sources:
            require_text(source, "coverage.missing_sources")
        if rule.coverage.completeness == "complete" and (
            rule.coverage.truncated or rule.coverage.missing_sources
        ):
            raise ProtocolViolation("invalid_coverage", "Complete coverage cannot be truncated or missing sources")
        if rule.status in {"unavailable", "timeout", "error"}:
            if rule.record_ids or rule.coverage.completeness == "complete" or not rule.error_code:
                raise ProtocolViolation("invalid_failure", "Failed source cannot claim complete evidence")
        elif rule.error_code is not None or rule.retryable:
            raise ProtocolViolation("invalid_success", "Success response cannot declare retry/error")
        if rule.status == "empty" and (rule.record_ids or rule.coverage.completeness != "complete"):
            raise ProtocolViolation("invalid_empty", "Empty requires zero records and complete coverage")
        if rule.status == "ok" and (not rule.record_ids or rule.coverage.completeness != "complete"):
            raise ProtocolViolation("invalid_ok", "ok requires records and complete coverage; use partial otherwise")
        if rule.status == "partial" and rule.coverage.completeness == "complete":
            raise ProtocolViolation("invalid_partial", "Partial response cannot declare complete coverage")
    return fixture


def load_environment(path: str | Path, *, namespace: str = "runtime-v1",
                     remap_ids: bool = True) -> EnvironmentFixture:
    if type(remap_ids) is not bool:
        raise ProtocolViolation("invalid_mode", "remap_ids must be bool")
    document = load_json(path)
    validate_document(EnvironmentFixture, document)
    fixture = validate_environment(decode(EnvironmentFixture, document))
    if not remap_ids:
        return fixture
    records = {tool: tuple(replace(record,
                                  record_id=opaque_id("record", record.record_id, namespace),
                                  independence_group=opaque_id("group", record.independence_group, namespace))
                            for record in values)
               for tool, values in fixture.records_by_tool.items()}
    rules = tuple(replace(rule, record_ids=tuple(opaque_id("record", rid, namespace)
                                                for rid in rule.record_ids))
                  for rule in fixture.query_rules)
    return replace(fixture, environment_id=opaque_id("environment", fixture.environment_id, namespace),
                   records_by_tool=records, query_rules=rules)
