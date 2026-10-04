"""Pure rule matching and record selection, independent of case IDs and oracle.

Payload convention (all timestamps are ISO strings with UTC offset zero):
* SIEM: ``view``, ``occurred_at``, host/user/process_id where requested.
* History: ``entity_type``, ``entity``, ``occurred_at`` and optional selectors.
* TI: ``indicator_type``, ``value``, ``published_at``.
* Asset: ``host``, ``published_at``.
* ATT&CK: ``snapshot_version``, ``published_at``, ``technique_id`` or
  ``technique_ids`` and ``behavior_terms`` (arrays of exact, case-sensitive terms).
SIEM/history availability uses ``observed_at`` (or ``published_at`` if absent).
Missing/invalid required times and selectors do not match. Events use [start,end);
publication at as_of is available. Knowledge publication does not establish
maliciousness. Records and hashes are returned unchanged, never projected or
annotated. This layer does not apply query.limit: the server must retain the
pre-limit count to report truncation honestly.
These conventions are preliminary M3 interfaces; real M2 fixture adapters
require separate integration checks after M2 is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, HistoryQuery, JsonValue, SIEMQuery, TIQuery,
    TimeWindow, ToolArguments, ToolRecord,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.validation import (
    require_time_window, require_utc,
)
from .signatures import canonical_query


def _utc_timestamp(value: JsonValue) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value)
        require_utc(stamp, "record timestamp")
        return stamp
    except (ValueError, ProtocolViolation):
        return None


def _constraint_time(value: JsonValue, name: str) -> datetime:
    result = _utc_timestamp(value)
    if result is None:
        raise ProtocolViolation("invalid_constraint", f"{name} requires a UTC ISO timestamp")
    return result


def _terms(value: JsonValue, name: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProtocolViolation("invalid_constraint", f"{name} requires an array of strings")
    return frozenset(value)


def _json_equal(left: JsonValue, right: JsonValue) -> bool:
    # JSON boolean is not a JSON number, despite True == 1 in Python.
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    return left == right


def matches_constraints(query: ToolArguments, constraints: dict[str, JsonValue]) -> bool:
    """Match a rule, rejecting misspelled or malformed constraint fields.

Ordinary fields are exact; time fields compare UTC instants. A rule's window
must contain the entire requested window. ATT&CK term arrays compare as sets.
All constraint fields are validated before determining a non-match, so a typo
cannot hide behind an earlier mismatch.
    """
    query = canonical_query(query)
    if not isinstance(constraints, dict) or any(not isinstance(key, str) for key in constraints):
        raise ProtocolViolation("invalid_constraint", "Constraints require an object with string keys")
    allowed = {field.name for field in fields(query)}
    unknown = set(constraints) - allowed
    if unknown:
        raise ProtocolViolation("unknown_constraint", f"Unknown query constraints: {sorted(unknown)}")
    payload = encode(query)
    # Dependent fields (TI indicator_type/value) must be interpreted together.
    # Applying a hash rule's value to an IP request temporarily creates an
    # invalid IP, even though the complete rule is a valid non-match.
    ordinary = {k: v for k, v in constraints.items()
                if k not in {"window", "as_of"} and
                not (isinstance(query, AttackQuery) and k in {"behavior_terms", "technique_ids"})}
    candidate = decode(type(query), {**payload, **ordinary})
    incompatible_partial_value = False
    if isinstance(query, TIQuery) and "indicator_type" in ordinary and "value" not in ordinary:
        # A type-only predicate does not reclassify the request's indicator.
        pass
    else:
        try:
            candidate = canonical_query(candidate)
        except ProtocolViolation as exc:
            if (isinstance(query, TIQuery) and "value" in ordinary and
                    "indicator_type" not in ordinary and exc.code == "invalid_indicator"):
                # Value-only rules can match another indicator kind; this kind
                # is a definite non-match, not an invalid caller query.
                incompatible_partial_value = True
            else:
                raise
    candidate_payload = encode(candidate)
    comparisons: list[bool] = []
    for key, expected in constraints.items():
        if key == "window":
            if not isinstance(expected, dict) or set(expected) != {"start", "end"}:
                raise ProtocolViolation("invalid_constraint", "window requires exactly start and end")
            rule_window = TimeWindow(
                _constraint_time(expected["start"], "window.start"),
                _constraint_time(expected["end"], "window.end"),
            )
            require_time_window(rule_window, "constraint.window")
            window = query.window
            comparisons.append(rule_window.start <= window.start and window.end <= rule_window.end)
        elif key == "as_of":
            comparisons.append(query.as_of == _constraint_time(expected, "as_of"))
        elif isinstance(query, AttackQuery) and key in ("behavior_terms", "technique_ids"):
            comparisons.append(frozenset(getattr(query, key)) == _terms(expected, key))
        else:
            comparisons.append(_json_equal(payload[key], candidate_payload[key]))
    return not incompatible_partial_value and all(comparisons)


def filter_records(
    query: ToolArguments, records: tuple[ToolRecord, ...], as_of: datetime,
) -> tuple[ToolRecord, ...]:
    """Select available records; leave limits and coverage to the caller."""
    return select_records(query, records, as_of).records


@dataclass(frozen=True)
class SelectionResult:
    records: tuple[ToolRecord, ...]
    incomplete: bool
    missing_fields: tuple[str, ...]


def _required_fields(query: ToolArguments) -> dict[str, str]:
    if isinstance(query, SIEMQuery):
        selectors = {"view": query.view}
        selectors.update({key: getattr(query, key) for key in ("host", "user", "process_id")
                          if getattr(query, key) is not None})
        return selectors
    if isinstance(query, HistoryQuery):
        selectors = {"entity_type": query.entity_type, "entity": query.entity}
        selectors.update({key: getattr(query, key) for key in ("host", "user", "command_line")
                          if getattr(query, key) is not None})
        return selectors
    if isinstance(query, TIQuery):
        return {"indicator_type": query.indicator_type, "value": query.value}
    if isinstance(query, AssetQuery):
        return {"host": query.host}
    return {"snapshot_version": query.snapshot_version}


def _classify(
    query: ToolArguments, payload: dict[str, JsonValue], as_of: datetime,
) -> tuple[bool, set[str]]:
    """Definite non-matches need no missing-field flags; ambiguous ones do."""
    missing: set[str] = set()
    for key, required in _required_fields(query).items():
        actual = payload.get(key)
        if not isinstance(actual, str):
            missing.add(key)
            continue
        if isinstance(query, TIQuery) and key == "value":
            try:
                actual = canonical_query(TIQuery(query.indicator_type, actual, query.as_of)).value
            except ProtocolViolation:
                missing.add("value")
                continue
        if actual != required:
            return False, set()
    event = isinstance(query, (SIEMQuery, HistoryQuery))
    if event:
        occurred = _utc_timestamp(payload.get("occurred_at"))
        if occurred is None:
            missing.add("occurred_at")
        elif not (query.window.start <= occurred < query.window.end and occurred <= as_of):
            return False, set()
    publication_key = "observed_at" if event and "observed_at" in payload else "published_at"
    publication = _utc_timestamp(payload.get(publication_key))
    deadline = min(as_of, query.as_of) if isinstance(query, (TIQuery, AssetQuery)) else as_of
    if publication is None:
        missing.add(publication_key)
    elif publication > deadline:
        return False, set()
    elif event and occurred is not None and publication < occurred:
        missing.add("publication_before_occurrence")
    if isinstance(query, AttackQuery) and (query.technique_ids or query.behavior_terms):
        id_value = payload.get("technique_ids")
        singleton = payload.get("technique_id")
        term_value = payload.get("behavior_terms")
        valid_ids = isinstance(id_value, list) and all(isinstance(item, str) for item in id_value)
        valid_singleton = isinstance(singleton, str)
        valid_terms = isinstance(term_value, list) and all(isinstance(item, str) for item in term_value)
        id_match = bool(query.technique_ids and (
            (valid_singleton and singleton in query.technique_ids)
            or (valid_ids and set(id_value).intersection(query.technique_ids))
        ))
        term_match = bool(query.behavior_terms and valid_terms and set(term_value).intersection(query.behavior_terms))
        if not id_match and not term_match:
            attack_missing: set[str] = set()
            if query.technique_ids and not valid_ids and not valid_singleton:
                attack_missing.add("technique_ids")
            if query.behavior_terms and not valid_terms:
                attack_missing.add("behavior_terms")
            if not attack_missing:
                return False, set()
            missing.update(attack_missing)
    return not missing, missing


def select_records(
    query: ToolArguments, records: tuple[ToolRecord, ...], as_of: datetime,
) -> SelectionResult:
    """Return matches plus ambiguous exclusions, so unknown cannot become empty.

Only filtering metadata is required. Missing command bodies, process parents,
or other investigation facts do not exclude otherwise selected records. A
known selector/window/publication mismatch definitively excludes a record;
missing metadata on potentially matching records sets incomplete=True.
"""
    query = canonical_query(query)
    require_utc(as_of, "filter.as_of")
    selected: list[ToolRecord] = []
    missing_fields: set[str] = set()
    for record in records:
        matched, missing = _classify(query, record.payload, as_of)
        missing_fields.update(missing)
        if matched:
            selected.append(record)
    return SelectionResult(tuple(selected), bool(missing_fields), tuple(sorted(missing_fields)))
