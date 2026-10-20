"""Adversarial dataset boundary checks, without relying on the M3 server."""

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from evaluation.contracts import ActionExpectation, OracleCase
from evaluation.oracle_loader import load_oracle, validate_oracle
from evidence_investigation.state.codec import encode
from evidence_investigation.state.content import content_hash, contract_schema, opaque_id
from evidence_investigation.state.contracts import (
    Alert, Coverage, PublicCase, RawReference, Reliability, TimeWindow, ToolRecord,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.public_loader import load_public, validate_public
from evidence_investigation.tools.contracts import EnvironmentFixture, FixtureRule
from evidence_investigation.tools.fixture_loader import load_environment, validate_environment

T0 = datetime(2026, 9, 1, 2, 14, tzinfo=timezone.utc)
AS_OF = datetime(2026, 9, 1, 2, 20, tzinfo=timezone.utc)
WINDOW = TimeWindow(T0, AS_OF)
RAW = {"detector": {"rule": "encoded PowerShell", "note": "malicious and benign are legal words"}}
PUBLIC = PublicCase(Alert("original-alert", "powershell", T0, AS_OF, "WS-041", "analyst-a",
                         "p-101", None, RAW,
                         RawReference("original-alert", "/detector", content_hash(RAW))))
PAYLOAD = {"host": "WS-041", "view": "process_tree", "process_id": "p-101",
           "occurred_at": T0.isoformat(), "observed_at": AS_OF.isoformat(),
           "maintenance_window_end": "2026-09-01T03:00:00+00:00"}
RECORD = ToolRecord("original-record", PAYLOAD, content_hash(PAYLOAD), "edr", "group-original",
                    Reliability("high", "collected by EDR", "policy-v1"))
RULE = FixtureRule("siem", {"view": "process_tree", "host": "WS-041"}, (RECORD.record_id,),
                   "ok", Coverage({"view": "process_tree", "host": "WS-041"},
                                  WINDOW, "complete", False, ()), False, None)
ENV = EnvironmentFixture("fixture-original", AS_OF, {"siem": (RECORD,)}, (RULE,), "v1")
ORACLE = OracleCase("C1", "powershell", "dev", "malicious", {"E0": {}, "E1": {}, "E2": {}},
                    ("E0", "E1"), ("E1", "E2"), ("E0",), {"TP": (("E1",),), "FP": ()},
                    ("TP",), True, (), "powershell-v1", "Observable E1 is sufficient; E2 is hidden")


def save(tmp_path, value, name="input.json"):
    path = tmp_path / name
    path.write_text(json.dumps(encode(value), ensure_ascii=False), encoding="utf-8")
    return path


def test_valid_loads_and_consistent_opaque_references(tmp_path):
    public = load_public(save(tmp_path, PUBLIC, "public.json"))
    env = load_environment(save(tmp_path, ENV, "environment.json"))
    assert public.alert.alert_id == public.alert.raw_reference.record_id
    assert public.alert.alert_id != PUBLIC.alert.alert_id
    assert env.query_rules[0].record_ids == (env.records_by_tool["siem"][0].record_id,)
    assert env.records_by_tool["siem"][0].payload == PAYLOAD
    assert env.records_by_tool["siem"][0].content_sha256 == RECORD.content_sha256
    assert public.alert.host == "WS-041"
    assert load_oracle(save(tmp_path, ORACLE, "oracle.json")) == ORACLE


def test_twin_remapping_ignores_filename_and_world_label(tmp_path):
    first = load_public(save(tmp_path, PUBLIC, "C4.json"))
    second = load_public(save(tmp_path, PUBLIC, "C5.json"))
    assert first == second
    assert opaque_id("record", "id", "a") != opaque_id("record", "id", "b")
    assert opaque_id("record", "id", "a") != opaque_id("alert", "id", "a")


@pytest.mark.parametrize("contract,loader,value", [
    (PublicCase, load_public, PUBLIC),
    (EnvironmentFixture, load_environment, ENV),
    (OracleCase, load_oracle, ORACLE),
])
def test_closed_schema_rejects_wrong_zone_and_unknown_fields(tmp_path, contract, loader, value):
    document = encode(value)
    document["accidental_private_metadata"] = "secret"
    path = save(tmp_path, document)
    with pytest.raises(ProtocolViolation, match="dataset_schema"):
        loader(path)
    assert contract_schema(contract)["$defs"][contract.__name__]["additionalProperties"] is False


@pytest.mark.parametrize("loader", [load_public, load_environment, load_oracle])
def test_duplicate_json_keys_and_nan_are_rejected_before_decode(tmp_path, loader):
    path = tmp_path / "bad.json"
    path.write_text('{"x": 1, "x": 2}', encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="duplicate_json_key"):
        loader(path)
    path.write_text('{"x": NaN}', encoding="utf-8")
    with pytest.raises(ProtocolViolation, match="non_finite_number"):
        loader(path)


@pytest.mark.parametrize("mutate", [
    lambda a: replace(a, occurred_at=datetime(2026, 9, 1, 2, 21, tzinfo=timezone.utc)),
    lambda a: replace(a, as_of=AS_OF.replace(tzinfo=None)),
    lambda a: replace(a, raw_reference=replace(a.raw_reference, content_sha256="0" * 64)),
    lambda a: replace(a, raw_reference=replace(a.raw_reference, json_pointer="/not-here")),
    lambda a: replace(a, raw_reference=replace(a.raw_reference, json_pointer="/detector/~2")),
    lambda a: replace(a, alert_id=" "),
])
def test_invalid_public_provenance_and_time_rejected(mutate):
    with pytest.raises(ProtocolViolation):
        validate_public(replace(PUBLIC, alert=mutate(PUBLIC.alert)))


def test_nested_oracle_metadata_rejected_but_legitimate_verdict_words_allowed():
    assert validate_public(PUBLIC) == PUBLIC
    raw = {"nested": [{"ground_truth": "malicious"}]}
    alert = replace(PUBLIC.alert, raw=raw, raw_reference=RawReference("r", "", content_hash(raw)))
    with pytest.raises(ProtocolViolation, match="hidden_metadata"):
        validate_public(PublicCase(alert))


def env_record(payload=None, **updates):
    payload = PAYLOAD if payload is None else payload
    record = replace(RECORD, payload=payload, content_sha256=content_hash(payload), **updates)
    return replace(ENV, records_by_tool={"siem": (record,)})


@pytest.mark.parametrize("key,value", [
    ("published_at", "2026-09-01T02:21:00+00:00"),
    ("observed_at", "2026-09-01T02:10:00+00:00"),
    ("occurred_at", "2026-09-01T02:14:00+08:00"),
    ("published_at", "not-a-time"),
])
def test_fixture_refuses_future_naive_and_impossible_publication(key, value):
    with pytest.raises(ProtocolViolation):
        validate_environment(env_record({**PAYLOAD, key: value}))


def test_prospective_approval_expiry_does_not_make_publication_future():
    assert validate_environment(ENV) == ENV


@pytest.mark.parametrize("rule", [
    replace(RULE, status="unavailable", record_ids=(), error_code="gone"),
    replace(RULE, status="empty", record_ids=(), coverage=replace(RULE.coverage, completeness="unknown")),
    replace(RULE, status="partial"),
    replace(RULE, status="nonsense"),
    replace(RULE, record_ids=("another-tool-record",)),
    replace(RULE, argument_constraints={"host": "WS-041", "unknown_filter": "x"}),
    replace(RULE, argument_constraints={"view": "network-events-misspelled"}),
    replace(RULE, coverage=replace(RULE.coverage, truncated=True)),
    replace(RULE, coverage=replace(RULE.coverage, missing_sources=("edr",))),
    replace(RULE, retryable=True),
])
def test_status_coverage_constraints_and_dangling_references_rejected(rule):
    with pytest.raises(ProtocolViolation):
        validate_environment(replace(ENV, query_rules=(rule,)))


def test_duplicate_record_ids_across_tools_and_ambiguous_rules_rejected():
    with pytest.raises(ProtocolViolation, match="duplicate_id"):
        validate_environment(replace(ENV, records_by_tool={"siem": (RECORD,), "asset": (RECORD,)}))
    with pytest.raises(ProtocolViolation, match="duplicate_rule"):
        validate_environment(replace(ENV, query_rules=(RULE, RULE)))


def test_record_hash_and_provenance_rejected():
    with pytest.raises(ProtocolViolation, match="content_hash_mismatch"):
        validate_environment(replace(ENV, records_by_tool={"siem": (replace(RECORD, content_sha256="0"*64),)}))
    with pytest.raises(ProtocolViolation, match="empty_identity"):
        validate_environment(env_record(source_system=" "))


@pytest.mark.parametrize("update", [
    {"sufficient_sets": {"TP": (("E2",),)}},
    {"sufficient_sets": {"TP": ((),)}},
    {"sufficient_sets": {"TP": (("E1",), ("E1",))}},
    {"sufficient_sets": {"Suspicious": (("E1",),)}},
    {"critical_fact_keys": ("missing",)},
    {"distractor_fact_keys": ("E1",)},
    {"acceptable_verdicts": ("FP",)},
    {"resolvable_with_full_observable_evidence": False},
    {"observable_fact_keys": ("E0", "E0", "E1")},
])
def test_oracle_semantic_errors_rejected(update):
    with pytest.raises(ProtocolViolation):
        validate_oracle(replace(ORACLE, **update))


def test_hidden_only_critical_keys_and_empty_observable_denominator_are_valid():
    oracle = replace(ORACLE, observable_fact_keys=("E0",), critical_fact_keys=("E2",),
                     distractor_fact_keys=(), sufficient_sets={"TP": (), "FP": ()},
                     acceptable_verdicts=("Abstain",), resolvable_with_full_observable_evidence=False)
    assert validate_oracle(oracle) == oracle
    assert not set(oracle.critical_fact_keys) & set(oracle.observable_fact_keys)


def test_schema_assets_match_generated_contracts():
    root = Path(__file__).resolve().parents[1]
    locations = [(PublicCase, root / "src/evidence_investigation/state/schemas/public_case.schema.json"),
                 (EnvironmentFixture, root / "src/evidence_investigation/tools/schemas/environment_fixture.schema.json"),
                 (OracleCase, root / "evaluation/schemas/oracle_case.schema.json")]
    for contract, path in locations:
        assert json.loads(path.read_text(encoding="utf-8")) == contract_schema(contract)


def test_direct_validator_rejects_structurally_json_valid_but_untyped_objects():
    with pytest.raises(ProtocolViolation, match="invalid_dataset_structure"):
        validate_public(replace(PUBLIC, alert=replace(PUBLIC.alert, occurred_at=T0.isoformat())))
    with pytest.raises(ProtocolViolation, match="invalid_dataset_structure"):
        validate_environment(replace(ENV, query_rules=[RULE]))
    with pytest.raises(ProtocolViolation, match="invalid_dataset_structure"):
        validate_oracle(replace(ORACLE, critical_fact_keys=["E1", "E2"]))


@pytest.mark.parametrize("key", ["expected_actions", "resolvable_with_full_observable_evidence"])
@pytest.mark.parametrize("surface", ["public", "environment"])
def test_investigation_path_and_resolvability_annotations_are_private(key, surface):
    if surface == "public":
        raw = {**RAW, "nested": [{key: "evaluation hint"}]}
        case = replace(PUBLIC, alert=replace(PUBLIC.alert, raw=raw,
                       raw_reference=RawReference("original-alert", "", content_hash(raw))))
        with pytest.raises(ProtocolViolation, match="hidden_metadata"):
            validate_public(case)
    else:
        payload = {**PAYLOAD, "nested": [{key: "evaluation hint"}]}
        with pytest.raises(ProtocolViolation, match="hidden_metadata"):
            validate_environment(env_record(payload))


@pytest.mark.parametrize("tool,constraints", [
    ("asset", {"host": True}), ("asset", {"host": 17}),
    ("asset", {"unknown_filter": "x"}), ("asset", {"as_of": "not-time"}),
    ("asset", {"as_of": "2026-09-01T02:20:00+08:00"}),
    ("siem", {"limit": False}), ("siem", {"limit": 0}), ("siem", {"limit": 51}),
    ("siem", {"window": {"start": "2026-09-01T02:20:00+00:00", "end": "2026-09-01T02:10:00+00:00"}}),
    ("siem", {"window": {"start": "2026-09-01T00:00:00+00:00", "end": "2026-09-03T00:00:00+00:00"}}),
    ("history", {"window": {"start": "2026-08-01T00:00:00+00:00", "end": "2026-09-03T00:00:00+00:00"}}),
    ("attack", {"behavior_terms": [""]}),
])
def test_expected_actions_reject_bad_fields_types_time_and_ranges(tool, constraints):
    action = ActionExpectation(("E0",), ("E1",), (tool,), constraints, "Check critical behavior")
    with pytest.raises(ProtocolViolation, match="invalid_action_constraints"):
        validate_oracle(replace(ORACLE, expected_actions=(action,)))


def test_multi_tool_partial_constraints_need_one_complete_compatible_type():
    good = ActionExpectation(("E0",), ("E1",), ("asset", "history"), {"host": "h"}, "Check authorization")
    assert validate_oracle(replace(ORACLE, expected_actions=(good,))).expected_actions == (good,)
    # Each key belongs to some named tool, but no tool accepts the entire predicate.
    bad = replace(good, argument_constraints={"host": "h", "entity": "h", "as_of": AS_OF.isoformat()})
    with pytest.raises(ProtocolViolation, match="invalid_action_constraints"):
        validate_oracle(replace(ORACLE, expected_actions=(bad,)))
    # One compatible alternative is enough; missing fields do not imply a full query.
    specific = replace(good, argument_constraints={"entity_type": "host", "entity": "h"})
    assert validate_oracle(replace(ORACLE, expected_actions=(specific,))).expected_actions == (specific,)
