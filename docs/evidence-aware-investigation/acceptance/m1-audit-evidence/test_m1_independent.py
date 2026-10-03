"""Independent M1 regression probes; run only against the captured audit snapshot."""
import importlib.util
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidence_investigation.state import codec, schema_loader as sl, validation
from evidence_investigation.state.contracts import (
    Alert, FinalAssessment, JsonValue, RawReference, SIEMQuery, TimeWindow,
    ToolCall, ToolName,
)
from evidence_investigation.state.errors import ProtocolViolation

ROOT = Path(os.environ.get("M1_AUDIT_ROOT", str(Path(__file__).resolve().parents[1])))
T0 = datetime(2026, 9, 1, 2, 14, tzinfo=timezone.utc)


@pytest.mark.parametrize("value", [{"process": {"pid": 123}}, ["e-1", {"n": 2}], {"a": [True, None]}])
def test_nested_json_values_roundtrip(value):
    assert codec.decode(JsonValue, codec.encode(value)) == value


def test_nested_alert_roundtrip():
    alert = Alert("a-1", "powershell", T0, T0, "h", "u", "p", None,
                  {"event": {"process": {"pid": 123}}, "tags": ["edr"]},
                  RawReference("r", "", "a" * 64))
    assert codec.decode(Alert, codec.encode(alert)) == alert


def test_json_integer_is_valid_float_number():
    assert codec.decode(float, 1) == 1.0


def test_typed_dictionary_rejects_unknown_tool_key():
    with pytest.raises(ProtocolViolation):
        codec.decode(dict[ToolName, int], {"hidden_tool": 1})


@pytest.mark.parametrize("value", [float("nan"), float("inf")])
def test_nonfinite_cost_rejected(value):
    with pytest.raises(ProtocolViolation):
        validation.require_non_negative(value, "cost")


@pytest.mark.parametrize("limit", [51, 1.5])
def test_invalid_query_limit_rejected(limit):
    query = SIEMQuery("host_events", TimeWindow(T0, T0 + timedelta(hours=1)), host="h", limit=limit)
    with pytest.raises(ProtocolViolation):
        validation.validate_query(query)


def test_siem_query_needs_entity_scope():
    with pytest.raises(ProtocolViolation):
        validation.validate_query(SIEMQuery("host_events", TimeWindow(T0, T0 + timedelta(hours=1))))


def test_tool_schema_correlates_name_and_arguments():
    bad = {"action": "tool", "tool": "siem", "arguments": {"host": "h", "as_of": "2026-09-01T02:14:00Z"}}
    with pytest.raises(ProtocolViolation):
        sl.validate_model_output(bad, sl.ACTION)


def test_schema_accepted_final_is_decodable():
    final = {"verdict": "Abstain", "disposition": "human_review", "stop_reason": "tool_budget",
             "claims": [], "final_evidence_ids": []}
    sl.validate_model_output(final, sl.FINAL_ASSESSMENT)
    codec.decode(FinalAssessment, final)


def test_runtime_final_roundtrip_passes_final_schema():
    final = FinalAssessment("Abstain", "human_review", "tool_budget", None, (), (), (), (),
                            "budget exhausted", "unavailable")
    sl.validate_model_output(codec.encode(final), sl.FINAL_ASSESSMENT)


def _guard_module():
    spec = importlib.util.spec_from_file_location("captured_boundary_guard", ROOT / "investigation/tests/test_import_boundaries.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("statement", [
    "from evidence_investigation.tools.contracts import EnvironmentFixture\n",
    "from ..tools.contracts import EnvironmentFixture\n",
])
def test_state_guard_detects_environment_import(tmp_path, statement):
    source = tmp_path / "state"
    source.mkdir()
    (source / "bad.py").write_text(statement, encoding="utf8")
    guard = _guard_module()
    guard.SRC = tmp_path
    with pytest.raises(AssertionError):
        guard.test_state_never_imports_tools()


def test_agents_guard_detects_environment_contract_import(tmp_path):
    source = tmp_path / "agents"
    source.mkdir()
    (source / "bad.py").write_text("from evidence_investigation.tools.contracts import EnvironmentFixture\n", encoding="utf8")
    guard = _guard_module()
    guard.SRC = tmp_path
    with pytest.raises(AssertionError):
        guard.test_src_never_imports_evaluation()


def test_evaluation_guard_detects_environment_import(tmp_path):
    (tmp_path / "bad.py").write_text("from evidence_investigation.tools.contracts import EnvironmentFixture\n", encoding="utf8")
    guard = _guard_module()
    guard.EVAL = tmp_path
    with pytest.raises(AssertionError):
        guard.test_evaluation_only_imports_stdlib_and_state()


def test_positive_control_unknown_reference_rejected():
    with pytest.raises(ProtocolViolation):
        validation.require_known_references(["e-404"], ["e-1"], "evidence")


def test_positive_control_private_field_rejected():
    with pytest.raises(ProtocolViolation):
        sl.validate_model_output({"action": "tool", "tool": "asset", "arguments": {"host": "h", "as_of": "2026-09-01T02:14:00Z"}, "hypotheses": []}, sl.ACTION)
