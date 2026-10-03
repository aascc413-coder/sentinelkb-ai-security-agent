"""Checks for the rewritten guard and new model-output entry point."""
import importlib.util
import os
from pathlib import Path

import pytest

from evidence_investigation.state.adapters import final_assessment_from_output
from evidence_investigation.state.errors import ProtocolViolation

ROOT = Path(os.environ.get("M1_AUDIT_ROOT", str(Path(__file__).resolve().parents[1])))


def guard_module():
    spec = importlib.util.spec_from_file_location("m1_retest_guard", ROOT / "investigation/tests/test_import_boundaries.py")
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    return guard


@pytest.mark.parametrize("zone,statement", [
    ("state", "from evidence_investigation import tools\n"),
    ("state", "from .. import tools\n"),
    ("agents", "from evidence_investigation import tools as environment\n"),
    ("evaluation", "from evidence_investigation import tools\n"),
])
def test_guard_detects_imported_module_alias(tmp_path, zone, statement):
    src = tmp_path / "src/evidence_investigation"
    evaluation = tmp_path / "evaluation"
    folder = evaluation if zone == "evaluation" else src / zone
    folder.mkdir(parents=True)
    (folder / "bad.py").write_text(statement, encoding="utf8")
    assert guard_module().find_violations(src, evaluation), "environment package import escaped the guard"


def test_guard_accepts_runtime_sibling_import(tmp_path):
    src = tmp_path / "src/evidence_investigation"
    folder = src / "state"
    folder.mkdir(parents=True)
    (folder / "good.py").write_text("from . import contracts\n", encoding="utf8")
    assert guard_module().find_violations(src, tmp_path / "evaluation") == []


def test_adapter_rejects_nonfinite_probability():
    payload = {"verdict": "Abstain", "disposition": "human_review", "stop_reason": "tool_budget",
               "claims": [], "final_evidence_ids": [], "p_attack": float("nan")}
    with pytest.raises(ProtocolViolation):
        final_assessment_from_output(payload)
