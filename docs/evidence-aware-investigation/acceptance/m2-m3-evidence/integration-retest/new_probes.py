"""Independent continuation review of primary scripts and rule selection."""
from dataclasses import replace
from datetime import datetime, timezone
import json

import pytest

from probes import copy_data, modify, module, world, call, win
from evidence_investigation.state.contracts import TIQuery, SIEMQuery
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.selection import matches_constraints

AS_OF = datetime(2026, 9, 1, 2, 20, tzinfo=timezone.utc)


def test_valid_partial_ti_type_constraint_nonmatch_does_not_parse_request_value_as_other_type():
    assert not matches_constraints(TIQuery("hash", "h-9", AS_OF), {"indicator_type": "ip"})


def test_summary_ungrounded_failure_envelope_rejected(tmp_path):
    root = copy_data(tmp_path)
    modify(root, "oracle/c3.json", lambda doc: doc["complete_world_evidence"]["E5"].update(reason="invented_failure"))
    with pytest.raises(ProtocolViolation, match="ungrounded_annotation"):
        module("dataset_summary").summarize(root)


def test_summary_unknown_annotation_source_rejected(tmp_path):
    root = copy_data(tmp_path)
    modify(root, "oracle/c1.json", lambda doc: doc["complete_world_evidence"]["E1"].update(source="unknown_sensor"))
    with pytest.raises(ProtocolViolation, match="annotation_source_mismatch"):
        module("dataset_summary").summarize(root)


@pytest.mark.parametrize("value", [None, "not structured", 17])
def test_summary_annotation_shape_rejected_with_protocol_error(tmp_path, value):
    root = copy_data(tmp_path)
    modify(root, "oracle/c1.json", lambda doc: doc["complete_world_evidence"].update(E1=value))
    with pytest.raises(ProtocolViolation, match="invalid_annotation"):
        module("dataset_summary").summarize(root)


def test_summary_nonstring_record_reference_rejected(tmp_path):
    root = copy_data(tmp_path)
    modify(root, "oracle/c1.json", lambda doc: doc["complete_world_evidence"]["E1"].update(record_ids=[True]))
    with pytest.raises(ProtocolViolation, match="invalid_annotation"):
        module("dataset_summary").summarize(root)


@pytest.mark.asyncio
async def test_request_optional_process_constraint_cannot_expand_claimed_complete_scope():
    alert, server = world(1)
    result = await call(server, alert, "siem", SIEMQuery("process_tree", win(alert), alert.host, alert.user, "different-process"))
    assert result.status == "partial" and result.records == ()
    assert result.coverage.completeness == "partial"


def test_summary_public_asof_environment_mismatch_rejected(tmp_path):
    root = copy_data(tmp_path)
    modify(root, "public/c1.json", lambda doc: doc["alert"].update(as_of="2026-09-01T02:21:00+00:00"))
    with pytest.raises(ProtocolViolation, match="dataset_mapping_mismatch"):
        module("dataset_summary").summarize(root)
