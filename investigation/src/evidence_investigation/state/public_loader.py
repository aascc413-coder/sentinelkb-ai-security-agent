"""Public inputs only: no environment or oracle contract imports."""

from dataclasses import replace
from pathlib import Path

from .codec import decode, encode
from .content import (content_hash, load_json, opaque_id, reject_hidden_metadata,
                      require_text, resolve_pointer, validate_document)
from .contracts import PublicCase
from .errors import ProtocolViolation
from .validation import validate_alert


def validate_public(case: PublicCase) -> PublicCase:
    validate_document(PublicCase, encode(case))
    if decode(PublicCase, encode(case)) != case:
        raise ProtocolViolation("invalid_dataset_structure", "PublicCase must use typed contract fields")
    validate_alert(case.alert)
    alert = case.alert
    for name in ("alert_id", "alert_type"):
        require_text(getattr(alert, name), "alert." + name)
    require_text(alert.raw_reference.record_id, "alert.raw_reference.record_id")
    reject_hidden_metadata(alert.raw)
    if alert.raw_reference.content_sha256 != content_hash(alert.raw):
        raise ProtocolViolation("content_hash_mismatch", "Alert raw hash does not match raw document")
    resolve_pointer(alert.raw, alert.raw_reference.json_pointer)
    return case


def load_public(path: str | Path, *, namespace: str = "runtime-v1",
                remap_ids: bool = True) -> PublicCase:
    if type(remap_ids) is not bool:
        raise ProtocolViolation("invalid_mode", "remap_ids must be bool")
    document = load_json(path)
    validate_document(PublicCase, document)
    case = validate_public(decode(PublicCase, document))
    if not remap_ids:
        return case
    alert = case.alert
    reference_kind = "alert" if alert.raw_reference.record_id == alert.alert_id else "record"
    reference = replace(alert.raw_reference,
                        record_id=opaque_id(reference_kind, alert.raw_reference.record_id, namespace))
    return replace(case, alert=replace(alert, alert_id=opaque_id("alert", alert.alert_id, namespace),
                                       raw_reference=reference))
