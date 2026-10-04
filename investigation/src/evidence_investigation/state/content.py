"""Dataset boundary utilities, independent of tool and oracle implementations."""

from __future__ import annotations

import dataclasses
import json
import types
import typing
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from .contracts import JsonValue
from .errors import ProtocolViolation


def content_hash(value: JsonValue) -> str:
    """Hash exact JSON meaning; object order is canonical, array order retained."""
    def check(item):
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise ProtocolViolation("invalid_json_key", "JSON keys must be strings")
            for child in item.values():
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
        elif item is not None and not isinstance(item, (str, bool, int, float)):
            raise ProtocolViolation("invalid_json_value", "Only JSON values can be hashed")
    check(value)
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError) as exc:
        raise ProtocolViolation("invalid_json_value", "JSON must contain finite values") from exc
    return sha256(raw).hexdigest()


def load_json(path: str | Path) -> JsonValue:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProtocolViolation("duplicate_json_key", f"Duplicate JSON key: {key}")
            result[key] = value
        return result
    def constant(value):
        raise ProtocolViolation("non_finite_number", f"Invalid JSON constant: {value}")
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"),
                          object_pairs_hook=pairs, parse_constant=constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProtocolViolation("invalid_dataset_json", str(exc)) from exc


def opaque_id(kind: str, original: str, namespace: str = "runtime-v1") -> str:
    if not isinstance(namespace, str) or not namespace:
        raise ProtocolViolation("invalid_namespace", "Namespace must be nonempty")
    return kind + "-" + sha256((namespace + "\0" + kind + "\0" + original).encode()).hexdigest()


def contract_schema(contract: type) -> dict:
    """Closed JSON Schema derived only from the caller's own contract graph."""
    definitions = {"JsonValue": {"anyOf": [
        {"type": "null"}, {"type": "boolean"}, {"type": "number"}, {"type": "string"},
        {"type": "array", "items": {"$ref": "#/$defs/JsonValue"}},
        {"type": "object", "additionalProperties": {"$ref": "#/$defs/JsonValue"}},
    ]}}
    def schema(tp):
        if tp is JsonValue or isinstance(tp, typing.ForwardRef):
            return {"$ref": "#/$defs/JsonValue"}
        if tp is datetime:
            return {"type": "string", "format": "date-time"}
        if tp in (str, bool, int, float, type(None)):
            return {"type": {str: "string", bool: "boolean", int: "integer",
                             float: "number", type(None): "null"}[tp]}
        origin, args = typing.get_origin(tp), typing.get_args(tp)
        if origin in (typing.Union, types.UnionType):
            return {"anyOf": [schema(arg) for arg in args]}
        if origin is typing.Literal:
            return {"enum": list(args)}
        if origin in (tuple, list):
            if origin is list or len(args) == 2 and args[1] is Ellipsis:
                return {"type": "array", "items": schema(args[0])}
            return {"type": "array", "prefixItems": [schema(arg) for arg in args],
                    "minItems": len(args), "maxItems": len(args)}
        if origin is dict:
            result = {"type": "object", "additionalProperties": schema(args[1])}
            if typing.get_origin(args[0]) is typing.Literal:
                result["propertyNames"] = {"enum": list(typing.get_args(args[0]))}
            return result
        if dataclasses.is_dataclass(tp):
            name = tp.__name__
            if name not in definitions:
                definitions[name] = {}
                hints = typing.get_type_hints(tp)
                fields = dataclasses.fields(tp)
                definitions[name] = {
                    "type": "object", "additionalProperties": False,
                    "properties": {field.name: schema(hints[field.name]) for field in fields},
                    "required": [field.name for field in fields
                                 if field.default is dataclasses.MISSING
                                 and field.default_factory is dataclasses.MISSING],
                }
            return {"$ref": "#/$defs/" + name}
        raise TypeError(f"Unsupported contract type: {tp}")
    root = schema(contract)
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **root,
            "$defs": definitions}


def validate_document(contract: type, document: JsonValue) -> None:
    # JSON Schema alone permits Infinity in Python objects; canonical JSON does not.
    content_hash(document)
    validator = Draft202012Validator(contract_schema(contract), format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(document), key=lambda error: str(list(error.path)))
    if errors:
        raise ProtocolViolation("dataset_schema", errors[0].message)


_HIDDEN_KEYS = frozenset({"case_id", "family_id", "ground_truth", "complete_world_evidence",
                         "observable_fact_keys", "critical_fact_keys", "distractor_fact_keys",
                         "sufficient_sets", "acceptable_verdicts", "annotation_rationale",
                         "expected_actions", "resolvable_with_full_observable_evidence",
                         "oracle_only", "oracle_canary", "hidden_world_evidence"})


def reject_hidden_metadata(value: JsonValue) -> None:
    """Reject explicit oracle metadata, not words used by legitimate threat facts."""
    if isinstance(value, dict):
        illegal = set(value) & _HIDDEN_KEYS
        if illegal:
            raise ProtocolViolation("hidden_metadata", f"Oracle metadata at visible boundary: {sorted(illegal)}")
        for child in value.values():
            reject_hidden_metadata(child)
    elif isinstance(value, list):
        for child in value:
            reject_hidden_metadata(child)


def require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ProtocolViolation("empty_identity", f"{name} must be nonempty")


def resolve_pointer(document: JsonValue, pointer: str) -> JsonValue:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ProtocolViolation("invalid_json_pointer", "JSON Pointer must begin with /")
    current = document
    for token in pointer[1:].split("/"):
        index = 0
        while index < len(token):
            if token[index] == "~":
                if index + 1 >= len(token) or token[index + 1] not in "01":
                    raise ProtocolViolation("invalid_json_pointer", "Invalid JSON Pointer escape")
                index += 2
            else:
                index += 1
        token = token.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(current, list):
                if not token.isascii() or not token.isdigit() or len(token) > 1 and token[0] == "0":
                    raise KeyError(token)
                current = current[int(token)]
            elif isinstance(current, dict):
                current = current[token]
            else:
                raise KeyError(token)
        except (KeyError, IndexError) as exc:
            raise ProtocolViolation("dangling_json_pointer", f"JSON Pointer cannot resolve {pointer}") from exc
    return current
