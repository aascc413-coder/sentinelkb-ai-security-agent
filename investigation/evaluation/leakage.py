"""Evaluation-only capture of actual ModelAdapter.complete inputs.

This is a structural experiment boundary check, not a prompt-injection detector.
Policy values remain in the evaluator and are never added to model messages.
`forwarded` means the wrapped adapter was invoked, not that a provider received
or billed the request. Provider credentials and headers are not captured here.
"""

from copy import deepcopy
from dataclasses import dataclass, fields
import json
import math
from pathlib import Path
import re
from typing import Literal

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.content import content_hash, load_json, require_text
from evidence_investigation.state.contracts import JsonValue
from evidence_investigation.state.errors import ProtocolViolation
from .contracts import OracleCase


# rubric_version is legitimate public run metadata; the remaining OracleCase
# fields belong to the evaluator and have no place in actual model inputs.
ORACLE_ONLY_FIELDS = frozenset(f.name for f in fields(OracleCase)
                             if f.name != "rubric_version") | frozenset({
    "annotation_version", "budget_profile", "discriminating_fact_keys",
    "risk_clue_fact_keys", "required_abstention", "avoidable_abstention",
    "required_human_review",
})
SOURCE_FIELDS = frozenset({"source", "source_kind", "source_type", "provenance",
                           "origin", "data_source"})


@dataclass(frozen=True)
class LeakagePolicy:
    forbidden_fields: frozenset[str] = ORACLE_ONLY_FIELDS
    canary_tokens: tuple[str, ...] = ()
    semantic_case_ids: tuple[str, ...] = ()
    forbidden_sources: tuple[str, ...] = ("oracle", "evaluation", "datasets/oracle")
    max_depth: int = 24

    def __post_init__(self):
        for name in ("forbidden_fields", "canary_tokens", "semantic_case_ids", "forbidden_sources"):
            values = getattr(self, name)
            if isinstance(values, str) or any(not isinstance(v, str) or not v for v in values):
                raise ValueError(f"{name} must contain nonempty strings")
            # A frozen dataclass alone would not protect a caller-supplied list.
            object.__setattr__(self, name, frozenset(values) if name == "forbidden_fields" else tuple(values))
        if type(self.max_depth) is not int or self.max_depth < 1:
            raise ValueError("max_depth must be a positive integer")


@dataclass(frozen=True)
class LeakageFinding:
    rule: Literal["oracle_field", "canary", "semantic_case_id", "forbidden_source", "inspection_limit"]
    path: str
    marker: str


@dataclass(frozen=True)
class CapturedRequest:
    request_index: int
    request: dict[str, JsonValue]
    findings: tuple[LeakageFinding, ...]
    forwarded: bool
    adapter_error_type: str | None = None


@dataclass(frozen=True)
class CaptureBundle:
    format_version: Literal["model-request-capture-v1"]
    run_id: str
    captures: tuple[CapturedRequest, ...]


def validate_capture(capture: CapturedRequest) -> CapturedRequest:
    request = capture.request
    required = {"messages", "output_schema", "max_output_tokens", "timeout_seconds"}
    if not isinstance(request, dict) or set(request) != required:
        raise ProtocolViolation("invalid_capture", "captured request fields differ")
    messages = request["messages"]
    if not isinstance(messages, list) or not messages:
        raise ProtocolViolation("invalid_capture", "captured messages must be a nonempty list")
    for message in messages:
        if (not isinstance(message, dict) or not isinstance(message.get("role"), str)
                or "content" not in message):
            raise ProtocolViolation("invalid_capture", "captured message requires role and content")
    if not isinstance(request["output_schema"], dict):
        raise ProtocolViolation("invalid_capture", "captured output schema must be an object")
    if type(request["max_output_tokens"]) is not int or request["max_output_tokens"] <= 0:
        raise ProtocolViolation("invalid_capture", "captured max_output_tokens must be positive")
    timeout = request["timeout_seconds"]
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or timeout <= 0):
        raise ProtocolViolation("invalid_capture", "captured timeout_seconds must be positive and finite")
    if type(capture.request_index) is not int or capture.request_index < 1:
        raise ProtocolViolation("invalid_capture", "captured request_index must be positive")
    return capture


def save_capture_bundle(path: str | Path, run_id: str,
                        captures: tuple[CapturedRequest, ...]) -> None:
    """Persist evaluation-only requests once, with an integrity digest."""
    require_text(run_id, "capture run_id")
    bundle = CaptureBundle("model-request-capture-v1", run_id, deepcopy(tuple(captures)))
    payload = encode(bundle)
    envelope = {"bundle": payload, "sha256": content_hash(payload)}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(envelope, stream, ensure_ascii=False, indent=1, allow_nan=False)
    except FileExistsError as exc:
        raise ProtocolViolation("capture_exists", "capture artifact is immutable") from exc


def load_capture_bundle(path: str | Path, expected_run_id: str) -> CaptureBundle:
    envelope = load_json(path)
    if not isinstance(envelope, dict) or set(envelope) != {"bundle", "sha256"}:
        raise ProtocolViolation("invalid_capture", "capture envelope fields differ")
    if content_hash(envelope["bundle"]) != envelope["sha256"]:
        raise ProtocolViolation("invalid_capture", "capture digest mismatch")
    bundle = decode(CaptureBundle, envelope["bundle"])
    if bundle.run_id != expected_run_id:
        raise ProtocolViolation("capture_run_mismatch", "capture belongs to another run")
    if tuple(item.request_index for item in bundle.captures) != tuple(range(1, len(bundle.captures) + 1)):
        raise ProtocolViolation("request_sequence", "persisted captures must be contiguous")
    for capture in bundle.captures:
        validate_capture(capture)
    return bundle


class LeakageBlocked(RuntimeError):
    """A request was captured but never forwarded to the wrapped adapter."""

    def __init__(self, findings):
        self.findings = tuple(findings)
        super().__init__(f"model input leakage blocked: {len(self.findings)} finding(s)")


def _path(parent, value):
    return parent + "/" + str(value).replace("~", "~0").replace("/", "~1")


def _preserve_pairs(items):
    """Preserve duplicate JSON values for inspection of text the model can see."""
    result = {}
    for key, value in items:
        if key in result:
            result[key] = [result[key], value]
        else:
            result[key] = value
    return result


def _json_fragments(text):
    """Inspect full JSON strings, fenced JSON and prose containing JSON objects."""
    decoder = json.JSONDecoder(object_pairs_hook=_preserve_pairs)
    stripped = text.strip()
    if stripped.startswith('"'):
        try:
            value, end = decoder.raw_decode(stripped)
            if not stripped[end:].strip():
                yield value
                return
        except (ValueError, RecursionError):
            pass
    index = 0
    while index < len(text):
        starts = [position for token in ("{", "[")
                  if (position := text.find(token, index)) >= 0]
        if not starts:
            return
        start = min(starts)
        try:
            value, end = decoder.raw_decode(text, start)
        except (ValueError, RecursionError):
            index = start + 1
        else:
            yield value
            index = end


def inspect_request(request, policy: LeakagePolicy | None = None) -> tuple[LeakageFinding, ...]:
    """Inspect a captured adapter input or a decoded provider request body.

    IDs use token boundaries (C1 does not match C10). Canary strings use exact,
    case-sensitive substring matching. Source checks apply only under declared
    source/provenance fields; ordinary malicious/benign words are never rules.
    Findings cannot establish authenticity of an input's source declaration.
    """
    policy = policy or LeakagePolicy()
    findings = []
    seen = set()
    id_patterns = [(identifier, re.compile(r"(?<![\w-])" + re.escape(identifier) + r"(?![\w-])"))
                   for identifier in policy.semantic_case_ids]

    def add(rule, path, marker):
        key = (rule, path, marker)
        if key not in seen:
            seen.add(key)
            findings.append(LeakageFinding(rule, path, marker))

    def walk(value, path, depth, source_context=False):
        if depth > policy.max_depth:
            add("inspection_limit", path, "maximum nesting exceeded")
            return
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = _path(path, key)
                if key in policy.forbidden_fields:
                    add("oracle_field", child_path, key)
                # Keys themselves may carry a dedicated marker or semantic ID.
                if isinstance(key, str):
                    scan_string(key, child_path + "#key", depth, False, parse=False)
                walk(child, child_path, depth + 1,
                     source_context or key in SOURCE_FIELDS)
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                walk(child, _path(path, index), depth + 1, source_context)
        elif isinstance(value, str):
            scan_string(value, path, depth, source_context)

    def scan_string(text, path, depth, source_context, parse=True):
        for token in policy.canary_tokens:
            if token in text:
                add("canary", path, token)
        for identifier, pattern in id_patterns:
            if pattern.search(text):
                add("semantic_case_id", path, identifier)
        if source_context:
            normalized = text.replace("\\", "/").strip().casefold().strip("/")
            for source in policy.forbidden_sources:
                target = source.replace("\\", "/").casefold().strip("/")
                if (normalized == target or normalized.startswith(target + "/")
                        or normalized.endswith("/" + target) or "/" + target + "/" in normalized):
                    add("forbidden_source", path, source)
        if parse:
            for index, fragment in enumerate(_json_fragments(text)):
                walk(fragment, path + f"#json/{index}", depth + 1, source_context)

    walk(request, "", 0)
    return tuple(findings)


class CapturingModelAdapter:
    """Wrap an adapter in detection or blocking mode without leaking policy data.

    `detect` records findings and forwards the unchanged inputs. `block` records
    the attempt but raises LeakageBlocked before invoking the adapter. Captures
    and forwarded inputs are separate deep copies, including repair requests.
    """

    def __init__(self, adapter, *, policy: LeakagePolicy | None = None,
                 mode: Literal["detect", "block"] = "detect"):
        if mode not in {"detect", "block"}:
            raise ValueError("mode must be detect or block")
        self.adapter = adapter
        self.policy = policy or LeakagePolicy()
        self.mode = mode
        self._captures: list[CapturedRequest] = []

    @property
    def captures(self) -> tuple[CapturedRequest, ...]:
        return deepcopy(tuple(self._captures))

    async def complete(self, messages, output_schema, max_output_tokens, timeout_seconds):
        request = deepcopy({"messages": messages, "output_schema": output_schema,
                            "max_output_tokens": max_output_tokens, "timeout_seconds": timeout_seconds})
        findings = inspect_request(request, self.policy)
        forwarded = self.mode == "detect" or not findings
        index = len(self._captures)
        captured = CapturedRequest(index + 1, request, findings, forwarded)
        self._captures.append(captured)
        if not forwarded:
            raise LeakageBlocked(findings)
        outbound = deepcopy(request)
        try:
            return await self.adapter.complete(
                outbound["messages"], outbound["output_schema"],
                outbound["max_output_tokens"], outbound["timeout_seconds"],
            )
        except BaseException as exc:
            self._captures[index] = CapturedRequest(index + 1, request, findings, True,
                                                     type(exc).__name__)
            raise

    async def aclose(self):
        close = getattr(self.adapter, "aclose", None)
        if close is not None:
            await close()
