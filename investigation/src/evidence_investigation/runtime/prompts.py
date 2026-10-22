"""Versioned prompt assets shared by baseline and Proposed runners."""

from __future__ import annotations

from hashlib import sha256
from importlib import resources

from evidence_investigation.state.errors import ProtocolViolation


def prompt_bytes(name: str) -> bytes:
    try:
        return resources.files("evidence_investigation.prompts").joinpath(name).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise ProtocolViolation("missing_prompt", f"missing versioned prompt {name}") from exc


def prompt_text(name: str) -> str:
    try:
        return prompt_bytes(name).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolViolation("invalid_prompt", f"prompt {name} is not UTF-8") from exc


def prompt_sha256(name: str) -> str:
    return sha256(prompt_bytes(name)).hexdigest()
