"""模型输出 JSON Schema 加载与校验（M1）。

schemas/ 下每份 *.schema.json 注册为独立资源，支持文件间 $ref；
统一按 Draft 2020-12 校验并启用 format 检查（date-time 等）。
校验失败抛 ProtocolViolation("schema_violation")，由调用方计入
ModelOutputRecord.validation_error（V4-3A）。
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from .errors import ProtocolViolation

SCHEMA_DIR = Path(resources.files("evidence_investigation.state")) / "schemas"

COMMON = "common.schema.json"
HYPOTHESIS_PROPOSAL = "hypothesis_proposal.schema.json"
PLAN = "plan.schema.json"
SUFFICIENCY_EXPLANATION = "sufficiency_explanation.schema.json"
FINAL_ASSESSMENT = "final_assessment.schema.json"
ACTION = "action.schema.json"

#: 可用于校验模型输出的 Schema（common 只是共享 $defs 载体，不单独校验输出）
SCHEMA_NAMES = (
    HYPOTHESIS_PROPOSAL, PLAN, SUFFICIENCY_EXPLANATION, FINAL_ASSESSMENT, ACTION,
)
#: 需要注册进 referencing Registry 的全部资源
_REGISTERED = (COMMON,) + SCHEMA_NAMES


@lru_cache(maxsize=1)
def _load_contents(name: str) -> dict[str, Any]:
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _registry() -> Registry:
    registry: Registry = Registry()
    for name in _REGISTERED:
        contents = _load_contents(name)
        resource = Resource.from_contents(contents, default_specification=DRAFT202012)
        uri = contents.get("$id", name)
        registry = registry.with_resource(uri, resource)
    return registry


def schema_contents(name: str = ACTION) -> dict[str, Any]:
    """返回指定 Schema 的原始内容（供 ModelAdapter 作为 output_schema 下发）。"""
    if name not in SCHEMA_NAMES:
        raise ProtocolViolation("unknown_schema", f"未知 Schema：{name}")
    return _load_contents(name)


def validate_model_output(instance: Any, name: str = ACTION) -> None:
    """校验模型输出；失败抛 ProtocolViolation，错误信息含 JSON 路径。"""
    if name not in SCHEMA_NAMES:
        raise ProtocolViolation("unknown_schema", f"未知 Schema：{name}")
    validator = jsonschema.Draft202012Validator(
        _load_contents(name),
        registry=_registry(),
        format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER,
    )
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    if errors:
        first = errors[0]
        location = "/".join(str(p) for p in first.absolute_path) or "<root>"
        raise ProtocolViolation(
            "schema_violation",
            f"{name} 校验失败于 {location}: {first.message}"
            + (f"（另有 {len(errors) - 1} 处）" if len(errors) > 1 else ""),
        )
