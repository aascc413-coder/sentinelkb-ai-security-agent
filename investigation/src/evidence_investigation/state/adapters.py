"""模型输出 → 运行时对象适配器（M1-A7 约定固化）。

**结构约定（统一结构方案，依复核意见调整）**：FinalAssessment dataclass 与
final_assessment.schema.json 字段一一对应，可选字段在两侧均有缺省——
Schema 可接受的最小输出可直接 `codec.decode(FinalAssessment, …)`，
完整运行时对象 `encode` 后也可通过 Schema 校验。

适配器 `final_assessment_from_output` 仍是模型输出进入运行时的**规定入口**，
职责是程序侧语义强制：
- `confidence_status` 永远覆写为 `uncalibrated`（模型不得主张校准状态）；
- 缺省字段显式补齐并留痕于本文件，M4/M5 不得另行猜测。
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from .codec import decode
from .contracts import Claim, FinalAssessment
from .schema_loader import FINAL_ASSESSMENT, validate_model_output

#: 程序强制字段的值（模型声明被忽略）
DEFAULT_CONFIDENCE_STATUS = "uncalibrated"


def final_assessment_from_output(payload: dict[str, Any]) -> FinalAssessment:
    """Schema 校验模型输出后构造运行时 FinalAssessment，并强制程序侧字段。"""
    validate_model_output(payload, FINAL_ASSESSMENT)
    assessment = decode(FinalAssessment, payload)
    return replace(assessment, confidence_status=DEFAULT_CONFIDENCE_STATUS)


def codec_claim(raw: dict[str, Any]) -> Claim:
    """单条 claim：模型 dict → 运行时对象（复用 codec 的字段严格性）。"""
    from .codec import decode

    return decode(Claim, raw)
