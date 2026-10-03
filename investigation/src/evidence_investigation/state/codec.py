"""dataclass ↔ JSON 编解码（M1）。

- encode：契约对象 → JSON 兼容值（datetime → ISO 8601 字符串，tuple → list）。
- decode：按类型注解递归还原；datetime 解析失败或类型不匹配抛 ProtocolViolation。
  解码不强制 UTC——时区约束由 validation.require_utc 在使用点强制。
"""

from __future__ import annotations

import dataclasses
import math
import types as _types
import typing
from datetime import datetime
from typing import Any, get_args, get_origin, get_type_hints

from .contracts import JsonValue
from .errors import ProtocolViolation

_NoneType = type(None)
_UnionForms = (typing.Union, _types.UnionType)  # Union[...] 与 X | Y 两种形态


def _require_finite(value: float, where: str) -> float:
    if not math.isfinite(value):
        raise ProtocolViolation(
            "non_finite_number", f"{where} 出现 NaN/Infinity，不能作为 JSON 数值"
        )
    return value


def encode(obj: Any) -> Any:
    """契约对象 → JSON 兼容值。"""
    if obj is None or isinstance(obj, (str, int, bool)):
        return obj
    if isinstance(obj, float):
        return _require_finite(obj, "encode")
    if isinstance(obj, datetime):
        return obj.isoformat()
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {
            f.name: encode(getattr(obj, f.name))
            for f in dataclasses.fields(obj)
        }
    if isinstance(obj, dict):
        return {str(k): encode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [encode(item) for item in obj]
    raise ProtocolViolation(
        "not_encodable", f"类型 {type(obj).__name__} 无法编码为 JSON"
    )


def _decode_json_value(data: Any) -> Any:
    """递归 JSON 值还原（M1-A1）：支持任意深度嵌套，保持 bool/int/float/null 区别。"""
    if data is None or isinstance(data, (str, bool, int)):
        return data
    if isinstance(data, float):
        return _require_finite(data, "decode")
    if isinstance(data, list):
        return [_decode_json_value(item) for item in data]
    if isinstance(data, dict):
        return {str(k): _decode_json_value(v) for k, v in data.items()}
    raise ProtocolViolation(
        "decode_type_mismatch", f"不是合法 JSON 值：{data!r}"
    )


def decode(tp: Any, data: Any) -> Any:
    """按类型注解把 JSON 值还原为契约对象。"""
    if isinstance(tp, typing.ForwardRef):
        # 受控前向引用：契约中仅 JsonValue 自引用（list["JsonValue"] 等）。
        if tp.__forward_arg__ == "JsonValue":
            return _decode_json_value(data)
        raise ProtocolViolation(
            "unsupported_type", f"无法解析前向引用 {tp.__forward_arg__!r}"
        )

    if tp is JsonValue:
        return _decode_json_value(data)

    if tp is None or tp is _NoneType:
        if data is None:
            return None
        raise ProtocolViolation("decode_type_mismatch", f"期望 null，收到 {data!r}")

    origin = get_origin(tp)

    if origin in _UnionForms or origin is typing.Union:
        if data is None and _NoneType in get_args(tp):
            return None
        for arg in get_args(tp):
            if arg is _NoneType:
                continue
            try:
                return decode(arg, data)
            except ProtocolViolation:
                continue
        raise ProtocolViolation(
            "decode_type_mismatch", f"值 {data!r} 不匹配联合类型 {tp}"
        )

    if tp is Any or tp is typing.Any:
        return data

    if get_origin(tp) is typing.Literal:
        if data not in get_args(tp):
            raise ProtocolViolation(
                "decode_type_mismatch", f"值 {data!r} 不在 {tp!r} 允许范围内"
            )
        return data

    if tp is datetime:
        if not isinstance(data, str):
            raise ProtocolViolation(
                "decode_type_mismatch", f"datetime 期望 ISO 字符串，收到 {data!r}"
            )
        try:
            return datetime.fromisoformat(data)
        except ValueError as exc:
            raise ProtocolViolation(
                "invalid_datetime", f"无法解析时间 {data!r}：{exc}"
            ) from exc

    if tp is float:
        # M1-A3：JSON number 包含整数字面量，模型可合法输出 p_attack=1（bool 仍拒绝）。
        if isinstance(data, bool) or not isinstance(data, (int, float)):
            raise ProtocolViolation("decode_type_mismatch", f"期望 number，收到 {data!r}")
        return _require_finite(float(data), "decode")

    if tp is int:
        if isinstance(data, bool) or not isinstance(data, int):
            raise ProtocolViolation("decode_type_mismatch", f"期望 int，收到 {data!r}")
        return data

    if tp in (str, bool):
        if not isinstance(data, tp):
            raise ProtocolViolation(
                "decode_type_mismatch", f"期望 {tp.__name__}，收到 {data!r}"
            )
        return data

    if dataclasses.is_dataclass(tp) and isinstance(tp, type):
        if not isinstance(data, dict):
            raise ProtocolViolation(
                "decode_type_mismatch", f"{tp.__name__} 期望对象，收到 {data!r}"
            )
        hints = get_type_hints(tp)
        field_names = {f.name for f in dataclasses.fields(tp)}
        unknown = set(data) - field_names
        if unknown:
            raise ProtocolViolation(
                "decode_unknown_field", f"{tp.__name__} 收到未知字段：{sorted(unknown)}"
            )
        kwargs = {name: decode(hints[name], data[name]) for name in data}
        for f in dataclasses.fields(tp):  # 补齐有默认值但未出现的字段
            if f.name not in kwargs and f.default is dataclasses.MISSING \
                    and f.default_factory is dataclasses.MISSING:
                raise ProtocolViolation(
                    "decode_missing_field", f"{tp.__name__} 缺少必填字段 {f.name}"
                )
        return tp(**kwargs)

    if origin in (list, tuple):
        args = get_args(tp)
        homogeneous = args[0] if (origin is tuple and len(args) == 2 and args[1] is Ellipsis) \
            else (args[0] if origin is list and args else None)
        if not isinstance(data, (list, tuple)):
            raise ProtocolViolation("decode_type_mismatch", f"期望数组，收到 {data!r}")
        if homogeneous is not None:
            items = [decode(homogeneous, item) for item in data]
        else:  # 固定长度异构 tuple
            if len(data) != len(args):
                raise ProtocolViolation(
                    "decode_type_mismatch",
                    f"期望 {len(args)} 元数组，收到 {len(data)} 元",
                )
            items = [decode(arg, item) for arg, item in zip(args, data)]
        return tuple(items) if origin is tuple else items

    if origin is dict:
        (key_tp, value_tp) = get_args(tp)
        if not isinstance(data, dict):
            raise ProtocolViolation("decode_type_mismatch", f"期望对象，收到 {data!r}")
        out: dict[str, Any] = {}
        for k, v in data.items():
            # M1-A6：键按声明类型校验，禁止静默字符串化未知键（如 dict[ToolName, …]）。
            decoded_key = decode(key_tp, k)
            if not isinstance(decoded_key, str):
                raise ProtocolViolation(
                    "invalid_dict_key", f"字典键解码后必须为字符串，收到 {decoded_key!r}"
                )
            out[decoded_key] = decode(value_tp, v)
        return out

    raise ProtocolViolation(
        "unsupported_type", f"解码不支持类型 {tp!r}"
    )
