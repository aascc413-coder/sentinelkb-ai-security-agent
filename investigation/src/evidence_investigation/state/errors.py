"""契约违反异常（M1）。

所有运行时校验失败都抛出 ProtocolViolation，携带机器可读 code，
供 Dispatcher/Agent 将其映射为 stop_reason=protocol_error（设计稿 4.3 节）。
"""

from __future__ import annotations


class ProtocolViolation(Exception):
    """契约违反：非法引用、时区、参数、概率、成本或 Schema 不合规。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message
