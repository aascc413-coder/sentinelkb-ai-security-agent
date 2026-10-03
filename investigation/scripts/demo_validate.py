"""M1 校验演示：构造非法输入，展示确定性拒绝与可读错误。

运行（在装有包的 venv 中）：
    investigation\\.venv\\Scripts\\python.exe investigation\\scripts\\demo_validate.py
每项演示输出 REJECTED（附 code 与原因）或 ACCEPTED；预期全部 REJECTED。
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1] / "src"))

from evidence_investigation.state import validation  # noqa: E402
from evidence_investigation.state.contracts import (  # noqa: E402
    Alert,
    Claim,
    FinalAssessment,
    RawReference,
    TimeWindow,
)
from evidence_investigation.state.errors import ProtocolViolation  # noqa: E402

UTC = timezone.utc
T0 = datetime(2026, 9, 1, 2, 14, tzinfo=UTC)


def _show(title: str, fn) -> None:
    try:
        fn()
    except ProtocolViolation as exc:
        print(f"REJECTED  {title}\n          code={exc.code}  {exc.message}")
    else:
        print(f"ACCEPTED  {title}  <-- 意外，请检查！")
        raise SystemExit(1)


# 1) 错误时区：naive 时间（无时区）
def case_naive_datetime() -> None:
    validation.require_utc(datetime(2026, 9, 1, 2, 14), "告警时间")


_show("1. naive 时间（无时区）", case_naive_datetime)

# 2) 错误时区：非 UTC 偏移（+08:00）
def case_non_utc() -> None:
    validation.require_utc(datetime(2026, 9, 1, 10, 14, tzinfo=timezone(timedelta(hours=8))), "告警时间")


_show("2. 非 UTC 偏移（+08:00）", case_non_utc)

# 3) 非法时间窗：start >= end
def case_bad_window() -> None:
    validation.require_time_window(TimeWindow(T0, T0))


_show("3. 时间窗 start >= end", case_bad_window)

# 4) 悬空引用：最终证据引用未获得的 e-999
def case_dangling_reference() -> None:
    final = FinalAssessment(
        verdict="TP", disposition="escalate", stop_reason="sufficient",
        p_attack=0.9, claims=(), final_evidence_ids=("e-999",),
        unresolved_questions=(), risk_flags=(), abstain_reason=None,
        confidence_status="uncalibrated",
    )
    validation.validate_final_assessment(final, available_evidence_ids=["e-1", "e-2"])


_show("4. 最终证据引用未获得的 e-999", case_dangling_reference)

# 5) 概率越界：p_attack = 1.5
def case_bad_probability() -> None:
    validation.require_probability(1.5, "p_attack")


_show("5. p_attack = 1.5 超出 [0,1]", case_bad_probability)

# 6) 告警发生时间晚于 as_of
def case_occurred_after_as_of() -> None:
    alert = Alert(
        alert_id="a-1", alert_type="powershell_encoded",
        occurred_at=T0.replace(minute=30), as_of=T0,
        host="WS-041", user=None, process_id=None, command_line=None,
        raw={}, raw_reference=RawReference("r", "/a/0", "0" * 64),
    )
    validation.validate_alert(alert)


_show("6. 告警 occurred_at 晚于 as_of", case_occurred_after_as_of)

# 7) claim 引用不存在的证据
def case_claim_dangling() -> None:
    final = FinalAssessment(
        verdict="FP", disposition="close_recommended", stop_reason="sufficient",
        p_attack=0.1,
        claims=(Claim("c-1", "h", "p", "v", ("e-404",), "t", "observation"),),
        final_evidence_ids=(), unresolved_questions=(), risk_flags=(),
        abstain_reason=None, confidence_status="uncalibrated",
    )
    validation.validate_final_assessment(final, available_evidence_ids=["e-1"])


_show("7. claim 引用不存在的证据", case_claim_dangling)

print("\n演示完成：7 项非法输入全部被确定性拒绝。")
