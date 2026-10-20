"""Trace 记录器（M4）：每 run 三件套 manifest.json / events.jsonl / final.json。

事件契约见 state.contracts.TraceEvent（设计稿 12 节）：
sequence 递增、UTC 时间、elapsed_ms、step、事件类型、state_version 前后、
payload（JSON 值）与 usage 快照。重放读取 read_trace，不再调用模型或工具。

run_id 由调用方生成（建议 uuid4.hex）；本模块不做业务决策，只做
确定性记录与基本校验（事件类型合法、payload 可编码、时钟单调）。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import (
    EventType, FinalAssessment, JsonValue, RunManifest, TraceEvent, Usage,
)
from evidence_investigation.state.errors import ProtocolViolation


@dataclass(frozen=True)
class TraceBundle:
    manifest: RunManifest
    events: tuple[TraceEvent, ...]
    final: FinalAssessment | None
    final_payload: dict | None


class TraceRecorder:
    """顺序写入 events.jsonl；manifest 在构造时落盘，final 在 finalize 时落盘。"""

    def __init__(
        self, run_id: str, manifest: RunManifest, output_dir: Path,
        *, usage_provider: Callable[[], Usage],
        wall_clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if not run_id or not isinstance(run_id, str):
            raise ProtocolViolation("invalid_run_id", "run_id 必须为非空字符串")
        if Path(run_id).name != run_id or run_id in {".", ".."} or "/" in run_id or "\\" in run_id:
            raise ProtocolViolation("invalid_run_id", "run_id must be a single path component")
        if manifest.run_id != run_id:
            raise ProtocolViolation("run_id_mismatch", "manifest and recorder run_id differ")
        self.run_id = run_id
        self._manifest = decode(RunManifest, encode(manifest))
        self._usage_provider = usage_provider
        self._wall = wall_clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic
        self._started = self._monotonic()
        self._events: list[TraceEvent] = []
        self._final: FinalAssessment | None = None
        self._finalized = False
        self.dir = Path(output_dir) / run_id
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        try:
            self.dir.mkdir(exist_ok=False)
        except FileExistsError as exc:
            raise ProtocolViolation("run_exists", "refusing to mix existing trace files") from exc
        (self.dir / "manifest.json").write_text(
            json.dumps(encode(self._manifest), ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        self._events_path = self.dir / "events.jsonl"
        self._events_path.touch(exist_ok=True)

    @property
    def events(self) -> tuple[TraceEvent, ...]:
        return tuple(self._events)

    @property
    def finalized(self) -> bool:
        return self._finalized

    def emit(
        self, event_type: str, payload: dict[str, JsonValue], *, step: int = 0,
        state_version_before: int = 0, state_version_after: int = 0,
    ) -> TraceEvent:
        if self._finalized:
            raise ProtocolViolation("trace_finalized", "final 已写入，禁止再追加事件")
        if event_type not in EventType.ALL:
            raise ProtocolViolation("unknown_event", f"未知事件类型：{event_type}")
        encoded_payload = encode(dict(payload))
        now = self._wall()
        if now.tzinfo is None or now.utcoffset().total_seconds() != 0:
            raise ProtocolViolation("not_utc", "trace 时钟必须返回 UTC 时间")
        elapsed_ms = max(0, int((self._monotonic() - self._started) * 1000))
        event = TraceEvent(
            run_id=self.run_id,
            sequence=len(self._events) + 1,
            timestamp=now,
            elapsed_ms=elapsed_ms,
            step=int(step),
            event_type=event_type,
            state_version_before=int(state_version_before),
            state_version_after=int(state_version_after),
            payload=encoded_payload,
            usage_snapshot=decode(Usage, encode(self._usage_provider())),
        )
        self._events.append(event)
        with self._events_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(encode(event), ensure_ascii=False,
                                    separators=(",", ":")) + "\n")
        return event

    def finalize(self, final: FinalAssessment) -> Path:
        if self._finalized:
            raise ProtocolViolation("trace_finalized", "final 只能写一次")
        self._final = decode(FinalAssessment, encode(final))
        payload = {
            "final": encode(self._final),
            "usage": encode(self._usage_provider()),
            "event_count": len(self._events),
            "finalized_at": self._wall().isoformat(),
        }
        path = self.dir / "final.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        self._finalized = True
        return path


def read_trace(output_dir: Path, run_id: str) -> TraceBundle:
    """离线重放入口：从三件套恢复 manifest / 事件序列 / final，不调模型不调工具。"""
    run_dir = Path(output_dir) / run_id
    manifest = decode(RunManifest, json.loads((run_dir / "manifest.json").read_text(encoding="utf-8")))
    events: list[TraceEvent] = []
    for line in (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(decode(TraceEvent, json.loads(line)))
    final_path = run_dir / "final.json"
    final: FinalAssessment | None = None
    payload: dict | None = None
    if final_path.exists():
        payload = json.loads(final_path.read_text(encoding="utf-8"))
        final = decode(FinalAssessment, payload["final"])
    return TraceBundle(manifest, tuple(events), final, payload)
