"""Frozen deterministic workflows used as M6 fixed and fixed-all controls."""

from __future__ import annotations

from datetime import timedelta
import ipaddress
import re
from pathlib import Path
from typing import Literal

from evidence_investigation.runtime.budget import BudgetExceeded
from evidence_investigation.runtime.model import ModelError
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    AssetQuery, AttackQuery, Budget, HistoryQuery, InvestigationTools, PublicCase,
    RunManifest, SIEMQuery, TIQuery, TimeWindow, ToolCall,
)
from evidence_investigation.state.errors import ProtocolViolation

from .common import start_run


ATTACK_SNAPSHOT = "attack-local-v1"
FIXED_ORDER = ("siem", "threat_intel", "attack")
FIXED_ALL_ORDER = ("siem", "threat_intel", "asset", "history", "attack")
_HEX = re.compile(r"[0-9a-fA-F]+\Z")


def _indicator_type(value: str) -> Literal["ip", "domain", "hash"]:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if len(value) in {32, 40, 64, 128} and _HEX.fullmatch(value):
        return "hash"
    return "domain"


class FixedWorkflowBaseline:
    """A fixed tool-type sequence; model output cannot alter the sequence."""

    def __init__(
        self, adapter, manifest: RunManifest, output_dir: str | Path, *,
        include_all_tools: bool = False,
    ):
        self.adapter = adapter
        self.manifest = manifest
        self.output_dir = Path(output_dir)
        self.include_all_tools = include_all_tools
        self.method = "fixed_all" if include_all_tools else "fixed"

    async def run(
        self, case: PublicCase, tools: InvestigationTools, budget: Budget
    ):
        run = start_run(
            method=self.method, case=case, tools=tools, adapter=self.adapter,
            manifest=self.manifest, budget=budget, output_dir=self.output_dir,
        )
        try:
            for stage in FIXED_ALL_ORDER if self.include_all_tools else FIXED_ORDER:
                step = run.begin_step()
                call, reason = self._call_for(stage, run)
                if call is None:
                    run.trace.emit(
                        "plan_selected",
                        {"method": self.method, "stage": stage, "decision": "stage_skipped",
                         "reason": reason},
                        step=step, state_version_before=run.registry.version,
                        state_version_after=run.registry.version,
                    )
                    continue
                run.trace.emit(
                    "plan_selected",
                    {"method": self.method, "stage": stage, "decision": "tool",
                     "call": encode(call)},
                    step=step, state_version_before=run.registry.version,
                    state_version_after=run.registry.version,
                )
                outcome = await run.dispatcher.dispatch(call, step=step)
                if outcome.protocol_error_code:
                    raise ProtocolViolation(
                        outcome.protocol_error_code,
                        outcome.detail or f"{stage} tool call violated the public protocol",
                    )
            run.begin_step()
            return run.finalize(await run.request_final(prompt_name="fixed-final-v1.txt"))
        except (BudgetExceeded, ModelError, ProtocolViolation) as exc:
            return run.finalize_expected_failure(exc)

    @staticmethod
    def _call_for(stage: str, run):
        alert = run.case.alert
        if stage == "siem":
            if not alert.host:
                return None, "alert has no host"
            window = TimeWindow(alert.as_of - timedelta(minutes=15), alert.as_of)
            # One frozen SIEM call preserves a final-model slot under the six-call budget.
            return ToolCall("siem", SIEMQuery(
                "network_events", window, host=alert.host, limit=50
            )), None
        if stage == "threat_intel":
            indicators = sorted(run.registry.known_entities()["indicators"])
            if not indicators:
                return None, "no alert-or-tool-derived indicator"
            value = indicators[0]
            return ToolCall(
                "threat_intel", TIQuery(_indicator_type(value), value, alert.as_of)
            ), None
        if stage == "asset":
            if not alert.host:
                return None, "alert has no host"
            return ToolCall("asset", AssetQuery(alert.host, alert.as_of)), None
        if stage == "history":
            window = TimeWindow(alert.as_of - timedelta(days=1), alert.as_of)
            if alert.user:
                query = HistoryQuery(
                    "user", alert.user, window, host=alert.host, user=alert.user, limit=50
                )
            elif alert.host:
                query = HistoryQuery("host", alert.host, window, host=alert.host, limit=50)
            else:
                return None, "alert has neither user nor host"
            return ToolCall("history", query), None
        if stage == "attack":
            return ToolCall("attack", AttackQuery(
                ATTACK_SNAPSHOT, behavior_terms=(alert.alert_type,)
            )), None
        raise AssertionError(f"unfrozen stage {stage}")
