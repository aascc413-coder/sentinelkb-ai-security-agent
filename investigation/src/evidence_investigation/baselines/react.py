"""ReAct baseline using only the shared public ToolAction | FinishAction union."""

from __future__ import annotations

from pathlib import Path

from evidence_investigation.runtime.budget import BudgetExceeded
from evidence_investigation.runtime.model import ModelError, run_model_call
from evidence_investigation.state.adapters import action_from_output
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    Budget, FinishAction, InvestigationTools, PublicCase, RunManifest, ToolAction,
    ToolCall,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.schema_loader import ACTION
from evidence_investigation.state.validation import validate_final_assessment

from .common import prompt_text, start_run


class ReActBaseline:
    method = "react"

    def __init__(self, adapter, manifest: RunManifest, output_dir: str | Path):
        self.adapter = adapter
        self.manifest = manifest
        self.output_dir = Path(output_dir)

    async def run(
        self, case: PublicCase, tools: InvestigationTools, budget: Budget
    ):
        run = start_run(
            method=self.method, case=case, tools=tools, adapter=self.adapter,
            manifest=self.manifest, budget=budget, output_dir=self.output_dir,
        )
        try:
            while True:
                step = run.begin_step()

                def validate_action(output):
                    action = action_from_output(output)
                    if isinstance(action, FinishAction):
                        validate_final_assessment(
                            action.final, run.available_evidence_ids()
                        )
                    return action

                response = await run_model_call(
                    run.controller,
                    self.adapter,
                    run_id=run.manifest.run_id,
                    phase=f"react_action_{step}",
                    messages=(
                        {"role": "system", "content": prompt_text("react-v1.txt")},
                        {"role": "user", "content": run.model_context()},
                    ),
                    schema_name=ACTION,
                    max_output_tokens=1200,
                    trace=run.trace,
                    step=step,
                    output_validator=validate_action,
                )
                action = action_from_output(response.output)
                run.trace.emit(
                    "plan_selected", {"method": self.method, "action": encode(action)},
                    step=step, state_version_before=run.registry.version,
                    state_version_after=run.registry.version,
                )
                if isinstance(action, FinishAction):
                    return run.finalize(action.final)
                if not isinstance(action, ToolAction):  # pragma: no cover - typed adapter guard
                    raise ProtocolViolation("invalid_action", "unknown public action")
                outcome = await run.dispatcher.dispatch(
                    ToolCall(action.tool, action.arguments), step=step
                )
                if outcome.protocol_error_code:
                    raise ProtocolViolation(
                        outcome.protocol_error_code,
                        outcome.detail or "ReAct tool call violated the public protocol",
                    )
        except (BudgetExceeded, ModelError, ProtocolViolation) as exc:
            return run.finalize_expected_failure(exc)
