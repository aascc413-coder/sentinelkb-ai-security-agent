"""Shared M6 baseline runtime: one registry, budget, dispatcher and trace format.

This module deliberately exposes only public alert/evidence/action structures to
baseline prompts.  Hypotheses, evidence gaps, sufficiency criteria and planner
scores are Proposed-method state and do not enter this comparison interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from importlib import resources
from pathlib import Path

from evidence_investigation.runtime.budget import BudgetController, BudgetExceeded
from evidence_investigation.runtime.dispatcher import Dispatcher
from evidence_investigation.runtime.model import ModelError, run_model_call
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.runtime.trace import TraceRecorder
from evidence_investigation.state.adapters import final_assessment_from_output
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    Budget, FinalAssessment, InvestigationTools, PublicCase, RunManifest,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.schema_loader import FINAL_ASSESSMENT
from evidence_investigation.state.validation import (
    validate_alert, validate_final_assessment,
)


PROMPT_BY_METHOD = {
    "direct": "direct-v1.txt",
    "fixed": "fixed-final-v1.txt",
    "fixed_all": "fixed-final-v1.txt",
    "react": "react-v1.txt",
}


def _prompt_bytes(name: str) -> bytes:
    try:
        return resources.files("evidence_investigation.prompts").joinpath(name).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError) as exc:
        raise ProtocolViolation("missing_prompt", f"missing versioned prompt {name}") from exc


def prompt_text(name: str) -> str:
    try:
        return _prompt_bytes(name).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolViolation("invalid_prompt", f"prompt {name} is not UTF-8") from exc


def prompt_sha256(name: str) -> str:
    return sha256(_prompt_bytes(name)).hexdigest()


def required_prompt_hashes(method: str) -> dict[str, str]:
    try:
        name = PROMPT_BY_METHOD[method]
    except KeyError as exc:
        raise ProtocolViolation("unknown_method", f"unsupported baseline method {method}") from exc
    return {name: prompt_sha256(name)}


@dataclass
class BaselineRun:
    """Objects owned by one run; callers must never reuse this container."""

    method: str
    case: PublicCase
    adapter: object
    manifest: RunManifest
    controller: BudgetController
    registry: EvidenceRegistry
    trace: TraceRecorder
    dispatcher: Dispatcher

    @property
    def step(self) -> int:
        return self.controller.snapshot().steps

    def begin_step(self) -> int:
        return self.controller.begin_step()

    def available_evidence_ids(self) -> tuple[str, ...]:
        return tuple(
            item.evidence_id
            for item in self.registry.facts() + self.registry.operational_facts()
        )

    def model_context(self) -> str:
        """A stable public projection.  It contains no oracle or Proposed state."""
        payload = {
            "alert": encode(self.case.alert),
            "evidence": encode(self.registry.facts()),
            "operational_evidence": encode(self.registry.operational_facts()),
            "budget_usage": encode(self.controller.snapshot()),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def validate_final_output(self, output) -> FinalAssessment:
        final = final_assessment_from_output(output)
        return validate_final_assessment(final, self.available_evidence_ids())

    async def request_final(self, *, prompt_name: str, phase: str = "final") -> FinalAssessment:
        result = await run_model_call(
            self.controller,
            self.adapter,
            run_id=self.manifest.run_id,
            phase=phase,
            messages=(
                {"role": "system", "content": prompt_text(prompt_name)},
                {"role": "user", "content": self.model_context()},
            ),
            schema_name=FINAL_ASSESSMENT,
            max_output_tokens=1200,
            trace=self.trace,
            step=self.step,
            output_validator=self.validate_final_output,
        )
        return self.validate_final_output(result.output)

    def finalize(self, final: FinalAssessment) -> FinalAssessment:
        final = validate_final_assessment(final, self.available_evidence_ids())
        self.trace.emit(
            "finalized", {"final": encode(final)}, step=self.step,
            state_version_before=self.registry.version,
            state_version_after=self.registry.version,
        )
        self.trace.finalize(final)
        return final

    def finalize_expected_failure(self, exc: BaseException) -> FinalAssessment:
        """Turn an admitted runtime failure into an explicit, replayable refusal."""
        if isinstance(exc, BudgetExceeded):
            reason = exc.reason
        elif isinstance(exc, ProtocolViolation):
            reason = "protocol_error"
        elif isinstance(exc, ModelError):
            reason = "model_error"
        else:  # pragma: no cover - call sites restrict this helper to expected failures
            raise exc
        final = FinalAssessment(
            verdict="Abstain",
            disposition="human_review",
            stop_reason=reason,
            unresolved_questions=("The investigation could not complete within the admitted runtime.",),
            risk_flags=("incomplete_investigation",),
            abstain_reason=str(exc),
            confidence_status="unavailable",
        )
        return self.finalize(final)


def start_run(
    *, method: str, case: PublicCase, tools: InvestigationTools, adapter,
    manifest: RunManifest, budget: Budget, output_dir: str | Path,
) -> BaselineRun:
    """Validate immutable run inputs before writing the first trace event."""
    if manifest.method != method:
        raise ProtocolViolation(
            "method_mismatch", f"manifest method {manifest.method!r} != runner {method!r}"
        )
    if encode(manifest.budget) != encode(budget):
        raise ProtocolViolation("budget_mismatch", "manifest and runner budgets differ")
    expected = required_prompt_hashes(method)
    if manifest.prompt_hashes != expected:
        raise ProtocolViolation(
            "prompt_hash_mismatch", "manifest does not bind the exact method prompt"
        )
    validate_alert(case.alert)
    controller = BudgetController(budget)
    registry = EvidenceRegistry(case.alert)
    trace = TraceRecorder(
        manifest.run_id, manifest, Path(output_dir), usage_provider=controller.snapshot
    )
    dispatcher = Dispatcher(
        manifest.run_id, case.alert.as_of, registry, controller, tools, trace=trace
    )
    trace.emit(
        "alert_received", {"alert": encode(case.alert)}, step=0,
        state_version_before=0, state_version_after=registry.version,
    )
    return BaselineRun(
        method, case, adapter, manifest, controller, registry, trace, dispatcher
    )
