"""M7 Evidence-Aware Proposed investigation loop."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from evidence_investigation.runtime.budget import BudgetController, BudgetExceeded
from evidence_investigation.runtime.dispatcher import Dispatcher
from evidence_investigation.runtime.model import ModelError, run_model_call
from evidence_investigation.runtime.prompts import prompt_sha256, prompt_text
from evidence_investigation.runtime.registry import EvidenceRegistry
from evidence_investigation.runtime.trace import TraceRecorder
from evidence_investigation.state.codec import encode
from evidence_investigation.state.contracts import (
    Budget, EventType, FinalAssessment, InvestigationState, InvestigationTools,
    MissingEvidence, PublicCase, RunManifest,
)
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.public_loader import validate_public
from evidence_investigation.state.rubric import FamilyRubric
from evidence_investigation.state.schema_loader import SUFFICIENCY_EXPLANATION
from evidence_investigation.state.validation import validate_final_assessment

from .hypothesis import propose_hypotheses
from .planner import DeterministicPlanner
from .sufficiency import AcquiredResult, SufficiencyEvaluation, evaluate_sufficiency


def required_prompt_hashes() -> dict[str, str]:
    return {name: prompt_sha256(name) for name in
            ("hypothesis-v2.txt", "sufficiency-v1.txt")}


class EvidenceAwareInvestigator:
    def __init__(self, *, adapter, manifest: RunManifest, output_dir: str | Path,
                 rubric: FamilyRubric, planner: DeterministicPlanner | None = None):
        self.adapter = adapter
        self.manifest = manifest
        self.output_dir = Path(output_dir)
        self.rubric = rubric
        self.planner = planner or DeterministicPlanner()

    async def run(self, case: PublicCase, tools: InvestigationTools,
                  budget: Budget) -> FinalAssessment:
        self._validate_start(case, budget)
        controller = BudgetController(budget)
        registry = EvidenceRegistry(case.alert)
        trace = TraceRecorder(self.manifest.run_id, self.manifest, self.output_dir,
                              usage_provider=controller.snapshot)
        dispatcher = Dispatcher(self.manifest.run_id, case.alert.as_of, registry,
                                controller, tools, trace=trace)
        state = InvestigationState(self.manifest.run_id, case.alert, budget,
                                   status="investigating")
        ledger: list[AcquiredResult] = []
        last_evaluation: SufficiencyEvaluation | None = None
        trace.emit(EventType.ALERT_RECEIVED, {"alert": encode(case.alert)},
                   state_version_before=0, state_version_after=registry.version)
        try:
            hypotheses, links = await propose_hypotheses(
                controller=controller, adapter=self.adapter,
                run_id=self.manifest.run_id, alert=case.alert,
                evidence=registry.facts() + registry.operational_facts(),
                trace=trace, step=0, revision=1,
            )
            state.hypotheses = list(hypotheses)
            state.evidence.links = list(links)
            trace.emit(EventType.HYPOTHESES_CREATED,
                       {"hypotheses": encode(hypotheses), "links": encode(links),
                        "other_hypotheses_possible": True},
                       state_version_before=registry.version,
                       state_version_after=registry.version)

            revision = 1
            while True:
                evaluation = evaluate_sufficiency(
                    case.alert, registry, tuple(ledger), self.rubric)
                last_evaluation = evaluation
                state.latest_sufficiency = evaluation.result
                self._sync_evidence(state, registry, evaluation, tuple(ledger))
                state.usage = controller.snapshot()
                trace.emit(EventType.SUFFICIENCY_CHECKED,
                           {"result": encode(evaluation.result),
                            "risk_flags": list(evaluation.risk_flags)},
                           step=controller.snapshot().steps,
                           state_version_before=registry.version,
                           state_version_after=registry.version)
                trace.emit(EventType.STATE_SNAPSHOT, {"state": encode(state)},
                           step=controller.snapshot().steps,
                           state_version_before=registry.version,
                           state_version_after=registry.version)

                hard_stop = controller.stopped_reason
                if hard_stop is not None:
                    return self._finalize(
                        state, registry, trace,
                        self._assessment(evaluation, hard_stop, hard_stop=True),
                    )
                plan = self.planner.plan(case.alert, tuple(ledger), evaluation,
                                         tuple(state.hypotheses))
                state.latest_plan = plan
                trace.emit(EventType.PLAN_SELECTED, {"plan": encode(plan)},
                           step=controller.snapshot().steps,
                           state_version_before=registry.version,
                           state_version_after=registry.version)
                if plan.action == "finalize":
                    if ledger:
                        revision += 1
                        hypotheses, links = await propose_hypotheses(
                            controller=controller, adapter=self.adapter,
                            run_id=self.manifest.run_id, alert=case.alert,
                            evidence=registry.facts() + registry.operational_facts(),
                            trace=trace, step=controller.snapshot().steps,
                            revision=revision,
                            previous_hypotheses=tuple(state.hypotheses),
                        )
                        state.hypotheses = list(hypotheses)
                        state.evidence.links = list(links)
                        trace.emit(EventType.HYPOTHESES_REVISED,
                                   {"hypotheses": encode(hypotheses),
                                    "links": encode(links),
                                    "other_hypotheses_possible": True,
                                    "reason": "final_evidence_consolidation"},
                                   step=controller.snapshot().steps,
                                   state_version_before=registry.version,
                                   state_version_after=registry.version)
                        state.usage = controller.snapshot()
                        trace.emit(EventType.STATE_SNAPSHOT, {"state": encode(state)},
                                   step=controller.snapshot().steps,
                                   state_version_before=registry.version,
                                   state_version_after=registry.version)
                    await self._explain_sufficiency(controller, trace, evaluation,
                                                    controller.snapshot().steps)
                    unavailable = any(item.result.status in {"unavailable", "timeout", "error"}
                                      for item in ledger)
                    stop = "sufficient" if evaluation.result.sufficient_for else \
                        "no_available_tool" if unavailable else "no_useful_action"
                    return self._finalize(
                        state, registry, trace, self._assessment(evaluation, stop),
                    )

                step = controller.begin_step()
                selected = next(item for item in plan.candidates
                                if item.action_id == plan.selected_action_id)
                outcome = await dispatcher.dispatch(selected.call, step=step)
                if outcome.protocol_error_code:
                    raise ProtocolViolation(outcome.protocol_error_code, outcome.detail)
                if outcome.result is not None and not outcome.late:
                    ledger.append(AcquiredResult(
                        selected.call, outcome.result, outcome.evidence_ids,
                        outcome.operational_ids,
                    ))
                    state.completed_call_ids.append(outcome.call_id)
                if controller.stopped_reason is not None:
                    # The last admitted tool closes model admission. Re-evaluate in
                    # the next iteration and finalize deterministically.
                    continue
        except (BudgetExceeded, ProtocolViolation, ModelError) as exc:
            if isinstance(exc, BudgetExceeded):
                reason = exc.reason
            elif isinstance(exc, ProtocolViolation):
                reason = "protocol_error"
            else:
                reason = "model_error"
            trace.emit(EventType.ERROR, {"detail": str(exc), "stop_reason": reason},
                       step=controller.snapshot().steps,
                       state_version_before=registry.version,
                       state_version_after=registry.version)
            if last_evaluation is not None:
                assessed = self._assessment(last_evaluation, reason, hard_stop=True)
                final = replace(
                    assessed,
                    risk_flags=tuple(dict.fromkeys(
                        assessed.risk_flags + ("incomplete_investigation",))),
                    abstain_reason=str(exc), confidence_status="unavailable",
                )
            else:
                final = FinalAssessment(
                    "Abstain", "human_review", reason,
                    final_evidence_ids=(),
                    unresolved_questions=("The evidence-aware investigation did not complete safely.",),
                    risk_flags=("incomplete_investigation",), abstain_reason=str(exc),
                    confidence_status="unavailable",
                )
            return self._finalize(state, registry, trace, final)

    def _validate_start(self, case, budget):
        validate_public(case)
        if self.manifest.method != "proposed":
            raise ProtocolViolation("method_mismatch", "Proposed runner requires method=proposed")
        if encode(self.manifest.budget) != encode(budget):
            raise ProtocolViolation("budget_mismatch", "manifest and runner budgets differ")
        if self.manifest.prompt_hashes != required_prompt_hashes():
            raise ProtocolViolation("prompt_hash_mismatch", "manifest does not bind both Proposed prompts")
        if self.manifest.rubric_version != self.rubric.rubric_version:
            raise ProtocolViolation("rubric_mismatch", "manifest and loaded rubric differ")

    @staticmethod
    def _sync_evidence(state, registry, evaluation, ledger):
        all_facts = registry.facts() + registry.operational_facts()
        state.evidence.facts = {item.evidence_id: item for item in all_facts}
        state.evidence.version = registry.version
        candidate_tools = {
            "current_process_behavior": ("siem",),
            "current_network_effects": ("siem",),
            "approval_coverage": ("asset", "history"),
            "approval_history": ("history",),
        }
        hypothesis_ids = tuple(item.hypothesis_id for item in state.hypotheses)
        def gap_status(gap):
            relevant = [item for item in ledger if (
                gap == "current_process_behavior" and item.result.tool == "siem"
                and getattr(item.call.arguments, "view", None) == "process_tree"
                or gap == "current_network_effects" and item.result.tool == "siem"
                and getattr(item.call.arguments, "view", None) == "network_events"
                or gap == "approval_coverage" and item.result.tool in {"asset", "history"}
                or gap == "approval_history" and item.result.tool == "history"
            )]
            if not relevant:
                return "unqueried"
            if gap == "approval_coverage":
                for item in relevant:
                    complete = (item.result.status in {"ok", "empty"}
                                and item.result.coverage.completeness == "complete"
                                and not item.result.coverage.truncated
                                and not item.result.coverage.missing_sources)
                    has_approval_scope = (item.result.tool == "asset" or any(
                        record.payload.get("approval_register_complete") is True
                        and isinstance(record.payload.get("register_window"), dict)
                        for record in item.result.records))
                    if complete and has_approval_scope:
                        return "resolved"
                if relevant[-1].result.status in {"unavailable", "timeout", "error"}:
                    return "unavailable"
                return "partial"
            latest = relevant[-1].result
            if latest.status in {"unavailable", "timeout", "error"}:
                return "unavailable"
            if (latest.status in {"ok", "empty"}
                    and latest.coverage.completeness == "complete"
                    and not latest.coverage.truncated and not latest.coverage.missing_sources):
                return "resolved"
            return "partial"
        state.evidence.missing = [
            MissingEvidence(gap, gap.replace("_", " "), hypothesis_ids, "both",
                            gap_status(gap), candidate_tools.get(gap, ()))
            for gap in evaluation.result.missing_gap_ids
        ]

    async def _explain_sufficiency(self, controller, trace, evaluation, step):
        checks = evaluation.result.tp_checks + tuple(
            item for item in evaluation.result.fp_checks
            if item.criterion_id not in {x.criterion_id for x in evaluation.result.tp_checks})
        by_id = {item.criterion_id: item for item in checks}

        def validator(output):
            if output["rubric_version"] != evaluation.result.rubric_version:
                raise ProtocolViolation("rubric_mismatch", "model changed rubric version")
            criteria = output["criteria"]
            if len(criteria) != len(by_id) or {x["criterion_id"] for x in criteria} != set(by_id):
                raise ProtocolViolation("criterion_mismatch", "every deterministic criterion is required once")
            for item in criteria:
                expected = by_id[item["criterion_id"]]
                if item["outcome"] != expected.outcome or set(item["evidence_ids"]) != set(expected.evidence_ids):
                    raise ProtocolViolation("criterion_mismatch", "model changed program outcome or evidence")

        context = json.dumps({"program_result": encode(evaluation.result)},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        await run_model_call(
            controller, self.adapter, run_id=self.manifest.run_id, phase="final",
            messages=(
                {"role": "system", "content": prompt_text("sufficiency-v1.txt")},
                {"role": "user", "content": context},
            ), schema_name=SUFFICIENCY_EXPLANATION, max_output_tokens=900,
            trace=trace, step=step, output_validator=validator,
        )

    @staticmethod
    def _assessment(evaluation: SufficiencyEvaluation, stop_reason, *, hard_stop=False):
        verdict = (evaluation.result.sufficient_for
                   if not hard_stop or stop_reason == "tool_budget" else None)
        if verdict is None and not hard_stop and evaluation.risk_flags \
                and stop_reason in {"no_useful_action", "no_available_tool"}:
            verdict = "Suspicious"
        if verdict is None:
            verdict = "Abstain"
        disposition = "escalate" if verdict == "TP" else \
            "close_recommended" if verdict == "FP" else "human_review"
        ids = evaluation.result.discriminating_evidence_ids or evaluation.risk_evidence_ids
        questions = evaluation.result.unresolved_alternatives
        abstain = None if verdict != "Abstain" else \
            f"No safe definitive conclusion was available at stop: {stop_reason}."
        return FinalAssessment(
            verdict, disposition, stop_reason,
            final_evidence_ids=ids, unresolved_questions=questions,
            risk_flags=evaluation.risk_flags, abstain_reason=abstain,
            confidence_status="uncalibrated" if verdict != "Abstain" else "unavailable",
        )

    @staticmethod
    def _finalize(state, registry, trace, final):
        available = tuple(item.evidence_id for item in
                          registry.facts() + registry.operational_facts())
        final = validate_final_assessment(final, available)
        state.status = "finalized"
        state.final = final
        trace.emit(EventType.FINALIZED, {"final": encode(final)},
                   step=trace.events[-1].step if trace.events else 0,
                   state_version_before=registry.version,
                   state_version_after=registry.version)
        trace.finalize(final)
        return final
