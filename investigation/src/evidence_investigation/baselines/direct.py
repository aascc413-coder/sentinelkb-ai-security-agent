"""Direct-LLM baseline: alert context to one final assessment, with no tools."""

from __future__ import annotations

from pathlib import Path

from evidence_investigation.runtime.budget import BudgetExceeded
from evidence_investigation.runtime.model import ModelError
from evidence_investigation.state.contracts import Budget, InvestigationTools, PublicCase, RunManifest
from evidence_investigation.state.errors import ProtocolViolation

from .common import start_run


class DirectBaseline:
    method = "direct"

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
            run.begin_step()
            return run.finalize(await run.request_final(prompt_name="direct-v1.txt"))
        except (BudgetExceeded, ModelError, ProtocolViolation) as exc:
            return run.finalize_expected_failure(exc)
