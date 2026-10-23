"""Model-assisted competing hypotheses with deterministic reference checks."""

from __future__ import annotations

import json

from evidence_investigation.runtime.model import run_model_call
from evidence_investigation.runtime.prompts import prompt_text
from evidence_investigation.state.codec import decode, encode
from evidence_investigation.state.contracts import EvidenceLink, Hypothesis
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.schema_loader import HYPOTHESIS_PROPOSAL


def validate_hypothesis_output(payload, known_evidence_ids, previous_hypotheses=()) -> tuple[tuple[Hypothesis, ...], tuple[EvidenceLink, ...]]:
    hypotheses = tuple(decode(Hypothesis, item) for item in payload["hypotheses"])
    links = tuple(decode(EvidenceLink, item) for item in payload["links"])
    if not 2 <= len(hypotheses) <= 4:
        raise ProtocolViolation("invalid_hypotheses", "two to four competing hypotheses are required")
    ids = [item.hypothesis_id for item in hypotheses]
    if len(set(ids)) != len(ids):
        raise ProtocolViolation("duplicate_id", "hypothesis IDs must be unique")
    kinds = {item.kind for item in hypotheses}
    if not {"malicious", "benign"}.issubset(kinds):
        raise ProtocolViolation("invalid_hypotheses", "a malicious and a benign hypothesis are required")
    known = set(known_evidence_ids)
    by_id = {item.hypothesis_id: item for item in hypotheses}
    previous = {item.hypothesis_id: item for item in previous_hypotheses}
    for item in hypotheses:
        cited = set(item.supporting_evidence) | set(item.disconfirming_evidence)
        if not cited <= known:
            raise ProtocolViolation("dangling_reference", "hypothesis cites unavailable evidence")
        if previous:
            if item.supersedes not in previous or item.version <= previous[item.supersedes].version:
                raise ProtocolViolation("invalid_revision", "revised hypotheses must supersede an earlier lower version")
        elif item.supersedes is not None:
            raise ProtocolViolation("dangling_reference", "initial hypotheses cannot supersede unknown state")
    support = {key: set() for key in by_id}
    contradict = {key: set() for key in by_id}
    for link in links:
        if link.hypothesis_id not in by_id or link.evidence_id not in known:
            raise ProtocolViolation("dangling_reference", "hypothesis link is not grounded")
        if not set(link.related_evidence_ids) <= known:
            raise ProtocolViolation("dangling_reference", "related evidence is not grounded")
        if link.stance == "support":
            support[link.hypothesis_id].add(link.evidence_id)
        elif link.stance == "contradict":
            contradict[link.hypothesis_id].add(link.evidence_id)
    for item in hypotheses:
        if set(item.supporting_evidence) != support[item.hypothesis_id]:
            raise ProtocolViolation("inconsistent_links", "supporting evidence and links differ")
        if set(item.disconfirming_evidence) != contradict[item.hypothesis_id]:
            raise ProtocolViolation("inconsistent_links", "disconfirming evidence and links differ")
    return hypotheses, links


async def propose_hypotheses(*, controller, adapter, run_id, alert, evidence, trace, step,
                             revision, previous_hypotheses=()):
    known = tuple(item.evidence_id for item in evidence)
    context = json.dumps({"alert": encode(alert), "evidence": encode(evidence),
                          "previous_hypotheses": encode(previous_hypotheses)},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def validator(output):
        validate_hypothesis_output(output, known, previous_hypotheses)

    result = await run_model_call(
        controller, adapter, run_id=run_id,
        phase=f"hypothesis-{revision}",
        messages=(
            {"role": "system", "content": prompt_text("hypothesis-v1.txt")},
            {"role": "user", "content": context},
        ),
        schema_name=HYPOTHESIS_PROPOSAL, max_output_tokens=1400,
        trace=trace, step=step, output_validator=validator,
    )
    return validate_hypothesis_output(result.output, known, previous_hypotheses)
