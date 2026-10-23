"""Model-assisted competing hypotheses with deterministic reference checks."""

from __future__ import annotations

import json
from dataclasses import replace

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
            if (item.supersedes != item.hypothesis_id
                    or item.hypothesis_id not in previous
                    or item.kind != previous[item.hypothesis_id].kind
                    or item.version <= previous[item.hypothesis_id].version):
                raise ProtocolViolation("invalid_revision", "revised hypotheses must supersede an earlier lower version")
        elif item.supersedes is not None:
            raise ProtocolViolation("dangling_reference", "initial hypotheses cannot supersede unknown state")
    if previous and set(by_id) != set(previous):
        raise ProtocolViolation("invalid_revision", "revisions must preserve the hypothesis set")
    support = {key: [] for key in by_id}
    contradict = {key: [] for key in by_id}
    seen_relations = set()
    directional_stances: dict[tuple[str, str], str] = {}
    for link in links:
        if link.hypothesis_id not in by_id or link.evidence_id not in known:
            raise ProtocolViolation("dangling_reference", "hypothesis link is not grounded")
        if not set(link.related_evidence_ids) <= known:
            raise ProtocolViolation("dangling_reference", "related evidence is not grounded")
        relation = (link.hypothesis_id, link.evidence_id, link.stance)
        if relation in seen_relations:
            raise ProtocolViolation("duplicate_link", "duplicate evidence link")
        seen_relations.add(relation)
        if link.stance in {"support", "contradict"}:
            pair = (link.hypothesis_id, link.evidence_id)
            prior = directional_stances.get(pair)
            if prior is not None and prior != link.stance:
                raise ProtocolViolation("conflicting_link", "evidence cannot both support and contradict one hypothesis")
            directional_stances[pair] = link.stance
        if link.stance == "support":
            support[link.hypothesis_id].append(link.evidence_id)
        elif link.stance == "contradict":
            contradict[link.hypothesis_id].append(link.evidence_id)
    projected = tuple(replace(
        item,
        supporting_evidence=tuple(support[item.hypothesis_id]),
        disconfirming_evidence=tuple(contradict[item.hypothesis_id]),
    ) for item in hypotheses)
    return projected, links


async def propose_hypotheses(*, controller, adapter, run_id, alert, evidence, trace, step,
                             revision, previous_hypotheses=()):
    known = tuple(item.evidence_id for item in evidence)
    previous_for_model = encode(previous_hypotheses)
    for item in previous_for_model:
        # Links are authoritative in v2. Do not invite the model to copy the
        # internal compatibility projections back into its closed output schema.
        item.pop("supporting_evidence", None)
        item.pop("disconfirming_evidence", None)
    context = json.dumps({"alert": encode(alert), "evidence": encode(evidence),
                          "previous_hypotheses": previous_for_model},
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def validator(output):
        validate_hypothesis_output(output, known, previous_hypotheses)

    result = await run_model_call(
        controller, adapter, run_id=run_id,
        phase=f"hypothesis-{revision}",
        messages=(
            {"role": "system", "content": prompt_text("hypothesis-v2.txt")},
            {"role": "user", "content": context},
        ),
        schema_name=HYPOTHESIS_PROPOSAL, max_output_tokens=1000,
        trace=trace, step=step, output_validator=validator,
    )
    return validate_hypothesis_output(result.output, known, previous_hypotheses)
