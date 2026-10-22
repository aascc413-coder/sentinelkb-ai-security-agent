"""Independent fixture scoring, not an agent or a runtime sufficiency checker.

Supported atomic claim protocol: kind='observation', subject equals the cited
record's host/entity/value (or source tool), predicate is an RFC6901 JSON Pointer
such as '/parent_process', and value equals the pointed JSON value with strict
types. Free text is never interpreted as a fact. Inferences are reported
separately, not counted as grounded atomic observations.

Oracle observation dictionaries use frozen query-projection rules then structural subsets; arrays are exact.
ID mapping accepts raw fixture IDs or opaque record IDs in explicit namespace (default runtime-v1). An
opaque record ID alone never establishes semantic agreement. This mechanical
protocol is for frozen structured fixtures; free-text claims require a separately
versioned blind-review rubric. Unknown discriminating/budget annotations stay NA.
"""

from __future__ import annotations

from collections import defaultdict

from evidence_investigation.state.adapters import final_assessment_from_output
from evidence_investigation.state.codec import encode
from evidence_investigation.state.content import content_hash, opaque_id
from evidence_investigation.state.errors import ProtocolViolation

from .contracts import CaseEvaluationAnnotation, CaseScore, MetricCount, OracleCase
from .replay import ReplayFact, ReplayResult


def _count(numerator, denominator):
    return MetricCount(numerator, denominator, numerator / denominator if denominator else None)


def _equal(a, b):
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return set(a) == set(b) and all(_equal(value, b[key]) for key, value in a.items())
    if isinstance(a, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    return a == b


def _subset(expected, actual):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and _subset(v, actual[k])
                                                for k, v in expected.items())
    return _equal(expected, actual)


def _source(fact):
    parts = fact.fact_key.split(':')
    return parts[1] if parts[0] in {'source', 'absence'} else parts[0]


def _source_matches(fact, annotation):
    expected = annotation.get('source')
    return _source(fact) in annotation.get('source_tools', [expected])


def _record_ids(annotation, namespace):
    ids = set(annotation.get('record_ids', []))
    return ids | {opaque_id('record', rid, namespace) for rid in ids}


def _observation_matches(fact, annotation):
    expected = dict(annotation['observation'])
    actual = dict(fact.value)
    source = _source(fact)
    # Frozen query projections are not new business events. Opaque record IDs
    # still have to match before these narrow projection rules are applied.
    if source == 'siem' and 'view' in expected:
        if actual.get('view') not in {'process_tree', 'network_events', 'host_events', 'user_events'}:
            return False
        expected.pop('view')
    if source == 'history' and annotation.get('source') == 'tool' and 'approved_jobs' in expected:
        # Canonical approval fact shared by asset/history; history does not claim
        # asset purpose/department. Require every approval-defining field.
        return (actual.get('host') == expected.get('host')
                and _equal(actual.get('approved_jobs'), expected.get('approved_jobs'))
                and _equal(actual.get('approval_register_complete'), expected.get('approval_register_complete'))
                and _equal(actual.get('register_window'), expected.get('approval_register_window'))
                and actual.get('observed_at') == expected.get('published_at'))
    if source == 'history' and 'entity_type' in expected:
        entity_type = actual.get('entity_type')
        if entity_type not in {'host', 'user'} or actual.get('entity') != actual.get(entity_type):
            return False
        expected.pop('entity_type', None)
        expected.pop('entity', None)
    return _subset(expected, actual)


def matched_fact_keys(fact: ReplayFact, oracle: OracleCase, *, namespace: str = "runtime-v1") -> set[str]:
    """Map a previously provenance-validated ReplayFact to observable oracle keys.

    E0's prose annotation denotes detector presence only, not malicious behavior.
    Operational annotations match tool, status and reason rather than fake IDs.
    """
    matched = set()
    for key in oracle.observable_fact_keys:
        annotation = oracle.complete_world_evidence[key]
        if not isinstance(annotation, dict) or not _source_matches(fact, annotation):
            continue
        if 'operational_status' in annotation:
            if (fact.fact_key.startswith('source:')
                    and fact.value.get('status') == annotation['operational_status']
                    and fact.value.get('error_code') == annotation.get('reason')):
                matched.add(key)
            continue
        if not set(fact.record_ids) & _record_ids(annotation, namespace):
            continue
        observation = annotation.get('observation')
        if isinstance(observation, dict) and _observation_matches(fact, annotation):
            matched.add(key)
        elif _source(fact) == 'alert' and isinstance(observation, str):
            matched.add(key)  # Frozen E0 is detector presence, not prose entailment.
    return matched


def _provenance_valid(fact, replay):
    if fact.fact_key.startswith('alert:'):
        alert = replay.alert
        payload = {'alert_id': alert.alert_id, 'alert_type': alert.alert_type,
                   'host': alert.host, 'user': alert.user, 'process_id': alert.process_id,
                   'command_line': alert.command_line, 'occurred_at': alert.occurred_at.isoformat(),
                   'raw': alert.raw}
        return (fact.fact_key == 'alert:' + content_hash(payload) and _equal(fact.value, payload)
                and fact.record_ids == [alert.raw_reference.record_id] and not fact.call_ids)
    for result in replay.tool_results:
        if result.call_id not in fact.call_ids or result.snapshot_version != replay.manifest.tool_snapshot:
            continue
        if fact.fact_key.startswith(('source:', 'absence:')):
            envelope = {'tool': result.tool, 'status': result.status, 'error_code': result.error_code,
                        'retryable': result.retryable, 'coverage': encode(result.coverage),
                        'snapshot_version': result.snapshot_version}
            if result.status == 'empty':
                expected_key = f'absence:{result.tool}:{content_hash(envelope)}'
                expected = {**envelope, 'absence_provable': result.coverage.completeness == 'complete'
                            and not result.coverage.truncated and not result.coverage.missing_sources}
            elif result.status == 'partial':
                expected_key = f'source:{result.tool}:partial:{content_hash(envelope)}'
                expected = envelope
            elif result.status in {'unavailable', 'timeout', 'error'}:
                expected_key = f'source:{result.tool}:{content_hash(envelope)}'
                expected = envelope
            else:
                continue
            if (fact.fact_key == expected_key and _equal(fact.value, expected)
                    and f'call:{result.call_id}' in fact.record_ids):
                return True
        for record in result.records:
            if (record.record_id in fact.record_ids and fact.fact_key == f'{result.tool}:{content_hash(record.payload)}'
                    and record.content_sha256 == content_hash(record.payload)
                    and _equal(fact.value, record.payload)
                    and record.independence_group in fact.independence_groups):
                return True
    return False


def _pointer(value, pointer):
    if not isinstance(pointer, str) or not pointer.startswith('/'):
        raise ValueError('predicate must be an RFC6901 JSON Pointer')
    for token in pointer[1:].split('/'):
        # Reject malformed escapes rather than silently interpreting them.
        for index, char in enumerate(token):
            if char == '~' and (index + 1 == len(token) or token[index + 1] not in '01'):
                raise ValueError('invalid JSON Pointer escape')
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(value, list):
            if not token.isascii() or not token.isdigit() or (len(token) > 1 and token.startswith('0')):
                raise ValueError('invalid array index')
            value = value[int(token)]
        else:
            value = value[token]
    return value


def _claim_grounded(claim, facts, valid_ids):
    if not claim.evidence_ids or any(eid not in valid_ids for eid in claim.evidence_ids):
        return False
    for eid in claim.evidence_ids:
        fact = facts[eid]
        subject = next((fact.value[k] for k in ('host', 'entity', 'value', 'snapshot_version')
                        if isinstance(fact.value.get(k), str) and fact.value[k]), _source(fact))
        try:
            if claim.subject == subject and _equal(_pointer(fact.value, claim.predicate), claim.value):
                return True
        except (KeyError, TypeError, ValueError, IndexError):
            continue
    return False


def _assessment_error(raw, facts, valid_ids):
    try:
        final = final_assessment_from_output(raw)
    except (ProtocolViolation, TypeError, ValueError):
        return True
    return (any(eid not in valid_ids for eid in final.final_evidence_ids)
            or any(eid not in valid_ids for claim in final.claims for eid in claim.evidence_ids)
            or any(not _claim_grounded(claim, facts, valid_ids)
                   for claim in final.claims if claim.kind == 'observation'))


def score_run(replay: ReplayResult, oracle: OracleCase, *, namespace: str = "runtime-v1",
              annotation: CaseEvaluationAnnotation | None = None) -> CaseScore:
    """Score one replay against independent annotations; no hidden data reaches agent.

    Sufficient means at least one frozen alternative set was acquired AND cited,
    without an acquired same-record observation contradicting its annotation or
    an opposite sufficient set. Missing annotation categories are NA with notes.
    A valid but unsafe final FP remains a valid run and counts as false closure.
    """
    if replay.manifest.rubric_version != oracle.rubric_version:
        raise ProtocolViolation('rubric_mismatch', 'trace and oracle rubric versions differ')
    if annotation is not None and annotation.case_id != oracle.case_id:
        raise ProtocolViolation('annotation_case_mismatch', 'evaluation annotation belongs to another case')
    facts = replay.facts
    valid_ids = {eid for eid, fact in facts.items()
                 if eid == fact.evidence_id and _provenance_valid(fact, replay)}
    mapped = {eid: matched_fact_keys(facts[eid], oracle, namespace=namespace) for eid in valid_ids}
    acquired = set().union(*mapped.values()) if mapped else set()
    final = replay.final
    final_ids = set(final.final_evidence_ids)
    cited = set().union(*(mapped.get(eid, set()) for eid in final_ids)) if final_ids else set()
    conflicts = set()
    for eid in valid_ids:
        fact = facts[eid]
        for key in oracle.observable_fact_keys:
            oracle_annotation = oracle.complete_world_evidence[key]
            if (isinstance(oracle_annotation, dict) and _source_matches(fact, oracle_annotation)
                    and set(fact.record_ids) & _record_ids(oracle_annotation, namespace)
                    and isinstance(oracle_annotation.get('observation'), dict)
                    and not _observation_matches(fact, oracle_annotation)):
                conflicts.add(key)
    determinate = final.verdict in {'TP', 'FP'}
    sufficient = None
    if determinate:
        alternatives = oracle.sufficient_sets.get(final.verdict, ())
        opposite = 'FP' if final.verdict == 'TP' else 'TP'
        opposite_complete = any(set(combination) <= acquired for combination in oracle.sufficient_sets.get(opposite, ()))
        sufficient = (bool(alternatives) and any(set(combination) <= cited for combination in alternatives)
                      and not conflicts and not opposite_complete and final_ids <= valid_ids)
    observations = [claim for claim in final.claims if claim.kind == 'observation']
    references = list(final.final_evidence_ids) + [eid for claim in final.claims for eid in claim.evidence_ids]
    relevant = set(oracle.observable_fact_keys) - set(oracle.distractor_fact_keys)
    available_critical = set(oracle.critical_fact_keys) & set(oracle.observable_fact_keys)
    metrics = {
        'provenance_validity': _count(sum(eid in valid_ids for eid in references), len(references)),
        'evidence_grounding_rate': _count(sum(_claim_grounded(c, facts, valid_ids) for c in observations), len(observations)),
        'evidence_precision': _count(sum(bool(mapped.get(eid, set()) & relevant) for eid in final_ids), len(final_ids)),
        'critical_evidence_recall': _count(len(acquired & available_critical), len(available_critical)),
        'unobservable_critical_fraction': _count(len(set(oracle.critical_fact_keys)-available_critical), len(oracle.critical_fact_keys)),
        'sufficiency_pass_rate': _count(int(bool(sufficient)), int(determinate)),
        'discriminating_evidence_recall': _count(
            len(acquired & set(annotation.discriminating_fact_keys)) if annotation else 0,
            len(annotation.discriminating_fact_keys) if annotation else 0),
        'required_abstention_recall': _count(
            int(final.verdict == 'Abstain') if annotation and annotation.required_abstention else 0,
            int(annotation.required_abstention) if annotation else 0),
        'avoidable_abstention_rate': _count(
            int(final.verdict == 'Abstain') if annotation and annotation.avoidable_abstention else 0,
            int(annotation.avoidable_abstention) if annotation else 0),
        'required_human_review_recall': _count(
            int(final.verdict in {'Suspicious', 'Abstain'})
            if annotation and annotation.required_human_review else 0,
            int(annotation.required_human_review) if annotation else 0),
        'suspicious_citable_risk_proportion': _count(
            int(bool(cited & set(annotation.risk_clue_fact_keys)))
            if annotation and final.verdict == 'Suspicious' else 0,
            int(final.verdict == 'Suspicious')
            if annotation else 0),
        'risk_clue_annotation_coverage': _count(
            int(annotation is not None), 1),
        'final_evidence_error_rate': _count(int(_assessment_error(encode(final), facts, valid_ids)), 1),
    }
    by_call = defaultdict(list)
    for revision in replay.model_output_revisions:
        raw = revision.get('raw_output')
        if revision.get('phase') == 'final' or isinstance(raw, dict) and 'verdict' in raw:
            by_call[revision['call_id']].append(revision)
    scoped = [revisions for revisions in by_call.values()
              if 'available_evidence_ids' in revisions[0]]
    raw_errors = sum(_assessment_error(revisions[0].get('raw_output'), facts,
                                      valid_ids & set(revisions[0]['available_evidence_ids']))
                     for revisions in scoped)
    accepted = [(revisions[-1]['accepted_output'], valid_ids & set(revisions[-1]['available_evidence_ids']))
                for revisions in by_call.values()
                if revisions[-1].get('accepted_output') is not None
                and 'available_evidence_ids' in revisions[-1]]
    metrics['model_proposal_error_rate'] = _count(raw_errors, len(scoped))
    metrics['model_proposal_scoring_coverage'] = _count(len(scoped), len(by_call))
    metrics['model_accepted_error_rate'] = _count(sum(_assessment_error(raw, facts, ids) for raw, ids in accepted), len(accepted))
    enough_now = any(set(combination) <= acquired for combinations in oracle.sufficient_sets.values() for combination in combinations)
    metrics['appropriate_abstention_precision'] = _count(int(final.verdict == 'Abstain' and (not enough_now or bool(conflicts))), int(final.verdict == 'Abstain'))
    notes = [
        'Atomic grounding supports observation claims with JSON Pointer predicates; inference text is not independently scored.',
        'Evidence relevance uses observable non-distractor annotations; no free-text relevance judge is used.',
        ('Discriminating/risk/budget annotations are frozen and applied.' if annotation else
         'Discriminating/risk/budget annotations are absent or budget-inapplicable: NA.'),
        'Proposal scoring requires replay-derived available_evidence_ids at that event; missing temporal scope is excluded and coverage reported.',
        f'acquired_oracle_keys={sorted(acquired)}; cited_oracle_keys={sorted(cited)}; conflicts={sorted(conflicts)}',
        f'inference_claims_unscored={sum(c.kind == "inference" for c in final.claims)}',
    ]
    return CaseScore(replay.manifest.run_id, oracle.case_id, 'valid', oracle.ground_truth,
                     final.verdict, oracle.ground_truth == 'malicious' and final.verdict == 'FP',
                     sufficient, metrics, replay.usage, tuple(notes))
