"""Independent fixture scoring: record identity alone is not semantic evidence."""

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from evaluation.evaluator import matched_fact_keys, score_run
from evaluation.oracle_loader import load_oracle
from evaluation.replay import ReplayFact, ReplayResult
from evidence_investigation.state.codec import encode
from evidence_investigation.state.content import content_hash
from evidence_investigation.state.contracts import Claim, Coverage, FinalAssessment, ToolResult, Usage
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.tools.fixture_loader import load_environment
from test_trace import make_manifest

ROOT = Path(__file__).resolve().parents[1] / 'datasets'


def sample(case=1, verdict=None, remap_ids=False):
    oracle = load_oracle(ROOT / 'oracle' / f'c{case}.json')
    alert = load_public(ROOT / 'public' / f'c{case}.json', remap_ids=remap_ids).alert
    world = load_environment(ROOT / 'environment' / (f'world-{case}.json' if case < 4 else 'shared-pair.json'), remap_ids=remap_ids)
    payload = {'alert_id': alert.alert_id, 'alert_type': alert.alert_type, 'host': alert.host,
               'user': alert.user, 'process_id': alert.process_id, 'command_line': alert.command_line,
               'occurred_at': alert.occurred_at.isoformat(), 'raw': alert.raw}
    facts = {'ev-0001': ReplayFact('ev-0001', 'alert:' + content_hash(payload), payload,
                                 [alert.raw_reference.record_id], [], ['alert'])}
    by_key = {}
    results = []
    for tool, records in world.records_by_tool.items():
        call_id = f'call-{tool}'
        results.append(ToolResult(call_id, tool, 'ok', records, Coverage({}, None, 'complete', False, ()),
                                  world.fixture_version, None, False, 0, 0, 0))
        for record in records:
            key = f'{tool}:{content_hash(record.payload)}'
            if key not in by_key:
                eid = f'ev-{len(facts)+1:04d}'
                facts[eid] = ReplayFact(eid, key, deepcopy(record.payload), [], [], [])
                by_key[key] = eid
            fact = facts[by_key[key]]
            fact.record_ids.append(record.record_id)
            if call_id not in fact.call_ids:
                fact.call_ids.append(call_id)
            if record.independence_group not in fact.independence_groups:
                fact.independence_groups.append(record.independence_group)
    selected_verdict = verdict or ('TP' if case == 1 else 'FP' if case == 2 else 'Suspicious' if case == 3 else 'Abstain')
    final = FinalAssessment(selected_verdict, 'human_review' if selected_verdict in {'Abstain','Suspicious'} else 'escalate' if selected_verdict == 'TP' else 'close_recommended',
                            'sufficient' if selected_verdict in {'TP','FP'} else 'no_useful_action', final_evidence_ids=tuple(facts))
    manifest = replace(make_manifest(), rubric_version=oracle.rubric_version, tool_snapshot=world.fixture_version)
    replay = ReplayResult(manifest, alert, facts, final, Usage(), tuple(results), ())
    return replay, oracle


def id_for(replay, oracle, key):
    return next(eid for eid, fact in replay.facts.items() if key in matched_fact_keys(fact, oracle))


@pytest.mark.parametrize('case,expected', [(1,True),(2,True),(3,None),(4,None),(5,None)])
def test_five_seed_cases_have_expected_sufficiency(case, expected):
    replay, oracle = sample(case)
    score = score_run(replay, oracle)
    assert score.evidence_sufficient is expected
    assert score.false_close is False
    assert score.metrics['discriminating_evidence_recall'].value is None
    if case in {4,5}:
        assert score.metrics['critical_evidence_recall'].denominator == 0
        assert score.metrics['unobservable_critical_fraction'].value == 1
        assert score.metrics['appropriate_abstention_precision'].value == 1


def test_c1_critical_denominator_deduplicates_asset_history_and_mirrors():
    replay, oracle = sample()
    score = score_run(replay, oracle)
    assert score.metrics['critical_evidence_recall'].numerator == 3
    assert score.metrics['critical_evidence_recall'].denominator == 3
    assert sum('E4' in matched_fact_keys(fact, oracle) for fact in replay.facts.values()) >= 2


def test_true_guess_without_cited_sufficient_evidence_fails():
    replay, oracle = sample()
    replay = replace(replay, final=replace(replay.final, final_evidence_ids=('ev-0001',)))
    assert score_run(replay, oracle).evidence_sufficient is False


def test_alternative_sufficient_sets_are_not_a_single_fixed_path():
    replay, oracle = sample()
    oracle = replace(oracle, sufficient_sets={'TP': (('E1', 'E2'), ('E1', 'E4')), 'FP': ()})
    cited = (id_for(replay, oracle, 'E1'), id_for(replay, oracle, 'E4'))
    score = score_run(replace(replay, final=replace(replay.final, final_evidence_ids=cited)), oracle)
    assert score.evidence_sufficient is True


def test_semantic_claim_uses_subject_pointer_value_not_text_or_id():
    replay, oracle = sample()
    eid = id_for(replay, oracle, 'E1')
    claims = (
        Claim('good', replay.alert.host, '/parent_process', 'WINWORD.EXE', (eid,), 'arbitrary prose', 'observation'),
        Claim('wrong', replay.alert.host, '/parent_process', 'trusted.exe', (eid,), 'seems safe', 'observation'),
        Claim('no-cite', replay.alert.host, '/parent_process', 'WINWORD.EXE', (), 'true but uncited', 'observation'),
        Claim('infer', replay.alert.host, '/anything', 'invented', (eid,), 'judgment', 'inference'),
    )
    scored = score_run(replace(replay, final=replace(replay.final, claims=claims)), oracle)
    metric = scored.metrics['evidence_grounding_rate']
    assert (metric.numerator, metric.denominator) == (1,3)
    assert scored.metrics['final_evidence_error_rate'].value == 1


def test_same_record_id_with_changed_semantics_does_not_map():
    replay, oracle = sample()
    eid = id_for(replay, oracle, 'E1')
    changed = deepcopy(replay.facts[eid])
    changed.value['parent_process'] = 'trusted.exe'
    assert 'E1' not in matched_fact_keys(changed, oracle)
    replay.facts[eid] = changed
    scored = score_run(replay, oracle)
    assert scored.metrics['provenance_validity'].value < 1


def test_authenticated_conflicting_observation_blocks_determinate_sufficiency():
    replay, oracle = sample()
    eid = id_for(replay, oracle, 'E1')
    fact = deepcopy(replay.facts[eid])
    fact.value['parent_process'] = 'trusted.exe'
    fact.fact_key = 'siem:' + content_hash(fact.value)
    replay.facts[eid] = fact
    results = []
    for result in replay.tool_results:
        records = tuple(replace(record, payload=deepcopy(fact.value), content_sha256=content_hash(fact.value))
                        if record.record_id in fact.record_ids else record for record in result.records)
        results.append(replace(result, records=records))
    score = score_run(replace(replay, tool_results=tuple(results)), oracle)
    assert score.metrics['provenance_validity'].value == 1
    assert score.evidence_sufficient is False
    assert any("conflicts=['E1']" in note for note in score.annotation_notes)


def test_oracle_record_id_from_wrong_tool_does_not_map():
    replay, oracle = sample()
    fact = deepcopy(replay.facts[id_for(replay, oracle, 'E1')])
    fact.fact_key = 'asset:' + content_hash(fact.value)
    assert not matched_fact_keys(fact, oracle)


def test_bad_raw_hash_does_not_count_as_provenance():
    replay, oracle = sample()
    eid = id_for(replay, oracle, 'E1')
    fact = replay.facts[eid]
    results = []
    for result in replay.tool_results:
        records = tuple(replace(record, content_sha256='00'*32)
                        if record.record_id in fact.record_ids else record for record in result.records)
        results.append(replace(result, records=records))
    replay = replace(replay, tool_results=tuple(results), final=replace(replay.final, final_evidence_ids=(eid,)))
    assert score_run(replay, oracle).metrics['provenance_validity'].value == 0


def test_equal_json_bool_and_integer_are_not_semantic_matches():
    replay, oracle = sample(2)
    eid = id_for(replay, oracle, 'E2')
    claim = Claim('bool', replay.alert.host, '/critical_asset', 0, (eid,), 'bad typed claim', 'observation')
    scored = score_run(replace(replay, final=replace(replay.final, claims=(claim,))), oracle)
    assert scored.metrics['evidence_grounding_rate'].value == 0


def test_original_invalid_proposal_and_safe_final_are_separate_and_temporally_scoped():
    replay, oracle = sample()
    eid = id_for(replay, oracle, 'E1')
    raw = encode(replace(replay.final, final_evidence_ids=(eid,), claims=()))
    safe = encode(FinalAssessment('Abstain','human_review','no_useful_action'))
    revisions = (
        {'call_id':'m1','phase':'final','raw_output':raw,'accepted_output':None,'available_evidence_ids':['ev-0001']},
        {'call_id':'m1','phase':'final','raw_output':raw,'accepted_output':safe,'available_evidence_ids':list(replay.facts)},
    )
    replay = replace(replay, final=FinalAssessment('Abstain','human_review','no_useful_action'), model_output_revisions=revisions)
    scored = score_run(replay, oracle)
    assert scored.metrics['model_proposal_error_rate'].denominator == 1
    assert scored.metrics['model_proposal_error_rate'].value == 1
    assert scored.metrics['model_accepted_error_rate'].value == 0
    assert scored.metrics['final_evidence_error_rate'].value == 0


def test_missing_proposal_temporal_scope_is_na_not_fabricated_correct():
    replay, oracle = sample()
    replay = replace(replay, model_output_revisions=({'call_id':'m','phase':'final','raw_output':encode(replay.final),'accepted_output':encode(replay.final)},))
    scored = score_run(replay, oracle)
    assert scored.metrics['model_proposal_error_rate'].value is None
    assert scored.metrics['model_proposal_scoring_coverage'].value == 0


def test_unsafe_fp_is_counted_as_false_close_not_dropped_as_protocol_failure():
    replay, oracle = sample(4, verdict='FP')
    scored = score_run(replay, oracle)
    assert scored.run_status == 'valid' and scored.false_close
    assert scored.evidence_sufficient is False


def test_react_nested_finish_is_included_in_model_proposal_error_metrics():
    replay, oracle = sample(1)
    good = encode(replay.final)
    bad = {**good, 'final_evidence_ids': ['ev-not-acquired']}
    available = list(replay.facts)
    revisions = (
        {'call_id': 'react-final', 'phase': 'react_action_2',
         'raw_output': {'action': 'finish', 'final': bad},
         'accepted_output': None, 'available_evidence_ids': available},
        {'call_id': 'react-final', 'phase': 'react_action_2',
         'raw_output': {'action': 'finish', 'final': bad},
         'accepted_output': {'action': 'finish', 'final': good},
         'available_evidence_ids': available},
    )
    scored = score_run(replace(replay, model_output_revisions=revisions), oracle)
    assert scored.metrics['model_proposal_error_rate'].value == 1
    assert scored.metrics['model_proposal_scoring_coverage'].value == 1
    assert scored.metrics['model_accepted_error_rate'].value == 0


def test_malformed_react_finish_attempt_counts_as_proposal_error():
    replay, oracle = sample(1)
    available = list(replay.facts)
    revisions = (
        {'call_id': 'react-malformed', 'phase': 'react_action_1',
         'raw_output': {'action': 'finish', 'final': 'bad'},
         'accepted_output': None, 'available_evidence_ids': available},
        {'call_id': 'react-malformed', 'phase': 'react_action_1',
         'raw_output': {'action': 'finish', 'final': 'bad'},
         'accepted_output': None, 'available_evidence_ids': available},
    )
    scored = score_run(replace(replay, model_output_revisions=revisions), oracle)
    assert scored.metrics['model_proposal_error_rate'].value == 1
    assert scored.metrics['model_proposal_scoring_coverage'].value == 1
    assert scored.metrics['model_accepted_error_rate'].value is None


@pytest.mark.parametrize('case', [1,2,3,4,5])
def test_default_runtime_id_remapping_preserves_oracle_mapping(case):
    replay, oracle = sample(case, remap_ids=True)
    scored = score_run(replay, oracle)
    assert 'E0' in matched_fact_keys(replay.facts['ev-0001'], oracle)
    assert scored.evidence_sufficient is (True if case < 3 else None)


@pytest.mark.asyncio
@pytest.mark.parametrize('case', [1,2,3,4,5])
async def test_actual_default_loaders_dispatch_trace_replay_and_score(case, tmp_path):
    from datetime import timedelta
    from evaluation.replay import replay_run
    from evidence_investigation.runtime.budget import BudgetController
    from evidence_investigation.runtime.dispatcher import Dispatcher
    from evidence_investigation.runtime.registry import EvidenceRegistry
    from evidence_investigation.runtime.trace import TraceRecorder
    from evidence_investigation.state.contracts import AssetQuery, Budget, SIEMQuery, TimeWindow, ToolCall
    from evidence_investigation.tools.server import MockToolServer

    oracle = load_oracle(ROOT / 'oracle' / f'c{case}.json')
    alert = load_public(ROOT / 'public' / f'c{case}.json').alert
    world = load_environment(ROOT / 'environment' / (f'world-{case}.json' if case < 4 else 'shared-pair.json'))
    registry = EvidenceRegistry(alert)
    budget = BudgetController(Budget())
    manifest = replace(make_manifest(), tool_snapshot=world.fixture_version, rubric_version=oracle.rubric_version)
    trace = TraceRecorder('run-1', manifest, tmp_path, usage_provider=budget.snapshot)
    dispatcher = Dispatcher('run-1', alert.as_of, registry, budget, MockToolServer(world, simulate_latency=False), trace=trace)
    trace.emit('alert_received', {'alert': encode(alert)}, state_version_after=1)
    window = TimeWindow(alert.as_of-timedelta(minutes=10), alert.as_of)
    for view in ('process_tree','network_events'):
        await dispatcher.dispatch(ToolCall('siem', SIEMQuery(view, window, host=alert.host, process_id=alert.process_id)))
    await dispatcher.dispatch(ToolCall('asset', AssetQuery(alert.host, alert.as_of)))
    verdict = 'TP' if case == 1 else 'FP' if case == 2 else 'Suspicious' if case == 3 else 'Abstain'
    final = FinalAssessment(verdict, 'escalate' if verdict == 'TP' else 'close_recommended' if verdict == 'FP' else 'human_review',
                            'sufficient' if case < 3 else 'no_useful_action',
                            final_evidence_ids=tuple(f.evidence_id for f in registry.facts()+registry.operational_facts()))
    trace.finalize(final)
    scored = score_run(replay_run(trace.dir), oracle)
    assert scored.evidence_sufficient is (True if case < 3 else None)
    assert scored.metrics['provenance_validity'].value == 1
    if case < 3:
        assert scored.metrics['critical_evidence_recall'].value == 1
    if case in {4,5}:
        assert any('E2' in matched_fact_keys(fact, oracle) for fact in replay_run(trace.dir).facts.values())
