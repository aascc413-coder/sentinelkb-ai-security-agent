from types import SimpleNamespace as NS
from evaluation.report import summarize_efficiency


def row(verdict, truth, value=None):
    behavior = None if value is None else NS(measurement={
        **{k: value for k in ('tool_attempts', 'backend_calls', 'steps', 'elapsed_ms',
                             'measured_input_tokens', 'measured_output_tokens', 'tool_cost_units')},
        'cost_comparison_eligible': True})
    return NS(score=NS(run_status='valid' if value is not None else 'protocol_failure',
                       verdict=verdict, ground_truth=truth), behavior=behavior)


def test_efficiency_retains_failures_and_separates_correct_decisions():
    report = summarize_efficiency([row('TP', 'malicious', 2), row('FP', 'malicious', 8),
                                   row('Abstain', 'benign', 5), row(None, 'benign')])
    all_runs = report['all_attempts']['tool_attempts']
    assert all_runs == dict(values=[2, 5, 8], measured_runs=3, attempted_runs=4,
                            mean=5, p50=5, p95=8)
    assert report['correct_determinate']['tool_attempts']['values'] == [2]


def test_efficiency_unknown_tokens_are_not_zero_and_empty_is_na():
    item = row('TP', 'malicious', 2)
    item.behavior.measurement['cost_comparison_eligible'] = False
    report = summarize_efficiency([item])
    assert report['all_attempts']['measured_input_tokens']['mean'] is None
    assert report['all_attempts']['tool_attempts']['mean'] == 2
    assert summarize_efficiency([])['all_attempts']['steps']['p95'] is None
