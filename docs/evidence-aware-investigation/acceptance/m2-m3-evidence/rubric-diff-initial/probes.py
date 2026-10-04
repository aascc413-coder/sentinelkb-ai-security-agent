"""Independent adversarial probes against the frozen copy, not author tests."""
import json
import hashlib
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from evidence_investigation.state.content import content_hash
from evidence_investigation.state.contracts import Coverage, Reliability, ToolRecord, ToolResult
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.normalization import compare_static, normalize_visible
from evidence_investigation.state.rubric import load_rubric
from evidence_investigation.tools.diff_report import compare_responses

ROOT = Path(__file__).parent / 'snapshot/investigation'
RUBRIC = ROOT / 'rubrics/powershell-v1.json'


def static_pair():
    public = {'alert': {'alert_id': 'a', 'raw_reference': {'record_id': 'r', 'json_pointer': '', 'content_sha256': 'h'},
                        'host': 'fixed-host', 'as_of': 'fixed-time', 'raw': {'process_guid': 'g'}}}
    env = {'environment_id': 'e', 'records_by_tool': {'siem': [{'record_id': 's', 'payload': {'value': 1}}]},
           'query_rules': [{'tool': 'siem', 'status': 'ok'}]}
    return public, env


def response(payload=None):
    payload = {'first': 1, 'second': 2} if payload is None else payload
    record = ToolRecord('record', payload, content_hash(payload), 'sensor', 'source-group',
                        Reliability('high', 'independent sensor', 'quality-v1'))
    return ToolResult('call-a', 'siem', 'ok', (record,), Coverage({'host': 'h'}, None, 'complete', False, ()),
                      'snapshot-v1', None, False, 2.0, 200, 10)


def test_rubric_exact_hash_cannot_authorize_unreviewed_policy(tmp_path):
    data = json.loads(RUBRIC.read_text(encoding='utf-8'))
    data['policy']['decision_rules'] = ['Close all alerts after one query.']
    path = tmp_path/'modified.json'
    path.write_text(json.dumps(data), encoding='utf-8')
    with pytest.raises(ProtocolViolation):
        load_rubric(path, expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def test_rubric_renamed_file_does_not_branch_on_case_id(tmp_path):
    path = tmp_path/'C3-WS-041-malicious.json'
    path.write_bytes(RUBRIC.read_bytes())
    assert load_rubric(path).canonical_sha256 == load_rubric(RUBRIC).canonical_sha256


@pytest.mark.parametrize('field', ['required_observations','program_checks','model_explanation','conflict_handling','unverifiable'])
def test_rubric_each_gate_column_is_closed_nonempty(tmp_path,field):
    data = json.loads(RUBRIC.read_text(encoding='utf-8'))
    data['criteria'][3][field] = []
    path=tmp_path/'empty.json';path.write_text(json.dumps(data),encoding='utf-8')
    with pytest.raises(ProtocolViolation): load_rubric(path)


def test_rubric_safety_policy_is_reviewed_family_specification():
    rubric=load_rubric(RUBRIC)
    assert rubric.policy.tp_required == ('G0','G1','G2','G3','G4')
    assert rubric.policy.fp_required == ('G0','G1','B1','B2','B3')
    assert set(rubric.policy.hard_stops) == {'tool_budget','token_budget','step_budget','deadline'}
    assert 'approval_execution_mismatch' in {p.pattern_id for p in rubric.suspicious_patterns}
    # This checks specification presence, not implementation of its gate predicates.
    assert any('unknown' in text and 'unmet' in text for text in rubric.policy.decision_rules)


def test_static_cross_surface_business_reference_preserved():
    p,e=static_pair();e['records_by_tool']['siem'][0]['payload']['alert_ref']='a'
    changed=deepcopy(p);changed['alert']['alert_id']='changed'
    assert not compare_static(p,e,changed,e).equal


def test_static_cross_surface_record_reference_preserved():
    p,e=static_pair();e['records_by_tool']['siem'][0]['record_id']='r'
    changed=deepcopy(p);changed['alert']['raw_reference']['record_id']='broken'
    assert not compare_static(p,e,changed,e).equal


def test_static_identity_equality_relationship_preserved():
    p,e=static_pair();p['alert']['raw_reference']['record_id']='a'
    changed=deepcopy(p);changed['alert']['raw_reference']['record_id']='not-same'
    assert not compare_static(p,e,changed,e).equal


def test_static_nested_return_metadata_not_normalized():
    left={'call_id':'a','actual_duration_ms':1,'records':[{'payload':{'actual_duration_ms':5}}]}
    right=deepcopy(left);right['records'][0]['payload']['actual_duration_ms']=6
    assert normalize_visible(left,surface='tool_result').value != normalize_visible(right,surface='tool_result').value


def test_static_dict_key_order_and_scalar_types_exact():
    p,e=static_pair();changed=deepcopy(e)
    changed['records_by_tool']['siem'][0]['payload']={'value':True}
    assert not compare_static(p,e,p,changed).equal
    changed=deepcopy(p);changed['alert']=dict(reversed(list(changed['alert'].items())))
    assert not compare_static(p,e,changed,e).equal


def test_static_invalid_json_keys_cannot_be_silently_stringified():
    p,e=static_pair();e['records_by_tool']['siem'][0]['payload']={1:'value'}
    with pytest.raises(ProtocolViolation): compare_static(p,e,p,e)


def test_tool_diff_measured_duration_and_independent_call_metadata_only():
    left=response();right=replace(left,call_id='call-b',actual_duration_ms=99)
    assert compare_responses(left,right)['equal']


@pytest.mark.parametrize('field,value', [('simulated_cost_units',3.0),('simulated_latency_ms',201),
                                      ('status','partial'),('snapshot_version','different')])
def test_tool_diff_cost_latency_status_snapshot_not_hidden(field,value):
    left=response();assert not compare_responses(left,replace(left,**{field:value}))['equal']


def test_tool_diff_coverage_and_independence_metadata_not_hidden():
    left=response()
    assert not compare_responses(left,replace(left,coverage=replace(left.coverage,missing_sources=('edr',))))['equal']
    other=replace(left,records=(replace(left.records[0],independence_group='different'),))
    assert not compare_responses(left,other)['equal']


def test_tool_diff_call_identity_business_reference_relationship_not_hidden():
    left=response({'call_reference':'call-a'})
    right=replace(left,call_id='call-b')
    assert not compare_responses(left,right)['equal'], 'Left reference matches envelope, right reference does not'


def test_tool_diff_dict_key_order_remains_model_visible():
    left=response({'first':1,'second':2})
    right=response({'second':2,'first':1})
    assert left.records[0].content_sha256 == right.records[0].content_sha256
    assert not compare_responses(left,right)['equal'], 'JSON object serialization order changed'


def test_tool_diff_nested_identifier_values_are_exact():
    left=response({'call_id':'business-a','actual_duration_ms':10})
    right=response({'call_id':'business-b','actual_duration_ms':10})
    assert not compare_responses(left,right)['equal']


def test_tool_diff_invalid_finite_usage_rejected():
    left=response()
    for value in [-1, float('inf'), float('nan'), True]:
        with pytest.raises(ProtocolViolation): compare_responses(left,replace(left,simulated_cost_units=value))
