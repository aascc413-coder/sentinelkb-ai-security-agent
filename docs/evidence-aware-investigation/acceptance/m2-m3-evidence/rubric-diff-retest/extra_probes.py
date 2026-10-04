"""Independent follow-up probes for reference, key and order semantics."""
from copy import deepcopy
from dataclasses import replace

import pytest

from evidence_investigation.state.content import content_hash
from evidence_investigation.state.contracts import Coverage, Reliability, ToolRecord, ToolResult
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.state.normalization import compare_static, normalize_visible
from evidence_investigation.tools.diff_report import compare_responses


def public(alert_id):
    return {'alert':{'alert_id':alert_id,'raw_reference':{'record_id':'r'},'raw':{}}}


def env(payload):
    return {'environment_id':'e','records_by_tool':{'siem':[{'record_id':'s','payload':payload}]}}


def tool(payload):
    record=ToolRecord('record',payload,content_hash(payload),'sensor','source',Reliability('high','basis','v1'))
    return ToolResult('call-a','siem','ok',(record,),Coverage({},None,'complete',False,()),'v1',None,False,2.0,200,10)


def test_static_business_index_key_preserves_alert_reference():
    e=env({'a':'event'})
    assert not compare_static(public('a'),e,public('b'),e).equal


def test_static_nested_business_index_key_preserves_raw_record_reference():
    p=public('a');changed=deepcopy(p);changed['alert']['raw_reference']['record_id']='different'
    e=env({'correlation':[{'r':{'event':'observed'}}]})
    assert not compare_static(p,e,changed,e).equal


def test_static_nonreferenced_dynamic_identity_remains_equivalent():
    e=env({'not-an-id':'event'})
    assert compare_static(public('a'),e,public('b'),e).equal


def test_tool_business_index_key_preserves_call_reference_and_reports_exclusion():
    first=tool({'call-a':{'event':'observed'}});second=replace(first,call_id='call-b')
    report=compare_responses(first,second)
    assert not report['equal']
    assert report['normalization_exclusions'][0]['path']=='/call_id'
    assert any('call-a' in path for path in report['normalization_exclusions'][0]['reference_paths']['left'])


def test_tool_right_only_nested_reference_anchors_both_sides():
    first=tool({'correlation':['call-b']});second=replace(first,call_id='call-b')
    report=compare_responses(first,second)
    assert not report['equal']
    assert '/call_id' not in {item['path'] for item in report['normalized_fields']}


def test_tool_nested_key_order_report_names_the_exact_scope():
    first=tool({'nested':{'one':1,'two':2}});second=tool({'nested':{'two':2,'one':1}})
    report=compare_responses(first,second)
    assert not report['equal']
    assert any(item['path']=='/records/0/payload/nested' and item['kind']=='object_key_order'
               for item in report['differences'])


def test_tool_actual_duration_normalization_does_not_hide_nested_duration_changes():
    first=tool({'actual_duration_ms':10});second=tool({'actual_duration_ms':11})
    second=replace(second,actual_duration_ms=100)
    assert not compare_responses(first,second)['equal']


def test_static_cycle_rejected_without_breaking_shared_ordinary_values():
    cyclic={};cyclic['cycle']=cyclic
    with pytest.raises(ProtocolViolation):normalize_visible(cyclic,surface='public')
    shared={'event':'observed'}
    value={'alert':{'alert_id':'a','raw_reference':{'record_id':'r'},'raw':{'one':shared,'two':shared}}}
    assert normalize_visible(value,surface='public').value['alert']['raw']=={'one':shared,'two':shared}
