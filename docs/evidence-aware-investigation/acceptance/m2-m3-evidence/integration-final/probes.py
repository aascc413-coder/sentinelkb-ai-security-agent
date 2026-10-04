from pathlib import Path
import sys,importlib.util,json,hashlib,shutil,itertools
from datetime import timedelta
import pytest
ROOT=Path(__file__).parent
LAB=ROOT/'investigation'
sys.path.insert(0,str(LAB/'src'))
sys.path.insert(0,str(LAB))
from evidence_investigation.state.contracts import *
from evidence_investigation.state.public_loader import load_public
from evidence_investigation.state.errors import ProtocolViolation
from evidence_investigation.tools.fixture_loader import load_environment
from evidence_investigation.tools.server import MockToolServer
from evidence_investigation.tools.diff_report import compare_responses
from evidence_investigation.tools.selection import matches_constraints

def module(name):
 spec=importlib.util.spec_from_file_location(name,LAB/'scripts'/f'{name}.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def world(n):
 p=load_public(LAB/f'datasets/public/c{n}.json');path='shared-pair' if n>=4 else f'world-{n}'
 return p.alert,MockToolServer(load_environment(LAB/f'datasets/environment/{path}.json'),simulate_latency=False)
def win(a): return TimeWindow(a.as_of-timedelta(minutes=10),a.as_of)
async def call(s,a,tool,q,cid='probe',timeout=5000): return await getattr(s,tool)(q,ToolContext('run',cid,a.as_of,timeout))
def test_dependency_code_comes_from_frozen_copy():
 import evidence_investigation.tools.selection as s
 assert Path(s.__file__).resolve().is_relative_to(ROOT)
@pytest.mark.asyncio
@pytest.mark.parametrize('order',list(itertools.permutations(('process_tree','network_events','asset'))))
async def test_c1_permutations_and_mirror_identity(order):
 a,s=world(1);out={}
 for tool in order:
  q=AssetQuery(a.host,a.as_of) if tool=='asset' else SIEMQuery(tool,win(a),a.host,a.user,a.process_id)
  out[tool]=await call(s,a,'asset' if tool=='asset' else 'siem',q)
 assert all(r.status=='ok' for r in out.values())
 p,n=out['process_tree'].records,out['network_events'].records
 assert len(p)==2 and p[0].record_id!=p[1].record_id and p[0].content_sha256==p[1].content_sha256
 assert p[0].independence_group==p[1].independence_group!=n[0].independence_group
 assert p[0].payload['process_guid']==n[0].payload['process_guid']
@pytest.mark.asyncio
async def test_event_upper_boundary_empty_is_not_unknown_or_truncated():
 a,s=world(1)
 at_event=TimeWindow(win(a).start,a.occurred_at)
 e=await call(s,a,'siem',SIEMQuery('process_tree',at_event,a.host,a.user,a.process_id))
 assert e.status=='empty' and e.coverage.completeness=='complete'
 after=TimeWindow(a.occurred_at,a.as_of)
 p=await call(s,a,'siem',SIEMQuery('process_tree',after,a.host,a.user,a.process_id,1))
 assert p.status=='partial' and p.coverage.truncated
 u=await call(s,a,'siem',SIEMQuery('process_tree',win(a),'unseen',a.user,a.process_id))
 assert u.status=='unavailable' and u.coverage.completeness=='unknown'
@pytest.mark.asyncio
async def test_same_window_alternative_approval_scope_and_independence():
 a,s=world(1);asset=await call(s,a,'asset',AssetQuery(a.host,a.as_of))
 for kind,entity in (('host',a.host),('user',a.user)):
  h=await call(s,a,'history',HistoryQuery(kind,entity,win(a),a.host,a.user))
  assert h.status=='ok' and len(h.records)==1
  assert h.records[0].payload['register_window']==asset.records[0].payload['approval_register_window']
  assert h.records[0].payload['approved_jobs']==asset.records[0].payload['approved_jobs']==[]
  assert h.records[0].independence_group==asset.records[0].independence_group
@pytest.mark.asyncio
@pytest.mark.parametrize('order',[('ip','hash'),('hash','ip')])
async def test_mixed_ti_constraints_atomic_in_both_orders(order):
 a,s=world(3);values={'ip':'198.51.100.27','hash':'h-9'}
 for kind in order:
  q=TIQuery(kind,values[kind],a.as_of)
  other='hash' if kind=='ip' else 'ip'
  assert matches_constraints(q,{'indicator_type':kind,'value':values[kind]})
  assert not matches_constraints(q,{'indicator_type':other,'value':values[other]})
  assert not matches_constraints(q,{'value':values[other],'indicator_type':other})
  r=await call(s,a,'threat_intel',q)
  assert r.status=='ok' and r.records[0].payload['indicator_type']==kind and r.records[0].payload['reputation']=='unknown'
@pytest.mark.asyncio
async def test_paired_reversed_independent_orders_response_cost_coverage():
 a,l=world(4);_,r=world(5)
 queries=[('siem',SIEMQuery('process_tree',win(a),a.host,a.user,a.process_id)),('asset',AssetQuery(a.host,a.as_of)),('history',HistoryQuery('user',a.user,win(a),a.host,a.user)),('siem',SIEMQuery('network_events',win(a),a.host,a.user,a.process_id))]
 first={}
 for i,(t,q) in enumerate(queries): first[i]=await call(l,a,t,q,f'L{i}')
 for i in reversed(range(len(queries))):
  t,q=queries[i];res=await call(r,a,t,q,f'R{i}');assert compare_responses(first[i],res)['equal']
 for i in reversed(range(len(queries))):
  t,q=queries[i];x=await call(l,a,t,q,f'LC{i}');y=await call(r,a,t,q,f'RC{i}')
  assert compare_responses(x,y)['equal'];assert x.simulated_cost_units==y.simulated_cost_units==0;assert x.simulated_latency_ms==0
@pytest.mark.asyncio
async def test_paired_timeout_not_cached_but_warm_cache_can_finish_fast():
 a,l=world(4);_,r=world(5);q=SIEMQuery('process_tree',win(a),a.host,a.user,a.process_id)
 for s in (l,r):
  x=await call(s,a,'siem',q,'short',50);assert x.status=='timeout' and x.retryable and x.simulated_cost_units==2
  good=await call(s,a,'siem',q,'full');assert good.status=='partial' and good.simulated_cost_units==2
  cached=await call(s,a,'siem',q,'cached',50);assert cached.status=='partial' and cached.simulated_cost_units==0 and cached.simulated_latency_ms==0
  assert s.stats().backend_calls==2 and s.stats().cache_hits==1

def copy_data(tmp_path): shutil.copytree(LAB/'datasets',tmp_path/'datasets');return tmp_path/'datasets'
def modify(root,rel,mutator):
 path=root/rel;data=json.loads(path.read_text());mutator(data);path.write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
 mpath=root/'manifest.json';m=json.loads(mpath.read_text());m['file_sha256'][rel]=hashlib.sha256(path.read_bytes()).hexdigest();mpath.write_text(json.dumps(m),encoding='utf-8')
def test_summary_rejects_dangling_oracle_ref(tmp_path):
 root=copy_data(tmp_path);modify(root,'oracle/c1.json',lambda d:d['complete_world_evidence']['E1'].update(record_ids=['dangling']))
 with pytest.raises(ProtocolViolation,match='dangling_annotation'):module('dataset_summary').summarize(root)
def test_summary_rejects_visible_hidden_world_annotation(tmp_path):
 root=copy_data(tmp_path);modify(root,'oracle/c4.json',lambda d:d['observable_fact_keys'].append('E6'))
 with pytest.raises(ProtocolViolation):module('dataset_summary').summarize(root)
def test_summary_rejects_mismatched_annotation_tool_source(tmp_path):
 root=copy_data(tmp_path);modify(root,'oracle/c1.json',lambda d:d['complete_world_evidence']['E1'].update(source='asset'))
 with pytest.raises(ProtocolViolation):module('dataset_summary').summarize(root)
def test_summary_rejects_unhashed_bytes_in_unused_declared_file(tmp_path):
 root=copy_data(tmp_path);extra=root/'public/unused.json';extra.write_bytes((root/'public/c1.json').read_bytes())
 mp=root/'manifest.json';m=json.loads(mp.read_text());m['file_sha256']['public/unused.json']='0'*64;mp.write_text(json.dumps(m))
 with pytest.raises(ProtocolViolation):module('dataset_summary').summarize(root)
@pytest.mark.asyncio
async def test_replay_never_reads_oracle_or_imports_evaluator(monkeypatch):
 replay=module('replay_seed_tools');original=Path.read_bytes
 def safe_read(self,*args,**kwargs):
  assert '/oracle/' not in self.as_posix(), 'Replay read oracle data'
  return original(self,*args,**kwargs)
 monkeypatch.setattr(Path,'read_bytes',safe_read)
 result=await replay.replay();assert result['paired_equal'] and result['paired_queries']==27
 assert all('ground_truth' not in c and 'verdict' not in c for c in result['cases'].values())
