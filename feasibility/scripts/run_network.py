"""Four real CometBFT + Rust ABCI processes; local experimental network only.

This checks ABCI, epoch accounting, validator delay, restart replay, and quorum.
It does NOT test shielded transactions, production staking, JMT, or custom signer.
"""
from pathlib import Path
import base64
import datetime as dt
import hashlib
import json
import os
import re
import socket
import subprocess
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
COMET=ROOT/'.tools/bin/cometbft.exe'
APP=ROOT/'target-consensus/release/bit-consensus-probe.exe'
RUN=ROOT/'runtime'/('network-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%f'))
REPORT=ROOT/'reports'
ENV=os.environ.copy()
ENV['PATH']=str(ROOT/'.tools/rust/bin')+os.pathsep+ENV['PATH']
procs={}; handles=[]; events=[]

def command(args):
    p=subprocess.run([str(x)for x in args],capture_output=True,text=True,env=ENV,creationflags=0x08000000,timeout=60)
    if p.returncode:raise RuntimeError(f'{args[1:]}: {p.stderr}')
    return p.stdout.strip()
def rpc(i,path):
    with urllib.request.urlopen(f'http://127.0.0.1:{28700+i}/{path}',timeout=2)as r:
        data=json.load(r)
    if 'error'in data:raise RuntimeError(data['error'])
    return data['result']
def height(i):
    try:return int(rpc(i,'status')['sync_info']['latest_block_height'])
    except (OSError,ValueError,RuntimeError):return 0
def spawn(key,args):
    out=(RUN/f'{key}-{time.time_ns()}.log').open('wb');handles.append(out)
    procs[key]=subprocess.Popen([str(x)for x in args],stdout=out,stderr=subprocess.STDOUT,env=ENV,creationflags=0x08000000)
def stop(key):
    p=procs.pop(key,None)
    if p and p.poll()is None:
        p.terminate()
        try:p.wait(timeout=5)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
def start_pair(i):
    flags=([11,'after-finalize']if i==0 else [21,'after-commit']if i==1 else [])
    spawn(f'app{i}',[APP,f'127.0.0.1:{28900+i}',RUN/f'app{i}',*flags])
    time.sleep(.2)
    spawn(f'node{i}',[COMET,'start','--home',RUN/'nodes'/f'node{i}'])
def wait_height(target,indices=range(4),seconds=90):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        hs=[height(i)for i in indices]
        if all(h>=target for h in hs):return hs
        time.sleep(.3)
    raise TimeoutError(f'height {target} not reached: {hs}')

def main():
    assert APP.is_file()and COMET.is_file(),'build programs first'
    for port in list(range(28700,28704))+list(range(28800,28804))+list(range(28900,28904)):
        with socket.socket()as s:s.bind(('127.0.0.1',port))
    RUN.mkdir(parents=True)
    command([COMET,'testnet','--v','4','--o',RUN/'nodes','--populate-persistent-peers=false'])
    ids=[command([COMET,'show-node-id','--home',RUN/'nodes'/f'node{i}'])for i in range(4)]
    genesis=json.loads((RUN/'nodes/node0/config/genesis.json').read_text(encoding='utf-8'))
    genesis['chain_id']='bit-feasibility-'+RUN.name
    genesis['genesis_time']=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=3)).isoformat().replace('+00:00','Z')
    for validator in genesis['validators']:validator['power']='10'
    first_key=min(base64.b64decode(v['pub_key']['value'])for v in genesis['validators'])
    genesis_bytes=json.dumps(genesis,indent=2)
    for i in range(4):
        folder=RUN/'nodes'/f'node{i}'/'config'
        (folder/'genesis.json').write_text(genesis_bytes,encoding='utf-8')
        config=(folder/'config.toml').read_text(encoding='utf-8')
        peers=','.join(f'{ids[j]}@127.0.0.1:{28800+j}'for j in range(4)if i!=j)
        replacements={
          'proxy_app':f'"tcp://127.0.0.1:{28900+i}"','persistent_peers':json.dumps(peers),
          'allow_duplicate_ip':'true','addr_book_strict':'false','pex':'false',
          'timeout_propose':'"500ms"','timeout_propose_delta':'"100ms"',
          'timeout_prevote':'"200ms"','timeout_precommit':'"200ms"','timeout_commit':'"500ms"',
          'log_level':'"error"','indexer':'"null"',
        }
        for name,value in replacements.items():
            config,n=re.subn(r'^'+re.escape(name)+r' = .*$',f'{name} = {value}',config,flags=re.M)
            assert n>=1,name
        config=config.replace('tcp://127.0.0.1:26657',f'tcp://127.0.0.1:{28700+i}')
        config=config.replace('tcp://0.0.0.0:26656',f'tcp://127.0.0.1:{28800+i}')
        config=config.replace('tcp://127.0.0.1:26656',f'tcp://127.0.0.1:{28800+i}')
        (folder/'config.toml').write_text(config,encoding='utf-8')
        start_pair(i)
    handled=set();deadline=time.monotonic()+150
    while time.monotonic()<deadline:
        for i in [0,1]:
            if i not in handled and procs[f'app{i}'].poll()is not None:
                code=procs[f'app{i}'].returncode
                assert code==86,f'app{i} unexpected failure {code}'
                state=json.loads((RUN/f'app{i}'/'state.json').read_text(encoding='utf-8'))
                expected=10 if i==0 else 21
                assert state['height']==expected,(state['height'],expected)
                events.append({'fault_node':i,'exit_code':code,'durable_height':state['height'],'completed_epochs':state['supply']['completed'],'phase':'after-finalize'if i==0 else'after-commit'})
                stop(f'node{i}');stop(f'app{i}');start_pair(i);handled.add(i)
                print(f'Restarted node {i} at durable height {expected}',flush=True)
        if len(handled)==2 and min(height(i)for i in range(4))>=40:break
        time.sleep(.3)
    assert len(handled)==2,'faults not exercised'
    wait_height(42)
    # Same committed state and header application hash across independently executing nodes.
    data=[(RUN/f'app{i}/state-40.json').read_bytes()for i in range(4)]
    assert all(x==data[0]for x in data),'state divergence'
    state_hash=hashlib.sha256(data[0]).hexdigest()
    for i in range(4):
        header=rpc(i,'block?height=41')['block']['header']
        assert header['app_hash'].lower()==state_hash,'state/header height mismatch'
    updates=[]
    for h,expected in [(5,10),(6,10),(7,11)]:
        vals=rpc(0,f'validators?height={h}&per_page=100')['validators']
        v=next(v for v in vals if base64.b64decode(v['pub_key']['value'])==first_key)
        actual=int(v['voting_power']);assert actual==expected,(h,actual)
        updates.append({'height':h,'power':actual})
    stop('node2');stop('node3')
    time.sleep(2)
    before=height(0);time.sleep(3);after=height(0)
    assert after==before,f'chain advanced without >2/3: {before}->{after}'
    spawn('node2',[COMET,'start','--home',RUN/'nodes/node2'])
    recovered=wait_height(after+4,indices=[0,1,2])
    print('Four-node state agreement, H+2, replay and quorum checks passed',flush=True)
    return {'scope':'real CometBFT v0.38.23 module and four Rust ABCI processes; empty-block emission fixture only',
      'runtime_dir':str(RUN),'checks':{'four_node_state_equal_at_40':True,'state40_matches_header41':True,'validator_updates':updates,'crash_recovery':events,'quorum_halt_height':after,'resumed_heights':recovered},
      'state_at_40':json.loads(data[0]),'sha256_state40':state_hash,
      'limitations':['no BIT user transaction protocol or ZK in this network','no production staking, slashing, fees or reward-score allocation','upstream FilePV signer in CometBFT processes, not a separate BIT signer','JSON durable fixture, not JMT/RocksDB state or state proofs','accelerated experimental policy; no mainnet decisions','same physical host, not independent failure domains']}

if __name__=='__main__':
    started=dt.datetime.now(dt.timezone.utc).isoformat()
    try:
        result=main();result.update(status='PASS',started_at=started,finished_at=dt.datetime.now(dt.timezone.utc).isoformat())
        (REPORT/'network-result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        (RUN/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    except Exception as error:
        (REPORT/'network-result.json').write_text(json.dumps({'status':'FAIL','started_at':started,'runtime_dir':str(RUN),'error':repr(error),'events':events},indent=2)+'\n',encoding='utf-8')
        if RUN.exists(): (RUN/'result.json').write_bytes((REPORT/'network-result.json').read_bytes())
        raise
    finally:
        for key in list(procs):stop(key)
        for handle in handles:handle.close()
