"""Run native proof benchmark and record actual process results, never preset success."""
from pathlib import Path
import ctypes
from ctypes import wintypes
import datetime as dt
import hashlib
import json
import os
import subprocess
import time

ROOT=Path(__file__).resolve().parents[1]
REPORTS=ROOT/'reports'
EXE=ROOT/'target/release/bit-proof-probe.exe'

class MemoryCounters(ctypes.Structure):
    _fields_=[('cb',wintypes.DWORD),('PageFaultCount',wintypes.DWORD),
      ('PeakWorkingSetSize',ctypes.c_size_t),('WorkingSetSize',ctypes.c_size_t),
      ('QuotaPeakPagedPoolUsage',ctypes.c_size_t),('QuotaPagedPoolUsage',ctypes.c_size_t),
      ('QuotaPeakNonPagedPoolUsage',ctypes.c_size_t),('QuotaNonPagedPoolUsage',ctypes.c_size_t),
      ('PagefileUsage',ctypes.c_size_t),('PeakPagefileUsage',ctypes.c_size_t)]

if __name__=='__main__':
    env=os.environ.copy();env['PATH']=str(ROOT/'.tools/rust/bin')+os.pathsep+env['PATH']
    env['RAYON_NUM_THREADS']='4'
    started=dt.datetime.now(dt.timezone.utc).isoformat();begin=time.monotonic()
    args=[str(EXE),str(ROOT/'.tools/downloads'),'5']
    peak=0
    get_memory=ctypes.windll.psapi.GetProcessMemoryInfo
    get_memory.argtypes=[wintypes.HANDLE,ctypes.POINTER(MemoryCounters),wintypes.DWORD]
    get_memory.restype=wintypes.BOOL
    with (REPORTS/'proof-stdout.json').open('wb')as out,(REPORTS/'proof-stderr.log').open('wb')as err:
        p=subprocess.Popen(args,stdout=out,stderr=err,env=env,creationflags=0x08000000)
        while p.poll()is None:
            counters=MemoryCounters();counters.cb=ctypes.sizeof(counters)
            if get_memory(int(p._handle),ctypes.byref(counters),counters.cb):peak=max(peak,counters.PeakWorkingSetSize)
            time.sleep(.1)
        code=p.wait()
    result={'status':'PASS'if code==0 else'FAIL','command':args,'started_at':started,
      'elapsed_seconds':time.monotonic()-begin,'exit_code':code,'peak_working_set_bytes':peak,
      'rayon_threads':4,'binary_sha256':hashlib.file_digest(EXE.open('rb'),'sha256').hexdigest(),
      'measurement_scope':'Windows desktop process; five samples do not establish a production p95 or mobile performance'}
    if code==0:result['probe']=json.loads((REPORTS/'proof-stdout.json').read_text())
    (REPORTS/'proof-result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items()if k!='probe'},indent=2))
    raise SystemExit(code)
