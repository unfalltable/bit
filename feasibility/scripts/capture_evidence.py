"""Record current binaries, source hashes, dependency locks, and measured host metadata."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import platform
import subprocess

ROOT=Path(__file__).resolve().parents[1]
REPORTS=ROOT/'reports'
def command(args):
 p=subprocess.run([str(x)for x in args],capture_output=True,creationflags=0x08000000)
 return {'command':[str(x)for x in args],'exit_code':p.returncode,'stdout':p.stdout.decode('utf-8',errors='replace').strip(),'stderr':p.stderr.decode('utf-8',errors='replace').strip()}
def sha(p):
 with p.open('rb')as f:return hashlib.file_digest(f,'sha256').hexdigest()

if __name__=='__main__':
 files=[]
 for folder in ['proof-probe','consensus-probe','scripts']:
  files.extend(
   p for p in (ROOT/folder).rglob('*')
   if p.is_file()
   and '__pycache__' not in p.parts
   and 'target' not in p.relative_to(ROOT/folder).parts
  )
 for path in ['.tools/bin/cometbft.exe','target/release/bit-proof-probe.exe','target-consensus/release/bit-consensus-probe.exe']:
  p=ROOT/path
  if p.exists():files.append(p)
 for name in ['proof-result.json','network-result.json','consensus-unit.log','proof-build.log',
              'consensus-build.log','feasibility-summary.json','proof-parameter-downloads.json',
              'tool-downloads.json','native-linker-download.json','comet-module.json']:
  p=REPORTS/name
  if p.exists():files.append(p)
 commands=[
  ['git','-C',ROOT/'upstream/penumbra','rev-parse','HEAD'],
  ['git','-C',ROOT/'upstream/penumbra','status','--porcelain'],
  [ROOT/'.tools/rust/bin/rustc.exe','--version','--verbose'],
  [ROOT/'.tools/go/bin/go.exe','version','-m',ROOT/'.tools/bin/cometbft.exe'],
  [ROOT/'.tools/bin/cometbft.exe','version'],
 ]
 data={'captured_at':dt.datetime.now(dt.timezone.utc).isoformat(),'system':platform.platform(),
  'python':platform.python_version(),'commands':[command(c)for c in commands],
  'files':[{'path':p.relative_to(ROOT).as_posix(),'size':p.stat().st_size,'sha256':sha(p)}for p in sorted(files)],
  'mobile':'SKIPPED_BY_USER','scope':'experimental source/build/report provenance, not a production release manifest or SBOM'}
 (REPORTS/'provenance.json').write_text(json.dumps(data,indent=2)+'\n',encoding='utf-8')
 print('Recorded provenance for',len(files),'files')
