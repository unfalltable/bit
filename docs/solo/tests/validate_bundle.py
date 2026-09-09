"""Validate this documentation bundle, NOT an actual blockchain implementation.
Dependencies: requirements-validation.txt. Run from any working directory.
"""
from __future__ import annotations
import json, re, sys, unittest, io
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
checks = []
def check(name, condition, details=''):
    checks.append({'check':name,'passed':bool(condition),'details':details})
    if not condition:raise AssertionError(name + ': ' + details)
def load(p):return json.loads((ROOT/p).read_text(encoding='utf-8'))
def refs(o):
    if isinstance(o,dict):
        if '$ref' in o:yield o['$ref']
        for v in o.values():yield from refs(v)
    elif isinstance(o,list):
        for v in o:yield from refs(v)
def resolve(obj,pointer):
    cur=obj
    for token in pointer[2:].split('/'):
        cur=cur[token.replace('~1','/').replace('~0','~')]
    return cur

for f in ROOT.rglob('*.json'):
    if '__pycache__' not in str(f):json.loads(f.read_text())
check('all_json_parse',True)
for f in ROOT.rglob('*.yaml'):yaml.safe_load(f.read_text())
check('all_yaml_parse',True)
for f in (ROOT/'contracts').glob('*.schema.json'):
    schema=json.loads(f.read_text());Draft202012Validator.check_schema(schema)
    for r in refs(schema):
        if r.startswith('#/'):resolve(schema,r)
check('json_schema_structure_and_local_refs',True)
Draft202012Validator(load('contracts/mainnet-inputs.schema.json')).validate(load('config/mainnet-inputs.template.json'))
check('mainnet_template_not_marked_ready',True)
api=yaml.safe_load((ROOT/'contracts/openapi.yaml').read_text())
ops=[]
for path,item in api['paths'].items():
    for verb,op in item.items():
        if verb not in ['get','post','put','patch','delete']:continue
        ops.append(op['operationId'])
        parameters=op.get('parameters',[])
        pnames={p['name'] for p in parameters if p['in']=='path' and p.get('required')}
        check('path_parameters:'+op['operationId'],pnames==set(re.findall(r'{(.*?)}',path)))
        check('response_present:'+op['operationId'],bool(op.get('responses')))
for r in refs(api):
    if r.startswith('#/'):resolve(api,r)
check('api_operation_ids_unique',len(ops)==len(set(ops))==19)
check('api_refs_resolve',True)
# This is structural validation, not full OpenAPI semantic validator/codegen.
tasks=load('codex/tasks.json')['tasks'];ids={x['id'] for x in tasks}
check('30_unique_tasks',len(tasks)==len(ids)==30)
visited=set();active=set();d={t['id']:t for t in tasks}
def visit(t):
    if t in active:raise AssertionError('task cycle')
    if t in visited:return
    active.add(t)
    for dep in d[t]['depends_on']:
        if dep not in ids:raise AssertionError('unknown dependency '+dep)
        visit(dep)
    active.remove(t);visited.add(t)
for t in ids:visit(t)
check('task_dependency_DAG',len(visited)==30)
reqs=load('contracts/requirements.json')['requirements'];reqids={r['id'] for r in reqs}
pages=load('contracts/pages.json')['pages'];pageids={p['id'] for p in pages}
expected={f'W{i:02}' for i in range(1,42)}|{f'N{i:02}' for i in range(1,17)}|{f'E{i:02}' for i in range(1,9)}
check('65_pages_complete_and_unique',len(pages)==len(pageids)==65 and pageids==expected)
matrix=load('tests/acceptance-matrix.json')['tests'];testids={t['id'] for t in matrix}
check('150_planned_tests_unique',len(matrix)==len(testids)==150)
check('acceptance_links_valid',all(t['task_id'] in ids and set(t['requirements'])<=reqids and set(t['pages'])<=pageids for t in matrix))
check('all_requirements_covered',set().union(*(set(t['requirements']) for t in matrix))==reqids)
check('all_pages_covered',set().union(*(set(t['pages']) for t in matrix))==pageids)
check('planned_tests_not_claimed_executed',all(t['status']=='PLANNED_NOT_EXECUTED' for t in matrix))
params=load('config/params.reference.json');st=params['staking'];ev=params['evidence'];tr=params['trust'];cs=params['consensus'];ec=params['economics']
check('exit_evidence_time_relationship',st['unbonding_seconds']>ev['max_age_seconds']+tr['max_clock_drift_seconds'])
check('exit_evidence_height_relationship',st['unbonding_blocks']>ev['max_age_blocks'])
check('weak_subjectivity_trust_period',tr['trust_period_seconds']<st['unbonding_seconds'])
check('supply_voting_power_bound',int(ec['supply_technical_cap_atomic'])//int(cs['power_unit_atomic'])<=int(cs['max_total_voting_power']))
check('tx_block_resource_limits',params['transactions']['max_tx_bytes']<=cs['max_block_bytes'] and params['transactions']['max_spends']+params['transactions']['max_outputs']<=cs['max_proofs_per_block'])
check('no_biometrics_or_telemetry',not params['wallet']['biometrics_enabled'] and not params['wallet']['telemetry_enabled'])
check('reference_not_mainnet',not params['runtime']['mainnet_enabled'] and params['network']['privacy_required'])
sources=load('contracts/sources.json');sids={s['id'] for s in sources}
used=set()
for f in list((ROOT/'docs').glob('*.md'))+[ROOT/'README.md',ROOT/'contracts/protocol-extra.md']:
    used|=set(re.findall(r'\[(S\d{2})\]',f.read_text()))
check('source_ids_resolve',used<=sids,str(used-sids))
check('24_unique_sources',len(sids)==len(sources)==24)
check('20_core_chapters',len(list((ROOT/'docs').glob('[0-9][0-9]_*.md')))==20)
# CDDL/proto are not compiled by this lightweight validator.
check('signing_body_memo_explicit','memo-ciphertext: (bstr .size 528) / null' in (ROOT/'contracts/tx_body.cddl').read_text())
check('effect_hash_width_consistent','BLAKE2b-512' in (ROOT/'docs/03_密码学与交易协议.md').read_text())
check('validator_activation_delay_explicit',cs['validator_update_delay_blocks']==2 and 'H+2' in (ROOT/'docs/05_原生质押与处罚.md').read_text())
# Run the independent arithmetic oracle, not any actual chain tests.
sys.path.insert(0,str(ROOT/'reference'))
suite=unittest.defaultTestLoader.discover(str(ROOT/'reference'),pattern='test_*.py')
stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
check('integer_oracle_tests',result.wasSuccessful(),f'{result.testsRun} actual tests')
report={'scope':'documentation structure + independent integer oracle only',
        'checks':checks,'model_tests':result.testsRun,'model_tests_passed':result.wasSuccessful(),
        'not_executed':['actual Rust implementation/build','actual cryptographic proofs or parameter audit','actual multi-node consensus','wallet/node/explorer UI execution','full OpenAPI generator/semantic validator','protoc/buf compilation','CDDL parser compilation','PostgreSQL migration execution','network privacy packet capture','platform installers','external security audit','mainnet launch'],
        'counts':{'chapters':20,'pages':65,'api_operations':19,'local_sdk_methods':len(load('contracts/local_sdk.json')['methods']),'tasks':30,'planned_acceptance_tests':150,'requirements':16,'sources':24}}
(ROOT/'tests/bundle-validation.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
(ROOT/'tests/reference-test-output.txt').write_text(stream.getvalue())
print(json.dumps({'passed_structural_checks':len(checks),'actual_model_tests':result.testsRun,'counts':report['counts'],'scope':report['scope']},ensure_ascii=False,indent=2))
