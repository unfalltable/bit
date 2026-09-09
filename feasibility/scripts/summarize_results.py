"""Derive a scoped summary from the recorded runs; does not run or replace tests."""
from pathlib import Path
import datetime as dt
import hashlib
import json
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / 'reports'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


if __name__ == '__main__':
    proof = json.loads((REPORTS / 'proof-result.json').read_text(encoding='utf-8'))
    network = json.loads((REPORTS / 'network-result.json').read_text(encoding='utf-8'))
    unit_log = (REPORTS / 'consensus-unit.log').read_text(encoding='utf-8-sig')
    matches = re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed;', unit_log)
    unit = {'status': 'NO_RESULT'}
    if matches:
        status, passed, failed = matches[-1]
        unit = {'status': 'PASS' if status == 'ok' and int(failed) == 0 else 'FAIL',
                'passed': int(passed), 'failed': int(failed)}
    metrics = {}
    if proof.get('status') == 'PASS':
        probe = proof['probe']
        for field in ['two_spend_two_output_proving_ms', 'strict_verification_ms']:
            values = [sample[field] for sample in probe['samples']]
            metrics[field] = {'samples': len(values), 'min': min(values),
                              'median': statistics.median(values), 'max': max(values)}
        metrics['parameter_load_ms'] = probe['parameter_load_ms']
        metrics['observed_peak_working_set_mib'] = proof['peak_working_set_bytes'] / 2**20
        scan = probe['scan']
        metrics['scan'] = dict(scan, average_payload_bytes=scan['protobuf_bytes_total'] / scan['payloads'])
        metrics['conditional_payload_volume'] = {
            'assumptions': '20 transactions/s, 2 outputs/transaction, measured NotePayload bytes only',
            'decimal_gb_per_day': 20 * 2 * metrics['scan']['average_payload_bytes'] * 86400 / 10**9,
            'not_measured_network_traffic': True,
        }
        metrics['complete_transfer'] = probe.get('complete_transfer')
    inputs = ['proof-result.json', 'network-result.json', 'consensus-unit.log',
              'proof-parameter-downloads.json']
    summary = {
        'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(),
        'overall_scope': 'PARTIAL_FEASIBILITY_ONLY',
        'proof_primitives': proof.get('status', 'NO_RESULT'),
        'empty_block_consensus': network.get('status', 'NO_RESULT'),
        'integer_unit_tests': unit,
        'mobile': proof.get('probe', {}).get('mobile', 'NO_RESULT'),
        'metrics': metrics,
        'unverified': ['non-Transfer action authorization and execution', 'single-asset closure across all actions',
                       'JMT/RocksDB and state proofs', 'separate durable signer',
                       'staking/slashing/fees', 'Tor and mobile', 'production acceptance'],
        'inputs': [{'path': name, 'sha256': digest(REPORTS / name)} for name in inputs],
    }
    target = REPORTS / 'feasibility-summary.json'
    target.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=2))
