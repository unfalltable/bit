from pathlib import Path
import hashlib
import json
import unittest

import protocol_oracle as oracle

ROOT = Path(__file__).resolve().parents[1]


class ProtocolOracleTests(unittest.TestCase):
    def test_reference_config_keeps_mainnet_unapproved(self):
        config = json.loads((ROOT / "config/params.reference.json").read_text(encoding="utf-8"))
        mainnet = json.loads((ROOT / "config/mainnet-inputs.template.json").read_text(encoding="utf-8"))
        self.assertEqual(config["spec_version"], "1.2")
        self.assertEqual(config["network"]["chain_id"], "bit-test-cap1024-1")
        self.assertEqual(int(config["economics"]["max_supply_atomic"]), oracle.MAX_SUPPLY_ATOMIC)
        self.assertFalse(config["economics"]["mainnet_economic_policy_approved"])
        self.assertFalse(mainnet["mainnet_ready"])
        self.assertIsNone(mainnet["monetary_policy"]["genesis_supply_atomic"])

    def test_policy_bytes_and_hash(self):
        vector = json.loads((ROOT / "tests/vectors/emission-vectors.json").read_text(encoding="utf-8"))["reference_policy"]
        encoded = oracle.reference_policy()
        self.assertEqual(encoded.hex(), vector["canonical_cbor_hex"])
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), vector["monetary_policy_hash"])

    def test_all_emission_points(self):
        vectors = json.loads((ROOT / "tests/vectors/emission-vectors.json").read_text(encoding="utf-8"))
        policy = vectors["reference_policy"]
        budget = int(policy["max_supply_atomic"]) - int(policy["genesis_atomic"])
        interval = policy["halving_epochs"]
        for point in vectors["reference_points"]:
            epoch = int(point["completed_epochs"])
            self.assertEqual(oracle.scheduled_issuance(budget, interval, epoch), int(point["scheduled_to_date"]))
            self.assertEqual(oracle.quota(budget, interval, epoch), int(point["next_epoch_quota"]))
        small = vectors["manual_small_vector"]
        self.assertEqual([oracle.quota(int(small["budget_atomic"]), small["halving_epochs"], i)
                          for i in range(len(small["quotas_atomic"]))], [int(x) for x in small["quotas_atomic"]])

    def test_transaction_body_effect_and_envelope(self):
        vector = json.loads((ROOT / "tests/vectors/transaction-vectors.json").read_text(encoding="utf-8"))
        body = oracle.structural_body()
        envelope = oracle.structural_envelope(body)
        self.assertEqual(body.hex(), vector["canonical_body_hex"])
        self.assertEqual(oracle.effect_hash(body).hex(), vector["effect_hash_hex"])
        self.assertEqual(envelope.hex(), vector["canonical_envelope_hex"])
        self.assertEqual(hashlib.sha256(envelope).hexdigest(), vector["tx_id_hex"])

    def test_empty_block_artifact_encoding_and_domain_hashes(self):
        vector = json.loads((ROOT / "tests/vectors/block-artifact-vectors.json").read_text(
            encoding="utf-8"))["empty_block"]
        artifact = oracle.empty_block_artifact(
            bytes.fromhex(vector["chain_context_hex"]),
            vector["height"],
            vector["block_time_seconds"],
            bytes.fromhex(vector["shielded_tree_root_hex"]),
        )
        self.assertEqual(artifact.hex(), vector["canonical_cbor_hex"])
        self.assertEqual(
            oracle.block_artifact_hash(b"bit/execution-summary/v1", artifact).hex(),
            vector["execution_hash_hex"],
        )
        self.assertEqual(
            oracle.block_artifact_hash(b"bit/compact-block/v1", artifact).hex(),
            vector["compact_hash_hex"],
        )

    def test_supply_audit_snapshot_encoding(self):
        vector = json.loads((ROOT / "tests/vectors/supply-audit-vectors.json").read_text(
            encoding="utf-8"))["complete_snapshot"]
        values = {
            name: int(vector[name + "_atomic"])
            for name in oracle.SUPPLY_AMOUNT_FIELDS
        }
        values["completed_epochs"] = vector["completed_epochs"]
        values["monetary_policy_hash"] = bytes.fromhex(vector["monetary_policy_hash_hex"])
        encoded = oracle.supply_audit_snapshot(values)
        self.assertEqual(encoded.hex(), vector["canonical_cbor_hex"])
        changed = dict(values)
        changed["current_supply"] -= 1
        with self.assertRaises(ValueError):
            oracle.supply_audit_snapshot(changed)


if __name__ == "__main__":
    unittest.main()
