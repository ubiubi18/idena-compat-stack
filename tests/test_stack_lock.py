from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_stack_lock", ROOT / "scripts" / "verify-stack-lock.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class StackLockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = json.loads((ROOT / "stack-lock.json").read_text(encoding="utf-8"))

    def test_repository_lock_is_valid(self) -> None:
        MODULE.validate_lock(self.payload)

    def test_repository_lock_pins_rc12_runtime(self) -> None:
        self.assertEqual(
            self.payload["releaseId"],
            "idena-mainnet-legacy-compat-2026.09.24-rc12",
        )
        node = next(
            component
            for component in self.payload["components"]
            if component["name"] == "idena-go"
        )
        self.assertEqual(
            node["runtimeCodeCommit"],
            "a5f43a9f68b10b6f45dc3877d4c6309b9ee9bc3d",
        )

    def test_consensus_change_opt_in_is_rejected(self) -> None:
        self.payload["chainInvariants"]["consensusChangesAllowed"] = True
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(self.payload)

    def test_consumer_drift_is_rejected(self) -> None:
        self.payload["consumerPins"]["idena-desktop"]["idena-go"] = "0" * 40
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(self.payload)

    def test_secret_bearing_fields_are_rejected(self) -> None:
        self.payload["apiKey"] = "must-not-appear"
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(self.payload)

    def test_approved_status_requires_every_gate_result(self) -> None:
        self.payload["status"] = "approved"
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(self.payload)

    def test_undeclared_gate_result_is_rejected(self) -> None:
        self.payload["gateResults"]["not-a-required-gate"] = {
            "status": "passed",
            "evidence": "compatibility/evidence/not-a-required-gate.json",
            "sha256": "0" * 64,
        }
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(self.payload)

    def test_duplicate_lock_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock = pathlib.Path(temporary) / "stack-lock.json"
            lock.write_text('{"schema":1,"schema":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.LockError, "duplicate object key"):
                MODULE.load_lock(lock)

    def test_approved_evidence_is_checksum_bound(self) -> None:
        raw = b'{"gate":"unit-tests","status":"passed"}\n'
        self.payload["requiredGates"] = ["unit-tests"]
        self.payload["gateResults"] = {
            "unit-tests": {
                "status": "passed",
                "evidence": "compatibility/evidence/unit-tests.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        }
        self.payload["status"] = "approved"
        MODULE.validate_lock(self.payload)

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            evidence = root / "compatibility" / "evidence" / "unit-tests.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(raw)
            MODULE.verify_gate_evidence(self.payload, root / "stack-lock.json")

            evidence.write_bytes(b'{"gate":"unit-tests","status":"failed"}\n')
            with self.assertRaisesRegex(MODULE.LockError, "digest mismatch"):
                MODULE.verify_gate_evidence(self.payload, root / "stack-lock.json")

    def test_evidence_symlink_is_rejected(self) -> None:
        raw = b'{"gate":"unit-tests","status":"passed"}\n'
        self.payload["requiredGates"] = ["unit-tests"]
        self.payload["gateResults"] = {
            "unit-tests": {
                "status": "passed",
                "evidence": "compatibility/evidence/unit-tests.json",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            evidence_dir = root / "compatibility" / "evidence"
            evidence_dir.mkdir(parents=True)
            target = root / "outside.json"
            target.write_bytes(raw)
            (evidence_dir / "unit-tests.json").symlink_to(target)
            with self.assertRaisesRegex(MODULE.LockError, "contains a symlink"):
                MODULE.verify_gate_evidence(self.payload, root / "stack-lock.json")


if __name__ == "__main__":
    unittest.main()
