from __future__ import annotations

import importlib.util
import json
import pathlib
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

    def test_released_status_requires_external_attestation(self) -> None:
        self.payload["status"] = "released"
        with self.assertRaises(MODULE.LockError):
            MODULE.validate_lock(self.payload)


if __name__ == "__main__":
    unittest.main()
