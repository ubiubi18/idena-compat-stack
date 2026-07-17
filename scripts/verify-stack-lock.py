#!/usr/bin/env python3
"""Validate the Idena compatibility stack lock without network access."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any


SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
EVIDENCE_RE = re.compile(
    r"^compatibility/evidence/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\.json$"
)
MAX_JSON_BYTES = 1024 * 1024
FORBIDDEN_KEY_RE = re.compile(
    r"(?:api.?key|password|passwd|secret|token|cookie|private.?key|wallet|mnemonic)",
    re.IGNORECASE,
)
EXPECTED_TOP_LEVEL = {
    "schema",
    "releaseId",
    "status",
    "legacyBaseline",
    "chainInvariants",
    "components",
    "toolchains",
    "artifacts",
    "consumerPins",
    "requiredGates",
    "gateResults",
}
EXPECTED_COMPONENTS = {
    "idena-go",
    "idena-wasm-binding",
    "idena-wasm",
    "wasmer",
    "idena-sdk-js-lite",
}
EXPECTED_ARTIFACTS = {
    "libidena_wasm_linux_amd64.a",
    "libidena_wasm_linux_aarch64.a",
    "libidena_wasm_darwin_amd64.a",
    "libidena_wasm_darwin_arm64.a",
    "libidena_wasm_windows_amd64.a",
}


class LockError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LockError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate object key: {key}")
        result[key] = value
    return result


def parse_json(raw: bytes, label: str) -> Any:
    require(len(raw) <= MAX_JSON_BYTES, f"{label} is unexpectedly large")
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LockError(f"{label} is not valid UTF-8 JSON") from exc


def validate_repository(value: Any, label: str) -> str:
    require(isinstance(value, str), f"{label} must be a string")
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == "https", f"{label} must use HTTPS")
    require(parsed.hostname == "github.com", f"{label} must use github.com")
    require(not parsed.username and not parsed.password, f"{label} contains user info")
    require(not parsed.query and not parsed.fragment, f"{label} contains query or fragment data")
    require(bool(re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git", parsed.path)), f"{label} has an invalid path")
    return value


def reject_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            require(not FORBIDDEN_KEY_RE.search(str(key)), f"forbidden secret-bearing field at {path}.{key}")
            reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{path}[{index}]")
    elif isinstance(value, str):
        lowered = value.lower()
        private_key_markers = (
            "-----begin " + "private key-----",
            "-----begin openssh " + "private key-----",
        )
        require(not any(marker in lowered for marker in private_key_markers), f"private key material at {path}")


def validate_lock(payload: Any) -> None:
    require(isinstance(payload, dict), "stack lock must be an object")
    require(set(payload) == EXPECTED_TOP_LEVEL, "stack lock has missing or unexpected top-level fields")
    reject_secret_fields(payload)

    require(payload["schema"] == 1, "unsupported stack-lock schema")
    require(isinstance(payload["releaseId"], str) and RELEASE_RE.fullmatch(payload["releaseId"]), "invalid releaseId")
    require(payload["status"] in {"candidate", "approved", "retired"}, "invalid release status")

    legacy = payload["legacyBaseline"]
    require(isinstance(legacy, dict) and set(legacy) == {"repository", "commit", "nodeVersion"}, "invalid legacy baseline")
    validate_repository(legacy["repository"], "legacyBaseline.repository")
    require(isinstance(legacy["commit"], str) and SHA1_RE.fullmatch(legacy["commit"]), "invalid legacy commit")
    require(legacy["nodeVersion"] == "1.1.2", "legacy node version must remain 1.1.2")

    invariants = payload["chainInvariants"]
    expected_invariants = {
        "mainnetNetworkId",
        "gossipProtocol",
        "intermediateGenesisHeaderSha256",
        "stateSnapshotSha256",
        "identitySnapshotSha256",
        "consensusChangesAllowed",
    }
    require(isinstance(invariants, dict) and set(invariants) == expected_invariants, "invalid chain invariant set")
    require(invariants["mainnetNetworkId"] == 1, "mainnet network ID changed")
    require(invariants["gossipProtocol"] == "/idena/gossip/1.1.0", "gossip protocol changed")
    require(invariants["consensusChangesAllowed"] is False, "candidate permits consensus changes")
    for field in ("intermediateGenesisHeaderSha256", "stateSnapshotSha256", "identitySnapshotSha256"):
        require(isinstance(invariants[field], str) and SHA256_RE.fullmatch(invariants[field]), f"invalid {field}")

    components = payload["components"]
    require(isinstance(components, list), "components must be a list")
    by_name: dict[str, dict[str, Any]] = {}
    for index, component in enumerate(components):
        require(isinstance(component, dict), f"component {index} must be an object")
        allowed = {"name", "role", "repository", "commit", "runtimeCodeCommit"}
        require(set(component).issubset(allowed), f"component {index} has unexpected fields")
        require({"name", "role", "repository", "commit"}.issubset(component), f"component {index} is incomplete")
        name = component["name"]
        require(isinstance(name, str) and name not in by_name, f"duplicate or invalid component {name!r}")
        validate_repository(component["repository"], f"components[{index}].repository")
        require(isinstance(component["commit"], str) and SHA1_RE.fullmatch(component["commit"]), f"invalid commit for {name}")
        if "runtimeCodeCommit" in component:
            require(SHA1_RE.fullmatch(component["runtimeCodeCommit"]), f"invalid runtime commit for {name}")
        by_name[name] = component
    require(set(by_name) == EXPECTED_COMPONENTS, "required component set changed")

    toolchains = payload["toolchains"]
    require(isinstance(toolchains, dict) and set(toolchains) == {"go", "rust", "node", "npm"}, "invalid toolchain set")
    for name, version in toolchains.items():
        require(isinstance(version, str) and VERSION_RE.fullmatch(version), f"invalid {name} version")

    artifacts = payload["artifacts"]
    require(isinstance(artifacts, list), "artifacts must be a list")
    artifact_names: set[str] = set()
    for index, artifact in enumerate(artifacts):
        require(isinstance(artifact, dict) and set(artifact) == {"name", "sha256"}, f"invalid artifact {index}")
        require(isinstance(artifact["name"], str) and artifact["name"] not in artifact_names, "duplicate artifact")
        require(isinstance(artifact["sha256"], str) and SHA256_RE.fullmatch(artifact["sha256"]), "invalid artifact digest")
        artifact_names.add(artifact["name"])
    require(artifact_names == EXPECTED_ARTIFACTS, "required artifact set changed")

    pins = payload["consumerPins"]
    require(isinstance(pins, dict) and pins, "consumerPins must not be empty")
    for consumer, consumer_pins in pins.items():
        require(isinstance(consumer, str) and isinstance(consumer_pins, dict), "invalid consumer pin set")
        for component_name, commit in consumer_pins.items():
            require(component_name in by_name, f"{consumer} pins unknown component {component_name}")
            require(commit == by_name[component_name]["commit"], f"{consumer} does not pin the locked {component_name} commit")

    gates = payload["requiredGates"]
    require(isinstance(gates, list) and gates, "requiredGates must not be empty")
    require(all(isinstance(gate, str) and RELEASE_RE.fullmatch(gate) for gate in gates), "invalid gate name")
    require(len(set(gates)) == len(gates), "duplicate required gate")

    results = payload["gateResults"]
    require(isinstance(results, dict), "gateResults must be an object")
    require(set(results).issubset(gates), "gateResults contains an undeclared gate")
    for gate, result in results.items():
        require(isinstance(result, dict), f"invalid result for {gate}")
        require(set(result) == {"status", "evidence", "sha256"}, f"invalid result fields for {gate}")
        require(result["status"] == "passed", f"gate {gate} has not passed")
        evidence = result["evidence"]
        require(isinstance(evidence, str) and EVIDENCE_RE.fullmatch(evidence), f"invalid evidence path for {gate}")
        evidence_path = PurePosixPath(evidence)
        require(
            evidence_path.parts[:2] == ("compatibility", "evidence")
            and evidence_path.suffix == ".json"
            and all(part not in {"", ".", ".."} for part in evidence_path.parts),
            f"invalid evidence path for {gate}",
        )
        require(
            isinstance(result["sha256"], str) and SHA256_RE.fullmatch(result["sha256"]),
            f"invalid evidence digest for {gate}",
        )
    if payload["status"] == "approved":
        require(set(results) == set(gates), "approved lock requires passing evidence for every gate")


def verify_gate_evidence(payload: dict[str, Any], lock_path: Path) -> None:
    lock_parent = lock_path.absolute().parent
    repository_root = lock_parent.parent if lock_parent.name == "compatibility" else lock_parent
    for gate, result in payload["gateResults"].items():
        relative = PurePosixPath(result["evidence"])
        evidence_path = repository_root.joinpath(*relative.parts)
        current = repository_root
        for part in relative.parts:
            current = current / part
            require(not current.is_symlink(), f"evidence path for {gate} contains a symlink")
        require(evidence_path.is_file(), f"evidence file for {gate} is missing")
        raw = evidence_path.read_bytes()
        parse_json(raw, f"evidence file for {gate}")
        require(
            hashlib.sha256(raw).hexdigest() == result["sha256"],
            f"evidence digest mismatch for {gate}",
        )


def load_lock(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), "stack lock must be a regular, non-symlink file")
    return parse_json(path.read_bytes(), "stack lock")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("lock", type=Path)
    args = parser.parse_args()
    try:
        payload = load_lock(args.lock)
        validate_lock(payload)
        verify_gate_evidence(payload, args.lock)
    except (OSError, LockError) as exc:
        print(f"stack lock validation failed: {exc}", file=sys.stderr)
        return 1
    print("stack lock validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
