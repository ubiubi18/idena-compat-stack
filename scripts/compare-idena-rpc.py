#!/usr/bin/env python3
"""Compare canonical block RPC responses from legacy and compatibility nodes."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


MAX_KEY_BYTES = 512
MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class ComparisonError(RuntimeError):
    pass


def read_key(path: Path) -> str:
    if path.is_symlink():
        raise ComparisonError("RPC key file must not be a symlink")
    try:
        metadata = path.stat()
    except OSError as exc:
        raise ComparisonError("RPC key file is not readable") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
        raise ComparisonError("RPC key file must be regular and mode 0600")
    raw = path.read_bytes()
    if not 0 < len(raw) <= MAX_KEY_BYTES:
        raise ComparisonError("RPC key file has an invalid size")
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ComparisonError("RPC key file is not ASCII") from exc
    if not value or any(character.isspace() for character in value):
        raise ComparisonError("RPC key has an invalid format")
    return value


def validate_url(value: str, allow_remote: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ComparisonError("RPC URL must be plain HTTP without embedded credentials")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ComparisonError("RPC URL contains unsupported path, query, or fragment data")
    try:
        address = ipaddress.ip_address(parsed.hostname)
        is_loopback = address.is_loopback
    except ValueError:
        is_loopback = parsed.hostname.lower() == "localhost"
    if not allow_remote and not is_loopback:
        raise ComparisonError("RPC URL must use loopback unless --allow-remote-rpc is explicit")
    return value


def read_response(response: Any) -> Any:
    length = response.headers.get("Content-Length")
    if length is not None and int(length) > MAX_RESPONSE_BYTES:
        raise ComparisonError("RPC response exceeds the size limit")
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ComparisonError("RPC response exceeds the size limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ComparisonError("RPC response is not valid JSON") from exc


class RpcClient:
    def __init__(self, url: str, key_file: Path, allow_remote: bool, timeout: int) -> None:
        self.url = validate_url(url, allow_remote)
        self.key = read_key(key_file)
        self.timeout = timeout

    def call(self, method: str, params: list[Any], request_id: int) -> Any:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "key": self.key, "method": method, "params": params},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = read_response(response)
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            raise ComparisonError("RPC request failed") from exc
        if not isinstance(payload, dict) or payload.get("error") is not None or "result" not in payload:
            raise ComparisonError("RPC returned an error or malformed response")
        return payload["result"]


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def first_difference(left: Any, right: Any, path: str = "$") -> str:
    if type(left) is not type(right):
        return path
    if isinstance(left, dict):
        keys = sorted(set(left) | set(right))
        for key in keys:
            child = f"{path}.{key}"
            if key not in left or key not in right:
                return child
            difference = first_difference(left[key], right[key], child)
            if difference:
                return difference
        return ""
    if isinstance(left, list):
        if len(left) != len(right):
            return f"{path}.length"
        for index, (left_item, right_item) in enumerate(zip(left, right)):
            difference = first_difference(left_item, right_item, f"{path}[{index}]")
            if difference:
                return difference
        return ""
    return "" if left == right else path


def compare(args: argparse.Namespace) -> int:
    legacy = RpcClient(args.legacy_rpc_url, args.legacy_api_key_file, args.allow_remote_rpc, args.timeout)
    modern = RpcClient(args.modern_rpc_url, args.modern_api_key_file, args.allow_remote_rpc, args.timeout)
    checked = 0
    aggregate = hashlib.sha256()
    for height in range(args.from_height, args.to_height + 1, args.step):
        legacy_block = legacy.call("bcn_blockAt", [height], height)
        modern_block = modern.call("bcn_blockAt", [height], height)
        if legacy_block is None or modern_block is None:
            if legacy_block is None and modern_block is None:
                side = "both"
            elif legacy_block is None:
                side = "legacy"
            else:
                side = "modern"
            raise ComparisonError(
                f"block unavailable height={height} side={side}"
            )
        left_digest = digest(legacy_block)
        right_digest = digest(modern_block)
        if left_digest != right_digest:
            difference = first_difference(legacy_block, modern_block) or "$"
            print(
                f"mismatch height={height} path={difference} legacy_sha256={left_digest} modern_sha256={right_digest}",
                file=sys.stderr,
            )
            return 1
        checked += 1
        aggregate.update(f"{height}:{left_digest}\n".encode("ascii"))
        if not args.quiet:
            print(f"match height={height} sha256={left_digest}")
    print(
        f"comparison passed blocks={checked} from={args.from_height} "
        f"to={args.to_height} step={args.step} aggregate_sha256={aggregate.hexdigest()}"
    )
    return 0


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-rpc-url", default="http://127.0.0.1:9009")
    parser.add_argument("--legacy-api-key-file", type=Path, required=True)
    parser.add_argument("--modern-rpc-url", default="http://127.0.0.1:9010")
    parser.add_argument("--modern-api-key-file", type=Path, required=True)
    parser.add_argument("--from-height", type=positive_int, required=True)
    parser.add_argument("--to-height", type=positive_int, required=True)
    parser.add_argument("--step", type=positive_int, default=1)
    parser.add_argument("--timeout", type=positive_int, default=20)
    parser.add_argument("--allow-remote-rpc", action="store_true")
    parser.add_argument("--quiet", action="store_true", help="print only the aggregate comparison result")
    args = parser.parse_args()
    if args.to_height < args.from_height:
        parser.error("--to-height must be greater than or equal to --from-height")
    try:
        return compare(args)
    except (ComparisonError, ValueError) as exc:
        print(f"comparison failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
