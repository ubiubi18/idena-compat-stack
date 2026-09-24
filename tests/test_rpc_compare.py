from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("compare_idena_rpc", ROOT / "scripts" / "compare-idena-rpc.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        if request.get("key") != self.server.expected_key:
            payload = {"id": request.get("id"), "error": {"message": "unauthorized"}}
        else:
            height = int(request["params"][0])
            result = (
                None
                if self.server.return_null
                else {
                    "height": height,
                    "header": {"root": f"root-{height}"},
                    "privateRegressionSentinel": self.server.sentinel,
                }
            )
            payload = {
                "id": request.get("id"),
                "result": result,
            }
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class RpcCompareTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.key_path = pathlib.Path(self.temp.name) / "api.key"
        self.key_path.write_text("test-only-key\n", encoding="ascii")
        self.key_path.chmod(0o600)
        self.servers: list[tuple[ThreadingHTTPServer, threading.Thread]] = []

    def tearDown(self) -> None:
        for server, thread in self.servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.temp.cleanup()

    def start_server(self, sentinel: str, *, return_null: bool = False) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.expected_key = "test-only-key"
        server.sentinel = sentinel
        server.return_null = return_null
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}"

    def args(self, legacy_url: str, modern_url: str) -> argparse.Namespace:
        return argparse.Namespace(
            legacy_rpc_url=legacy_url,
            legacy_api_key_file=self.key_path,
            modern_rpc_url=modern_url,
            modern_api_key_file=self.key_path,
            from_height=10,
            to_height=12,
            step=1,
            timeout=5,
            allow_remote_rpc=False,
            quiet=False,
        )

    def test_matching_nodes_pass(self) -> None:
        left = self.start_server("same-public-fixture")
        right = self.start_server("same-public-fixture")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(MODULE.compare(self.args(left, right)), 0)
        self.assertIn("comparison passed blocks=3", output.getvalue())
        self.assertIn("aggregate_sha256=", output.getvalue())
        self.assertNotIn("test-only-key", output.getvalue())

    def test_quiet_mode_prints_only_aggregate_result(self) -> None:
        left = self.start_server("same-public-fixture")
        right = self.start_server("same-public-fixture")
        args = self.args(left, right)
        args.quiet = True
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(MODULE.compare(args), 0)
        rendered = output.getvalue().splitlines()
        self.assertEqual(1, len(rendered))
        self.assertIn("comparison passed blocks=3 from=10 to=12 step=1", rendered[0])
        self.assertRegex(rendered[0], r"aggregate_sha256=[0-9a-f]{64}$")

    def test_mismatch_output_is_redacted(self) -> None:
        left = self.start_server("identity-address-must-not-leak-left")
        right = self.start_server("identity-address-must-not-leak-right")
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(MODULE.compare(self.args(left, right)), 1)
        rendered = error.getvalue()
        self.assertIn("mismatch height=10", rendered)
        self.assertNotIn("must-not-leak", rendered)
        self.assertNotIn("test-only-key", rendered)

    def test_matching_null_blocks_do_not_false_pass(self) -> None:
        left = self.start_server("unused", return_null=True)
        right = self.start_server("unused", return_null=True)
        with self.assertRaisesRegex(
            MODULE.ComparisonError,
            r"block unavailable height=10 side=both",
        ):
            MODULE.compare(self.args(left, right))

    def test_remote_rpc_requires_explicit_opt_in(self) -> None:
        with self.assertRaises(MODULE.ComparisonError):
            MODULE.validate_url("http://192.0.2.10:9009", allow_remote=False)

    def test_permissive_key_file_is_rejected(self) -> None:
        self.key_path.chmod(0o644)
        with self.assertRaises(MODULE.ComparisonError):
            MODULE.read_key(self.key_path)


if __name__ == "__main__":
    unittest.main()
