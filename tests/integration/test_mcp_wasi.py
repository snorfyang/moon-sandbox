"""Real MCP client -> MoonBit authorization -> Wasmtime -> WASI filesystem.

All secrets are temporary test canaries. No real credentials are accessed.
"""

import json
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
import uuid

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from adapters.mcp_wasi.register import register
from adapters.mcp_wasi.server import Adapter, load_registration

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "adapters/mcp_wasi"

BROKER = ROOT / "_build/native/debug/build/cmd/agent-sandbox/agent-sandbox.exe"
SOURCE = ROOT / "guests/wasi-reader/reader.wat"


class McpWasiTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "_build/mcp-wasi-evidence.json").unlink(missing_ok=True)

    def evidence(self, name, value):
        path = ROOT / "_build/mcp-wasi-evidence.json"
        evidence = (
            json.loads(path.read_text())
            if path.exists()
            else {"wasmtime": "49.0.0", "mcp_sdk": "1.26.0", "cases": {}}
        )
        evidence["cases"][name] = value
        path.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.text = "Actual file bytes: MoonSandbox 真实读取\n"
        (self.workspace / "notes.txt").write_text(self.text)
        self.canary = "outside-canary-" + uuid.uuid4().hex
        (self.base / "canary.txt").write_text(self.canary)
        self.reg_path = self.base / "registration.json"
        self.reg = register(SOURCE, self.workspace, BROKER, self.reg_path)
        self.audit = self.base / "audit.jsonl"

    def guest(self, wat):
        source = self.base / "guest.wat"
        source.write_text(wat)
        self.reg = register(source, self.workspace, BROKER, self.reg_path)

    async def mcp_calls(self, paths):
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(ADAPTER / "server.py"), "--registration", str(self.reg_path)],
            env={"MOONSANDBOX_TEST_SECRET": self.canary},
        )
        results = []
        with self.audit.open("w") as errors:
            async with stdio_client(params, errlog=errors) as (read, write):
                async with ClientSession(read, write) as session:
                    initialized = await session.initialize()
                    self.assertEqual(
                        initialized.serverInfo.name, "moonsandbox-wasi-reader"
                    )
                    tools = await session.list_tools()
                    self.assertEqual(
                        [tool.name for tool in tools.tools], ["read_text_file"]
                    )
                    for path in paths:
                        result = await session.call_tool(
                            "read_text_file", {"path": path}
                        )
                        outcome = json.loads(result.content[0].text)
                        self.assertEqual(result.isError, outcome["status"] != "success")
                        self.assertNotIn(self.canary, result.model_dump_json())
                        results.append(outcome)
        return results

    def events(self):
        return [
            json.loads(line)
            for line in self.audit.read_text().splitlines()
            if line.startswith('{"tool":')
        ]

    async def test_real_read_and_policy_denial(self):
        normal, denied = await self.mcp_calls(["notes.txt", "../canary.txt"])
        self.assertEqual(normal, {"status": "success", "text": self.text})
        self.assertEqual(denied["status"], "policy_denied")
        events = self.events()
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["policy"]["decision"], "allow")
        self.assertEqual(events[1]["policy"]["decision"], "deny")
        self.assertNotIn(self.text, self.audit.read_text())
        self.assertNotIn(self.canary, self.audit.read_text())
        self.evidence(
            "normal_read",
            {
                "artifact_sha256": self.reg["sha256"],
                "mcp_outcome": normal,
                "policy": events[0]["policy"],
                "matches_file_bytes": True,
            },
        )
        self.evidence(
            "policy_denial", {"mcp_outcome": denied, "policy": events[1]["policy"]}
        )

    async def test_internal_traversal_is_denied_by_wasi_after_policy_allow(self):
        wat = (
            SOURCE.read_text()
            .replace(
                '(memory (export "memory") 2 2)',
                '(memory (export "memory") 2 2) (data (i32.const 128) "../canary.txt")',
            )
            .replace(
                "(local.set $errno (call $open",
                "(local.set $path (i32.const 128)) (local.set $len (i32.const 13)) (local.set $errno (call $open",
                1,
            )
        )
        self.guest(wat)
        [outcome] = await self.mcp_calls(["notes.txt"])
        self.assertEqual(outcome["status"], "wasi_denied")
        # Preview 1 NOTCAPABLE=76 / PERM=63. Missing-file errors are NOT evidence.
        self.assertIn(outcome["errno"], [63, 76])
        self.assertEqual((self.base / "canary.txt").read_text(), self.canary)
        event = self.events()[0]
        self.assertEqual(event["policy"]["decision"], "allow")
        self.assertEqual(event["execution"], outcome)
        self.assertEqual(event["sha256"], self.reg["sha256"])
        evidence = {
            "case": "internal_traversal",
            "request": "notes.txt",
            "policy": "allow",
            "artifact_sha256": self.reg["sha256"],
            "execution": outcome,
            "canary_exists": True,
            "canary_returned": False,
            "wasmtime": "49.0.0",
        }
        self.evidence("internal_traversal", evidence)

    async def test_symlink_outside_preopen_is_denied(self):
        (self.workspace / "link.txt").symlink_to(self.base / "canary.txt")
        [result] = await self.mcp_calls(["link.txt"])
        self.assertEqual(result["status"], "wasi_denied")
        self.assertIn(result["errno"], [63, 76])
        self.assertEqual(self.events()[0]["policy"]["decision"], "allow")

    async def test_write_from_inside_guest_is_denied(self):
        # Same imported syscall, but guest requests FD_WRITE instead of FD_READ.
        self.guest(
            SOURCE.read_text().replace(
                "(i64.const 2) (i64.const 0)", "(i64.const 64) (i64.const 0)"
            )
        )
        [result] = await self.mcp_calls(["notes.txt"])
        self.assertEqual(result["status"], "wasi_denied")
        self.assertIn(result["errno"], [63, 76])
        self.assertEqual((self.workspace / "notes.txt").read_text(), self.text)

    async def test_environment_is_not_inherited(self):
        self.guest("""(module
          (import "wasi_snapshot_preview1" "environ_sizes_get" (func $env (param i32 i32) (result i32)))
          (memory (export "memory") 2 2)
          (func (export "run") (param i32 i32) (result i32)
            (drop (call $env (i32.const 0) (i32.const 4)))
            (if (i32.or (i32.load (i32.const 0)) (i32.load (i32.const 4)))
              (then (return (i32.const 63))))
            (i32.store (i32.const 8) (i32.const 0)) (i32.const 0)))""")
        [result] = await self.mcp_calls(["notes.txt"])
        self.assertEqual(result, {"status": "success", "text": ""})

    async def test_ungranted_network_interface_cannot_link(self):
        self.guest("""(module
          (import "wasi_snapshot_preview1" "sock_open" (func $network (result i32)))
          (memory (export "memory") 2 2)
          (func (export "run") (param i32 i32) (result i32) (call $network)))""")
        [result] = await self.mcp_calls(["notes.txt"])
        self.assertEqual(result["status"], "backend_error")
        self.assertEqual(result["error_type"], "WasmtimeError")
        self.assertEqual(self.events()[0]["policy"]["decision"], "allow")

    async def test_preview0_and_unused_wasm_extensions_are_rejected(self):
        guests = [
            '(import "wasi_unstable" "poll_oneoff" (func))',
            "(tag (param i32))",
            "(type (struct (field i32)))",
        ]
        for declaration in guests:
            self.guest(
                "(module " + declaration + '(memory (export "memory") 2 2) '
                '(func (export "run") (param i32 i32) (result i32) (i32.const 0)))'
            )
            [result] = await self.mcp_calls(["notes.txt"])
            self.assertEqual(result["status"], "backend_error")
            self.assertEqual(result["error_type"], "WasmtimeError")

    async def test_output_limit_and_instruction_limit(self):
        (self.workspace / "large.txt").write_text("x" * 5000)
        [result] = await self.mcp_calls(["large.txt"])
        self.assertEqual(result["status"], "output_limit")
        self.guest("""(module (memory (export "memory") 2 2)
          (func (export "run") (param i32 i32) (result i32) (loop $again (br $again)) (i32.const 0)))""")
        [result] = await self.mcp_calls(["notes.txt"])
        self.assertEqual(result["status"], "backend_error")
        self.assertEqual(result["error_type"], "Trap")

    async def test_file_content_boundaries_without_silent_truncation(self):
        (self.workspace / "empty.txt").write_bytes(b"")
        (self.workspace / "exact.txt").write_bytes(b"x" * 4096)
        (self.workspace / "huge.txt").write_bytes(b"x" * 100000)
        (self.workspace / "binary.txt").write_bytes(b"\xff")
        empty, exact, huge, binary = await self.mcp_calls(
            [
                "empty.txt",
                "exact.txt",
                "huge.txt",
                "binary.txt",
            ]
        )
        self.assertEqual(empty, {"status": "success", "text": ""})
        self.assertEqual(exact, {"status": "success", "text": "x" * 4096})
        self.assertEqual(huge, {"status": "output_limit"})
        self.assertEqual(binary["status"], "backend_error")
        self.assertEqual(binary["error_type"], "UnicodeDecodeError")

    async def test_worker_wall_clock_timeout(self):
        # Reading a FIFO blocks in a real WASI syscall, so fuel alone is insufficient.
        import os

        os.mkfifo(self.workspace / "blocked")
        self.reg["manifest"]["limits"]["timeout_ms"] = 1000
        self.reg_path.write_text(json.dumps(self.reg))
        [result] = await self.mcp_calls(["blocked"])
        self.assertEqual(result["status"], "timeout")

    async def test_missing_file_is_not_reported_as_permission_denial(self):
        [result] = await self.mcp_calls(["missing.txt"])
        self.assertEqual(result["status"], "wasi_error")
        self.assertEqual(result["errno"], 44)  # NOENT, not a sandbox boundary proof.

    async def test_loaded_artifact_is_the_verified_snapshot(self):
        registration = load_registration(self.reg_path)
        Path(self.reg["wasm"]).write_bytes(b"replaced after registration was loaded")
        adapter = Adapter(registration)
        result = await adapter.call_tool("read_text_file", {"path": "notes.txt"})
        self.assertEqual(
            json.loads(result.content[0].text), {"status": "success", "text": self.text}
        )

    async def test_digest_mismatch_rejected_before_server_start(self):
        Path(self.reg["wasm"]).write_bytes(b"not the approved guest")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            load_registration(self.reg_path)

    async def test_manifest_cannot_expand_the_read_only_backend(self):
        self.reg["manifest"]["capabilities"].append("fs.write")
        self.reg_path.write_text(json.dumps(self.reg))
        with self.assertRaisesRegex(ValueError, "only read_text_file"):
            load_registration(self.reg_path)

    async def test_invalid_broker_configuration_fails_closed(self):
        for policy, manifest in [
            ("not-json", self.reg["manifest"]),
            (
                json.dumps({"rules": []}),
                {"name": "read_text_file", "capabilities": ["fs.read"], "typo": True},
            ),
        ]:
            result = subprocess.run(
                [
                    str(BROKER),
                    "broker",
                    policy,
                    json.dumps(manifest),
                    "fs.read",
                    "workspace/notes.txt",
                ],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            self.assertIn("error", json.loads(result.stdout))

    async def test_client_cannot_supply_permissions_or_change_guest(self):
        params = StdioServerParameters(
            command=sys.executable,
            args=[str(ADAPTER / "server.py"), "--registration", str(self.reg_path)],
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "read_text_file",
                    {"path": "notes.txt", "manifest": {"capabilities": ["fs.write"]}},
                )
                self.assertTrue(result.isError)
                result = await session.call_tool(
                    "unregistered_guest", {"path": "notes.txt"}
                )
                self.assertTrue(result.isError)

    async def test_budgets_persist_across_mcp_calls(self):
        self.reg["manifest"]["limits"]["max_requests"] = 1
        self.reg_path.write_text(json.dumps(self.reg))
        first, second = await self.mcp_calls(["notes.txt", "notes.txt"])
        self.assertEqual(first["status"], "success")
        self.assertEqual(second["status"], "budget_denied")


if __name__ == "__main__":
    unittest.main()
