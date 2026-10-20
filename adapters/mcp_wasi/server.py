"""MCP stdio adapter. Local registration is trusted; MCP inputs are untrusted."""

import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool

POLICY = {
    "rules": [{"capability": "fs.read", "pattern": "workspace/**", "decision": "allow"}]
}


def load_registration(path: Path) -> dict:
    value = json.loads(path.read_text())
    if set(value) != {"wasm", "sha256", "workspace", "broker", "manifest"}:
        raise ValueError("invalid registration fields")
    manifest = value["manifest"]
    if set(manifest) != {"name", "capabilities", "limits"}:
        raise ValueError("invalid manifest fields")
    if manifest["name"] != "read_text_file" or manifest["capabilities"] != ["fs.read"]:
        raise ValueError("this backend supports only read_text_file / fs.read")
    limits = manifest["limits"]
    if set(limits) != {"timeout_ms", "max_output_bytes", "max_requests"}:
        raise ValueError("invalid limit fields")
    for key, maximum in [
        ("timeout_ms", 30000),
        ("max_output_bytes", 65535),
        ("max_requests", 10000),
    ]:
        if type(limits[key]) is not int or not 1 <= limits[key] <= maximum:
            raise ValueError("unsupported limit: " + key)
    # Read and hash ONCE; worker receives these exact bytes, never reopens the artifact.
    wasm = Path(value["wasm"]).read_bytes()
    if hashlib.sha256(wasm).hexdigest() != value["sha256"]:
        raise ValueError("artifact digest mismatch")
    workspace = Path(value["workspace"]).resolve(strict=True)
    if not workspace.is_dir() or workspace == Path(workspace.anchor):
        raise ValueError("workspace must be an explicit non-root directory")
    broker = Path(value["broker"]).resolve(strict=True)
    value.update(wasm_bytes=wasm, workspace=str(workspace), broker=str(broker))
    return value


class Adapter:
    def __init__(self, registration: dict):
        self.registration = registration
        self.requests = 0
        self.lock = asyncio.Lock()
        self.server = Server("moonsandbox-wasi-reader")
        self.server.list_tools()(self.list_tools)
        self.server.call_tool()(self.call_tool)

    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="read_text_file",
                description="Read a UTF-8 file in the registered read-only workspace.",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "minLength": 1, "maxLength": 2048}
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            )
        ]

    async def call_tool(self, name: str, arguments: dict) -> CallToolResult:
        if (
            name != "read_text_file"
            or set(arguments) != {"path"}
            or not isinstance(arguments["path"], str)
        ):
            return self.result({"status": "invalid_request"})
        path = arguments["path"]
        if not path or len(path.encode("utf-8")) > 2048 or "\0" in path:
            return self.result({"status": "invalid_request"})
        async with self.lock:
            return await self.evaluate(path)

    async def evaluate(self, path: str) -> CallToolResult:
        reg = self.registration
        limits = reg["manifest"]["limits"]
        event = {"tool": "read_text_file", "resource": path, "sha256": reg["sha256"]}
        if self.requests >= limits["max_requests"]:
            return self.finish(event, {"status": "budget_denied"})
        self.requests += 1
        resource = path if path.startswith(("/", "\\")) else "workspace/" + path
        proc = await asyncio.create_subprocess_exec(
            reg["broker"],
            "broker",
            json.dumps(POLICY),
            json.dumps(reg["manifest"]),
            "fs.read",
            resource,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            decision = json.loads(stdout)
        except (TimeoutError, ValueError):
            return self.finish(event, {"status": "broker_error"})
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
        event["policy"] = decision
        if proc.returncode != 0 or decision.get("decision") != "allow":
            return self.finish(event, {"status": "policy_denied"})
        payload = {
            "wasm": base64.b64encode(reg["wasm_bytes"]).decode("ascii"),
            "workspace": reg["workspace"],
            "path": path,
            "max_output_bytes": limits["max_output_bytes"],
        }
        worker = await asyncio.create_subprocess_exec(
            sys.executable,
            str(Path(__file__).with_name("backend.py")),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _ = await asyncio.wait_for(
                worker.communicate(json.dumps(payload).encode()),
                timeout=limits["timeout_ms"] / 1000,
            )
            outcome = json.loads(stdout)
        except TimeoutError:
            outcome = {"status": "timeout"}
        except ValueError:
            outcome = {"status": "backend_error"}
        finally:
            if worker.returncode is None:
                worker.kill()
                await worker.wait()
        if worker.returncode != 0 and outcome["status"] != "timeout":
            outcome = {"status": "backend_error"}
        return self.finish(event, outcome)

    def finish(self, event: dict, outcome: dict) -> CallToolResult:
        # Separate policy authorization from actual execution. Never audit returned content.
        event["execution"] = {
            key: value for key, value in outcome.items() if key != "text"
        }
        print(json.dumps(event, ensure_ascii=True), file=sys.stderr, flush=True)
        return self.result(outcome)

    @staticmethod
    def result(outcome: dict) -> CallToolResult:
        return CallToolResult(
            content=[
                TextContent(type="text", text=json.dumps(outcome, ensure_ascii=True))
            ],
            isError=outcome["status"] != "success",
        )

    async def run(self):
        async with stdio_server() as (read, write):
            await self.server.run(
                read, write, self.server.create_initialization_options()
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(Adapter(load_registration(args.registration)).run())
