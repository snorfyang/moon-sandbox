"""Explicit local approval: compile a reviewed guest and pin its exact SHA-256.

This command is an administrator action, not an MCP tool. Review the source,
workspace grant and generated registration before starting server.py.
"""

import argparse
import hashlib
import json
from pathlib import Path

import wasmtime


def register(source: Path, workspace: Path, broker: Path, output: Path) -> dict:
    workspace = workspace.resolve(strict=True)
    broker = broker.resolve(strict=True)
    if not workspace.is_dir() or workspace == Path(workspace.anchor):
        raise ValueError("approve an explicit non-root workspace directory")
    wasm = wasmtime.wat2wasm(source.read_text())
    output.parent.mkdir(parents=True, exist_ok=True)
    artifact = output.with_suffix(".wasm").resolve()
    artifact.write_bytes(wasm)
    registration = {
        "wasm": str(artifact),
        "sha256": hashlib.sha256(wasm).hexdigest(),
        "workspace": str(workspace),
        "broker": str(broker),
        "manifest": {
            "name": "read_text_file",
            "capabilities": ["fs.read"],
            "limits": {
                "timeout_ms": 5000,
                "max_output_bytes": 4096,
                "max_requests": 128,
            },
        },
    }
    output.write_text(json.dumps(registration, indent=2) + "\n")
    return registration


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--broker", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            register(args.source, args.workspace, args.broker, args.output), indent=2
        )
    )
