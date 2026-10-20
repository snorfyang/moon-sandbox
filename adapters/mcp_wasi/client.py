"""Minimal real MCP client for the registered WASI reader."""

import argparse
import asyncio
import json
from pathlib import Path
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def call(registration: Path, path: str):
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            str(Path(__file__).with_name("server.py")),
            "--registration",
            str(registration.resolve()),
        ],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            initialization = await session.initialize()
            tools = await session.list_tools()
            result = await session.call_tool("read_text_file", {"path": path})
            print(
                json.dumps(
                    {
                        "protocol": initialization.protocolVersion,
                        "tools": [tool.name for tool in tools.tools],
                        "result": result.model_dump(mode="json", exclude_none=True),
                    },
                    ensure_ascii=False,
                )
            )
            return result.isError


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registration", type=Path, required=True)
    parser.add_argument("--path", required=True)
    args = parser.parse_args()
    raise SystemExit(1 if asyncio.run(call(args.registration, args.path)) else 0)
