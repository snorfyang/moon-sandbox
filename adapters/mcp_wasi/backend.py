"""Trusted Wasmtime worker. stdin is a private host-to-worker envelope, not MCP.

Guest code gets only WASI Preview 1 and one read-only directory preopen. It never
receives Python callbacks for file access. Network interfaces, environment,
stdio inheritance and native process execution are not enabled.
"""

import base64
import json
import struct
import sys

import wasmtime


def execute(payload: dict) -> dict:
    config = wasmtime.Config()
    config.consume_fuel = True
    # Reference ABI needs only core scalar Wasm. Explicitly turn off extensions,
    # including the upstream exception/GC advisory's documented workaround.
    for feature in (
        "wasm_exceptions",
        "wasm_gc",
        "wasm_function_references",
        "wasm_threads",
        "wasm_memory64",
        "wasm_multi_memory",
        "wasm_simd",
        "wasm_relaxed_simd",
        "wasm_tail_call",
        "wasm_stack_switching",
        "wasm_component_model",
    ):
        setattr(config, feature, False)
    engine = wasmtime.Engine(config)
    module = wasmtime.Module(engine, base64.b64decode(payload["wasm"], validate=True))
    allowed = {"path_open", "fd_read", "fd_close", "environ_sizes_get"}
    for imported in module.imports:
        if imported.module != "wasi_snapshot_preview1" or imported.name not in allowed:
            raise wasmtime.WasmtimeError(
                "interface is not granted by the reference backend"
            )
    wasi = wasmtime.WasiConfig()
    wasi.preopen_dir(payload["workspace"], "/workspace", fs_mutable=False)
    # No inherit_env/network/stdio calls. Only the directory above is granted.
    store = wasmtime.Store(engine)
    store.set_limits(memory_size=131072, memories=1, tables=1, table_elements=1024)
    store.set_fuel(1_000_000)
    store.set_wasi(wasi)
    linker = wasmtime.Linker(engine)
    linker.define_wasi()
    instance = linker.instantiate(store, module)
    exports = instance.exports(store)
    path = payload["path"].encode("utf-8")
    if not path or len(path) > 2048 or b"\0" in path:
        return {"status": "invalid_path"}
    memory = exports["memory"]
    memory.write(store, path, 1024)
    errno = exports["run"](store, 1024, len(path))
    if errno:
        return {
            "status": "wasi_denied" if errno in (63, 76) else "wasi_error",
            "errno": errno,
        }
    size = struct.unpack("<I", memory.read(store, 8, 12))[0]
    if size > payload["max_output_bytes"] or size > 65535:
        return {"status": "output_limit"}
    data = bytes(memory.read(store, 4096, 4096 + size))
    return {"status": "success", "text": data.decode("utf-8", errors="strict")}


if __name__ == "__main__":
    try:
        result = execute(json.load(sys.stdin))
    except (Exception, wasmtime.Trap) as exc:
        # Do not expose raw host paths, arbitrary trap messages, or file content.
        result = {"status": "backend_error", "error_type": type(exc).__name__}
    print(json.dumps(result, ensure_ascii=True))
