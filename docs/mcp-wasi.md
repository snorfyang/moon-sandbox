# Real MCP → WASI file-tool execution

This adapter implements one real MCP tool, `read_text_file`. It speaks MCP stdio using the official Python SDK, asks the MoonBit broker to authorize requests, and executes a registered WebAssembly file reader inside Wasmtime. Successful results contain actual UTF-8 file bytes. This is a new reference tool, not an unchanged integration of the official Node.js Filesystem MCP server.

## Trust and execution path

```text
Local administrator reviews guest + approves one directory
  → register.py compiles WASM and records its SHA-256 in local registration
MCP client initialize → tools/list → tools/call(path)
  → trusted adapter selects the registered artifact and fs.read mapping
  → native MoonBit broker validates manifest + evaluates policy
  → DENY / ASK: no WASI execution
  → ALLOW: new Wasmtime worker, exact verified WASM bytes
      → one read-only preopen, no inherited environment or sockets
      → guest calls real WASI path_open / fd_read
  → MCP result + separate policy/execution audit on stderr
```

The administrator-controlled registration is the source of grants. It binds `read_text_file`, an exact WASM SHA-256, the host directory, MoonBit broker executable, and limits. Changing the artifact requires explicit re-registration. This is digest pinning, not a signature or proof that the code is safe. The adapter hashes and loads bytes once and sends those same bytes to the worker, avoiding a second artifact-path read after verification.

The registration, adapter, broker, Wasmtime and Python runtime are trusted. They must be outside directories an untrusted process can modify. The MCP client cannot select an artifact, set capabilities, change the directory or pass its own manifest. Tool descriptions and schemas never grant permissions. A malicious guest is allowed to ignore the requested path; the execution backend must still enforce the granted directory.

## Supported scope

- Exactly one administrator-approved directory, exposed read-only; the entire subtree is authorized. The fixed MoonBit policy is `fs.read workspace/** allow`, default deny otherwise. More restrictive per-file policies are not supported by this backend: a module can read other files inside its grant.
- An explicit reference guest ABI: exported memory, `run(path_pointer, path_length)`, WASI Preview 1, output length at address 8, output data at 4096. This is not a general WIT/Component Model implementation.
- The original guest is written in WebAssembly text and compiled to WASM. MoonBit implements configuration validation, capability policy, manifest checks and policy audit; Python implements the MCP SDK adapter, registration and Wasmtime lifecycle. The reference reader is not a MoonBit WASI compiler integration.
- Fresh instance per allowed call; 128 KiB guest memory, one million fuel, maximum output 65535 bytes, administrator-selected output cap and worker wall-clock timeout. The SDK and trusted worker are ordinary native processes; the untrusted guest is the isolated unit.
- No inherited environment, stdio, socket descriptors or socket-creation interface. This demonstrates missing network capability, not domain-based egress filtering. Worker termination bounds blocking WASI reads; fuel alone would not.
- Adapter session request count is enforced across MCP calls. The MoonBit CLI broker is a fresh decision per call; it does not persist the Python adapter's session budget.
- Timeout includes worker startup. OS/runtime escapes, host compromise, another host process mutating granted files or directories, and malicious text returned to a model are outside this boundary.
- No isolation for an arbitrary existing native MCP server, no automatic conversion of MCP descriptions to grants, no write tools and no one-time approval tokens. `ask` is fail-closed, not interactive approval.

## Reproduce

Requirements: MoonBit native toolchain, Python 3.12 and uv 0.8.17 (CI pins the latter and installs dependencies from the committed lockfile).

```bash
moon check --deny-warn
moon test --deny-warn
moon build --target native
uv sync --frozen --project adapters/mcp_wasi --python 3.12
adapters/mcp_wasi/.venv/bin/python -m unittest discover -s tests/integration -v
```

The integration suite uses the official MCP client and creates temporary files and random canaries. It never touches real SSH keys, home-directory secrets or external services. It performs actual initialize, tool discovery and calls; it does not replace WASI syscalls with a fake file backend. Results are also written to `_build/mcp-wasi-evidence.json` and uploaded by CI.

| Case | Policy | Actual execution |
| --- | --- | --- |
| Read `notes.txt` | Allow | Returns exact file text |
| Request `../canary.txt` | Deny | Worker not started |
| Legal `notes.txt` request; malicious guest internally opens `../canary.txt` | Allow | WASI permission error, canary never returned |
| Legal path is symlink to outside canary | Allow | WASI permission error |
| Guest requests write rights on a readable file | Allow for the submitted read request | WASI permission error |
| Guest queries environment | Allow for the submitted read request | Zero variables, including no inherited test secret |
| Guest imports socket creation | Allow for the submitted read request | Linking fails because that interface is absent |
| Guest blocks opening a FIFO | Allow | Worker killed on wall-clock timeout |
| Output exceeds the registered cap | Allow | No content returned; `output_limit` |
| Guest loops forever | Allow | Fuel exhaustion trap |
| Artifact bytes changed before startup | No call | Registration rejected |
| Artifact file changed after loading | Allow | Executes original verified bytes |

Permission cases assert WASI Preview 1 `PERM` (63) or `NOTCAPABLE` (76), not `NOENT` (44). A separate test checks that a genuinely missing file is classified as `wasi_error`, not permission denial. The backend reports guest-supplied return codes; errno alone is not an attestation for arbitrary malicious modules. The negative fixtures execute the real imported syscall and propagate its actual return value. Wasmtime resource configuration, not a guest claim, is the isolation mechanism.

## Manual MCP call

From the repository root, using a disposable directory:

```bash
mkdir -p _build/mcp-demo/workspace
printf 'Real file contents\n' > _build/mcp-demo/workspace/notes.txt
adapters/mcp_wasi/.venv/bin/python adapters/mcp_wasi/register.py \
  --source guests/wasi-reader/reader.wat \
  --workspace _build/mcp-demo/workspace \
  --broker _build/native/debug/build/cmd/agent-sandbox/agent-sandbox.exe \
  --output _build/mcp-demo/registration.json
adapters/mcp_wasi/.venv/bin/python adapters/mcp_wasi/client.py \
  --registration _build/mcp-demo/registration.json --path notes.txt
```

The registration command is an explicit local administrator action. Keep generated registrations and their absolute host paths out of Git. To reproduce the internal-bypass case, run the integration test `test_internal_traversal_is_denied_by_wasi_after_policy_allow`; it compiles and registers the deliberately malicious fixture, sends the legal MCP request, then checks the real WASI error and canary exclusion.

## Audit and dependencies

Stdout is reserved for MCP. Stderr receives JSON audit events containing tool, requested path, registered artifact digest, the MoonBit policy event and a separate execution status. Returned file contents and canary bytes are not logged. Requested paths can themselves be sensitive; stderr collection and retention are the administrator's responsibility. SDK diagnostic lines may also appear on stderr.

The dependencies are pinned to MCP Python SDK 1.26.0 and Wasmtime 49.0.0, with transitive packages locked in `adapters/mcp_wasi/uv.lock`. We use these projects rather than implement their protocols or VM. The WAT reference guest and integration fixtures are project-owned implementations. Upstream references:

- [Official MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/tree/v1.26.0), MIT license.
- [Wasmtime Python bindings](https://github.com/bytecodealliance/wasmtime-py/tree/49.0.0), Apache-2.0 with LLVM exception.
- [Wasmtime Python WASI configuration API](https://bytecodealliance.github.io/wasmtime-py/).
- [Official Filesystem MCP server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem), behavioral reference only; its source is not copied or run here.

### Restricted runtime features

The Python wheel is pinned to 49.0.0. Wasmtime's native core has newer patch releases; the Python wheel must not be represented as those patched releases. This reference backend disables exceptions, GC, function references, threads, memory64, multiple memories, SIMD, tail calls, stack switching and component support. Its import allowlist contains only `wasi_snapshot_preview1.path_open`, `fd_read`, `fd_close` and `environ_sizes_get`; Preview 0 interfaces are rejected. Integration tests check that exception/GC modules and Preview 0 imports fail closed.

Disabling exceptions follows the upstream workaround for [GHSA-hw8m-q44c-ggrf](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-hw8m-q44c-ggrf). Rejecting Preview 0 imports removes the interface implicated in [GHSA-j366-h8gg-77pm](https://github.com/bytecodealliance/wasmtime/security/advisories/GHSA-j366-h8gg-77pm). These restrictions are not a claim that the runtime is free of other vulnerabilities. Keep the lockfile and runtime review current before expanding the accepted guest ABI or import surface.
