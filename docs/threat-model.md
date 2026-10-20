# Threat model

## Protected boundary

MoonSandbox has a MoonBit capability policy control plane and a reference MCP/WASI file-tool backend. The adapter instantiates only the administrator-approved artifact with one read-only directory. The guest can ignore requested parameters, but its WASI calls remain bounded by that directory. The adapter, registration, MoonBit executable, Python runtime and Wasmtime are trusted. See [the execution contract](mcp-wasi.md).

## Threats addressed

- A tool requests a path outside the workspace.
- A tool uses `..`, an absolute path or a backslash path to escape a relative root.
- A tool requests a capability it did not declare in its manifest.
- A tool name is confused with another registered tool.
- A policy has no matching rule.
- A WASI guest directly tries to read outside its preopened directory, follows an outside symlink, or requests write rights: integration-tested backend refusal.
- An artifact is replaced before loading: digest mismatch rejects startup.
- A guest tries to inherit host environment or open an unprovided network interface: no capability supplied.

## Threats outside the MVP

- A native Agent process that already has host privileges.
- Kernel, hypervisor, WASM runtime or hardware vulnerabilities.
- Prompt injection contained in tool output after the runtime returns it to a model.
- Domain-level network egress enforcement; this backend supplies no network-creation interface.
- Fine-grained file restrictions within a granted directory; this backend authorizes its entire subtree.
- Approval token reuse prevention; approval tokens are not implemented.
- Every internal guest syscall appearing in audit: current audit records the submitted request and tool outcome, not a syscall trace.
- Secret scanning or data-loss prevention.

## Security invariants

1. No matching rule means `Deny`.
2. A tool must declare a capability before policy evaluation can allow it.
3. Filesystem requests must normalize successfully before matching.
4. Every evaluated request can produce a stable audit event.
5. The policy layer never treats a natural-language tool description as authority.

Native MCP servers remain outside the isolation boundary. Proxying `tools/call`, trusting MCP annotations, or validating a native server’s input paths is insufficient to constrain its internal host access. No automatic native fallback exists.
