# Getting started

MoonSandbox ships a MoonBit control plane and a separately installed MCP → Wasmtime read-only file adapter. The library evaluates a tool manifest and capability request against a default-deny policy. The adapter executes a registered WASI reference guest; arbitrary native commands and existing native MCP servers are not isolated. See [the real execution walkthrough](mcp-wasi.md) for installation and end-to-end tests.

## Run the control-plane demo

```bash
moon fmt --warn
moon check --deny-warn
moon test --deny-warn

moon run src/cmd/agent-sandbox -- policy
moon run src/cmd/agent-sandbox -- check --cap fs.read --resource workspace/src/main.mbt
moon run src/cmd/agent-sandbox -- check --cap fs.read --resource ../.ssh/id_rsa
moon run src/cmd/agent-sandbox -- audit-demo
```

`check` demonstrates policy matching. `audit-demo` demonstrates the complete manifest → request → decision → audit-event path.

## Library shape

```moonbit
let policy = @agent_tool_sandbox.project_policy()
let manifest = @agent_tool_sandbox.ToolManifest::new(
  "reader",
  [@agent_tool_sandbox.FsRead],
)
let request = @agent_tool_sandbox.Request::new(
  "reader",
  @agent_tool_sandbox.FsRead,
  "workspace/src/main.mbt",
)
let (decision, event) = @agent_tool_sandbox.authorize_manifest(
  policy,
  manifest,
  request,
)
println(@agent_tool_sandbox.audit_event_json(event))
```

The manifest check and policy check are separate. A tool cannot gain a capability merely because a broad policy rule exists; it must declare that capability first.

## Policy file

`examples/policy.json` is the machine-readable shape planned for the next CLI milestone. The current `policy` command prints the equivalent starter policy so the MVP remains dependency-free at the command boundary.

The library already accepts this format through `policy_from_json`. For tool declarations, pass the contents of [reader-manifest.json](../examples/reader-manifest.json) to `tool_manifest_from_json`. See [configuration validation](configuration.md) for the accepted fields and rejection rules. The CLI does not yet load these files.

## Broker command

The native `agent-sandbox broker <policy-json> <manifest-json> <capability> <resource>` command emits one JSON authorization event, or a JSON `error` object for invalid configuration. The MCP adapter passes trusted local registration data; this command itself is a decision API and never executes a tool.
