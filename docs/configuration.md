# Configuration validation

The library accepts JSON through `policy_from_json` and `tool_manifest_from_json`. Both return `Result`; callers must handle errors before installing a configuration. Unknown object fields are rejected so misspelled restrictions cannot silently disappear. There is currently no schema-version field; version negotiation is future work.

## Policy

The root accepts only `rules`, an array. Each rule accepts exactly `capability`, `pattern`, and `decision`, all required strings. The capability must be `fs.read`, `fs.write`, `net.connect`, or `env.read`; the decision must be `allow`, `deny`, or `ask`.

Patterns must be nonempty, relative, and free of backslashes or `..`. Matching supports exact values, `**`, and a trailing `/**`. Rules are evaluated in order; the last matching rule wins. An empty rule array denies every request.

See [policy.json](../examples/policy.json).

## Manifest

The root accepts `name`, `capabilities`, and optional `limits`. A name must be nonempty. Capabilities must be a nonempty array of supported capability names without duplicates. Duplicate capabilities also fail validation for manifests built directly through the library.

If `limits` is omitted, defaults apply. If supplied, all three fields are required and unknown fields are rejected:

| Field | Default | Accepted value |
| --- | --- | --- |
| `timeout_ms` | 30000 | Integer from 1 through 2147483647 |
| `max_output_bytes` | 1048576 | Integer from 1 through 2147483647 |
| `max_requests` | 128 | Integer from 1 through 2147483647 |

Fractional numbers, overflow, strings, null and nonpositive values fail parsing. Values are checked before integer conversion so they cannot be silently truncated or clamped. Integral JSON numbers such as `1.0` have integer semantics and are accepted.

The MoonBit control-plane `Runtime` enforces only `max_requests`. It does not launch modules. The optional [MCP/WASI adapter](mcp-wasi.md) additionally enforces output bytes, worker wall-clock timeout and a persistent adapter session budget, with a smaller supported registration range documented there.

See [reader-manifest.json](../examples/reader-manifest.json).
