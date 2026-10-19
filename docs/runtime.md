# Runtime contract

`Runtime` is the MVP control-plane facade for one tool session. It composes four checks:

1. the policy must validate;
2. the tool manifest must validate;
3. the request must be declared by the manifest and match the policy;
4. the manifest request budget must not be exhausted.

Every evaluated request is appended to the session's JSONL-compatible audit log. A future WASM/WASI backend will consume the approved capability set after this control-plane decision; the current runtime does not execute native commands.

`Runtime::new` snapshots the policy rule array and the manifest capability array after validation. Changing arrays held by the caller cannot grant or revoke permissions in an existing session. Create a new runtime to install updated policy or declarations.

All evaluated requests consume one request-budget slot, including denied requests and `ask` decisions. Once the budget is exhausted, further requests are denied without incrementing the counter. Every call appends exactly one event, retaining the submitted tool name, capability and resource even when the budget is exhausted. A denied final request reports its authorization result; it does not produce a second budget-exhaustion event.

Audit strings use the standard JSON serializer, including escaping all U+0000–U+001F control characters. Each event occupies one physical JSONL line. Field order remains `tool`, `capability`, `resource`, `decision`, `reason`.

## Example

```bash
moon run src/cmd/agent-sandbox -- runtime-demo
```

The demo creates a reader manifest with a one-request budget, authorizes one workspace read, and prints the resulting audit event. A second request is denied by the budget even if the path would otherwise match.

## Stable invariants

- Invalid policy or manifest cannot create a runtime.
- A session keeps the validated configuration snapshot taken at construction.
- An undeclared capability is denied before policy matching.
- A request budget is monotonic for the session.
- Audit events preserve evaluation order.
- Each request produces exactly one parseable event with its original identity.
- The runtime never grants a capability based on a natural-language description.
