///|
test "runtime snapshots policy rules against caller mutation" {
  let rules = [Rule::new(FsRead, "workspace/**", Deny)]
  let runtime = Runtime::new(
    Policy::new(rules),
    ToolManifest::new("reader", [FsRead]),
  ).unwrap()
  rules.clear()
  rules.push(Rule::new(FsRead, "workspace/**", Allow))
  assert_eq(
    runtime.request(Request::new("reader", FsRead, "workspace/a")),
    Deny,
  )
}

///|
test "runtime snapshots declared capabilities against additions and removals" {
  let capabilities = [FsRead]
  let runtime = Runtime::new(
    Policy::new([
      Rule::new(FsRead, "workspace/**", Allow),
      Rule::new(FsWrite, "workspace/**", Allow),
    ]),
    ToolManifest::new("reader", capabilities),
  ).unwrap()
  capabilities.clear()
  capabilities.push(FsWrite)
  assert_eq(
    runtime.request(Request::new("reader", FsRead, "workspace/a")),
    Allow,
  )
  assert_eq(
    runtime.request(Request::new("reader", FsWrite, "workspace/a")),
    Deny,
  )
}

///|
test "last permitted request and exhausted requests each produce one accurate event" {
  let runtime = Runtime::new(
    project_policy(),
    ToolManifest::with_limits("reader", [FsRead], Limits::new(1000, 4096, 1)),
  ).unwrap()
  assert_eq(runtime.request(Request::new("reader", FsRead, "../secret")), Deny)
  assert_eq(runtime.log.len(), 1)
  assert_true(!runtime.audit_jsonl().contains("request budget exhausted"))
  assert_eq(
    runtime.request(Request::new("other-tool", EnvRead, "SECRET")),
    Deny,
  )
  assert_eq(runtime.log.len(), 2)
  let event = runtime.log.events[1]
  assert_eq(event.tool, "other-tool")
  assert_eq(event.capability, "env.read")
  assert_eq(event.resource, "SECRET")
  assert_eq(event.reason, "request budget exhausted")
  // Repeated exhausted requests cannot overflow the counter or regain a grant.
  assert_eq(
    runtime.request(Request::new("reader", FsRead, "workspace/src/a")),
    Deny,
  )
  assert_eq(runtime.log.len(), 3)
  assert_eq(runtime.requests_used, 1)
}

///|
test "ask consumes budget and sessions have independent budgets and logs" {
  let policy = Policy::new([Rule::new(FsRead, "workspace/**", Ask)])
  let manifest = ToolManifest::with_limits(
    "reader",
    [FsRead],
    Limits::new(1, 1, 1),
  )
  let first = Runtime::new(policy, manifest).unwrap()
  let second = Runtime::new(policy, manifest).unwrap()
  let request = Request::new("reader", FsRead, "workspace/a")
  assert_eq(first.request(request), Ask)
  assert_eq(first.request(request), Deny)
  assert_eq(second.audit_jsonl(), "")
  assert_eq(second.request(request), Ask)
  assert_eq(first.log.len(), 2)
  assert_eq(second.log.len(), 1)
}

///|
test "audit JSON round trips all control characters in every string field" {
  let controls = StringBuilder()
  for code = 0; code < 32; code = code + 1 {
    controls.write_char(code.to_char().unwrap())
  }
  let value = controls.to_string() + "引号\" slash\\ emoji😀"
  let event : AuditEvent = {
    tool: value,
    capability: value,
    resource: value,
    decision: value,
    reason: value,
  }
  let line = audit_event_json(event)
  assert_true(!line.contains("\n"))
  let parsed = @json.parse(line)
  guard parsed is Json::Object(fields) else { fail("expected audit object") }
  assert_eq(fields.length(), 5)
  for key in ["tool", "capability", "resource", "decision", "reason"] {
    guard fields.get(key) is Some(Json::String(actual)) else {
      fail("missing string field: " + key)
    }
    assert_eq(actual, value)
  }
}

///|
test "JSONL preserves physical lines for hostile input" {
  let log = AuditLog::new()
  log.append(
    AuditEvent::new("reader", FsRead, "a\r\nb\t\u{0000}", Deny, "rejected"),
  )
  log.append(AuditEvent::new("reader", FsRead, "workspace/a", Allow, "matched"))
  let lines = log.to_jsonl().split("\n").to_array()
  assert_eq(lines.length(), 3)
  assert_eq(lines[2], "")
  for index = 0; index < 2; index = index + 1 {
    assert_true(@json.parse(lines[index].to_owned()) is Json::Object(_))
  }
}
