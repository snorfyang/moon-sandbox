/// Capability policy and decision engine for Agent tools.
///
/// This package deliberately enforces a tool-level boundary. It does not claim
/// to isolate arbitrary native processes; a WASM/WASI host must enforce the
/// lower-level execution boundary.

///|
pub(all) enum Decision {
  Allow
  Deny
  Ask
} derive(Eq, Debug)

///|
pub extend Decision with Eq::{not_equal, equal}

///|
pub extend Decision with @debug.Debug::{to_repr}

///|
pub(all) enum Capability {
  FsRead
  FsWrite
  NetConnect
  EnvRead
} derive(Eq, Debug)

///|
pub extend Capability with Eq::{not_equal, equal}

///|
pub extend Capability with @debug.Debug::{to_repr}

///|
pub struct Rule {
  capability : Capability
  pattern : String
  decision : Decision
}

///|
pub fn Rule::new(
  capability : Capability,
  pattern : String,
  decision : Decision,
) -> Rule {
  { capability, pattern, decision, }
}

///|

///|
pub struct Policy {
  rules : Array[Rule]
}

///|
pub fn Policy::new(rules : Array[Rule]) -> Policy {
  { rules, }
}

///|
/// Validate rules before a policy is installed.
pub fn Policy::validate(self : Policy) -> Result[Unit, String] {
  for rule in self.rules {
    if rule.pattern.is_empty() {
      return Err("policy rule pattern must not be empty")
    }
    if rule.pattern.has_prefix("/") || rule.pattern.has_prefix("\\") {
      return Err("policy rule pattern must be relative")
    }
    if rule.pattern.contains("\\") {
      return Err("policy rule pattern must not contain backslashes")
    }
    if rule.pattern.contains("..") {
      return Err("policy rule pattern must not contain ..")
    }
  }
  Ok(())
}

///|

///|
pub struct Request {
  tool : String
  capability : Capability
  resource : String
}

///|
pub fn Request::new(
  tool : String,
  capability : Capability,
  resource : String,
) -> Request {
  { tool, capability, resource, }
}

///|
/// A tool's declared capability surface.
pub(all) struct ToolManifest {
  name : String
  capabilities : Array[Capability]
  limits : Limits
}

///|
/// Per-tool resource budget enforced by the runtime boundary.
pub(all) struct Limits {
  timeout_ms : Int
  max_output_bytes : Int
  max_requests : Int
}

///|
pub fn Limits::new(
  timeout_ms : Int,
  max_output_bytes : Int,
  max_requests : Int,
) -> Limits {
  { timeout_ms, max_output_bytes, max_requests, }
}

///|
pub fn Limits::default() -> Limits {
  { timeout_ms: 30_000, max_output_bytes: 1_048_576, max_requests: 128, }
}

///|
pub fn ToolManifest::new(
  name : String,
  capabilities : Array[Capability],
) -> ToolManifest {
  { name, capabilities, limits: Limits::default(), }
}

///|
pub fn ToolManifest::with_limits(
  name : String,
  capabilities : Array[Capability],
  limits : Limits,
) -> ToolManifest {
  { name, capabilities, limits, }
}

///|
pub fn ToolManifest::has(self : ToolManifest, capability : Capability) -> Bool {
  self.capabilities.contains(capability)
}

///|
pub fn ToolManifest::validate(self : ToolManifest) -> Result[Unit, String] {
  if self.name.is_empty() {
    return Err("tool manifest name must not be empty")
  }
  if self.limits.timeout_ms <= 0 {
    return Err("timeout_ms must be positive")
  }
  if self.limits.max_output_bytes <= 0 {
    return Err("max_output_bytes must be positive")
  }
  if self.limits.max_requests <= 0 {
    return Err("max_requests must be positive")
  }
  let seen : Array[Capability] = []
  for capability in self.capabilities {
    if seen.contains(capability) {
      return Err("tool manifest contains a duplicate capability")
    }
    seen.push(capability)
  }
  if self.capabilities.is_empty() {
    return Err("tool manifest must declare at least one capability")
  }
  Ok(())
}

///|
/// Parse a manifest JSON document.
///
/// {
///   "name":"reader",
///   "capabilities":["fs.read"],
///   "limits":{"timeout_ms":30000,"max_output_bytes":1048576,"max_requests":128}
/// }
pub fn tool_manifest_from_json(text : String) -> Result[ToolManifest, String] {
  let value = @json.parse(text) catch {
    _ => return Err("manifest is not valid JSON")
  }
  match value {
    Json::Object(root) => {
      match
        validate_fields(root, ["name", "capabilities", "limits"], "manifest") {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      let name = match root.get("name") {
        Some(Json::String(value)) => value
        _ => return Err("manifest.name must be a string")
      }
      let capabilities = match root.get("capabilities") {
        Some(Json::Array(items)) => {
          let out : Array[Capability] = []
          for item in items {
            match item {
              Json::String(value) =>
                match capability_from_string(value) {
                  Some(capability) => out.push(capability)
                  None => return Err("manifest contains an unknown capability")
                }
              _ => return Err("manifest.capabilities must contain strings")
            }
          }
          out
        }
        _ => return Err("manifest.capabilities must be an array")
      }
      let limits = match root.get("limits") {
        Some(Json::Object(fields)) => {
          match
            validate_fields(
              fields,
              ["timeout_ms", "max_output_bytes", "max_requests"],
              "manifest.limits",
            ) {
            Err(message) => return Err(message)
            Ok(_) => ()
          }
          let timeout_ms = json_int_field(fields, "timeout_ms")
          let max_output_bytes = json_int_field(fields, "max_output_bytes")
          let max_requests = json_int_field(fields, "max_requests")
          match (timeout_ms, max_output_bytes, max_requests) {
            (Some(a), Some(b), Some(c)) => Limits::new(a, b, c)
            _ => return Err("manifest.limits has an invalid field")
          }
        }
        None => Limits::default()
        _ => return Err("manifest.limits must be an object")
      }
      let manifest = ToolManifest::with_limits(name, capabilities, limits)
      match manifest.validate() {
        Ok(_) => Ok(manifest)
        Err(message) => Err(message)
      }
    }
    _ => Err("manifest root must be an object")
  }
}

///|
fn json_int_field(fields : Map[String, Json], key : String) -> Int? {
  match fields.get(key) {
    Some(Json::Number(value, ..)) => {
      if value < 1.0 || value > 2147483647.0 {
        return None
      }
      let integer = value.to_int()
      if integer.to_double() != value {
        None
      } else {
        Some(integer)
      }
    }
    _ => None
  }
}

///|
/// A normalized, machine-readable execution event.
pub(all) struct AuditEvent {
  tool : String
  capability : String
  resource : String
  decision : String
  reason : String
}

///|
pub fn AuditEvent::new(
  tool : String,
  capability : Capability,
  resource : String,
  decision : Decision,
  reason : String,
) -> AuditEvent {
  {
    tool,
    capability: capability_name(capability),
    resource,
    decision: decision_name(decision),
    reason,
  }
}

///|
/// Convert a capability to its stable policy spelling.
pub fn capability_name(capability : Capability) -> String {
  match capability {
    FsRead => "fs.read"
    FsWrite => "fs.write"
    NetConnect => "net.connect"
    EnvRead => "env.read"
  }
}

///|
pub fn decision_name(decision : Decision) -> String {
  match decision {
    Allow => "allow"
    Deny => "deny"
    Ask => "ask"
  }
}

///|
/// A tool can only request capabilities it declared in its manifest.
pub fn authorize_manifest(
  policy : Policy,
  manifest : ToolManifest,
  request : Request,
) -> (Decision, AuditEvent) {
  if request.tool != manifest.name {
    let event = AuditEvent::new(
      request.tool,
      request.capability,
      request.resource,
      Deny,
      "tool name does not match manifest",
    )
    return (Deny, event)
  }
  if !manifest.has(request.capability) {
    let event = AuditEvent::new(
      request.tool,
      request.capability,
      request.resource,
      Deny,
      "capability was not declared by the tool",
    )
    return (Deny, event)
  }
  let decision = authorize(policy, request)
  let reason = match decision {
    Allow => "matched policy"
    Deny => "no matching allow rule"
    Ask => "policy requires approval"
  }
  (
    decision,
    AuditEvent::new(
      request.tool,
      request.capability,
      request.resource,
      decision,
      reason,
    ),
  )
}

///|
/// Serialize an audit event as one JSONL-compatible line.
pub fn audit_event_json(event : AuditEvent) -> String {
  "{\"tool\":" +
  Json(event.tool).stringify() +
  ",\"capability\":" +
  Json(event.capability).stringify() +
  ",\"resource\":" +
  Json(event.resource).stringify() +
  ",\"decision\":" +
  Json(event.decision).stringify() +
  ",\"reason\":" +
  Json(event.reason).stringify() +
  "}"
}

///|
/// Append-only audit stream for one Agent session.
pub struct AuditLog {
  events : Array[AuditEvent]
}

///|
pub fn AuditLog::new() -> AuditLog {
  { events: [], }
}

///|
pub fn AuditLog::append(self : AuditLog, event : AuditEvent) -> Unit {
  self.events.push(event)
}

///|
pub fn AuditLog::len(self : AuditLog) -> Int {
  self.events.length()
}

///|
/// Serialize the session as newline-delimited JSON with a final newline.
pub fn AuditLog::to_jsonl(self : AuditLog) -> String {
  let out = StringBuilder()
  for event in self.events {
    out.write_string(audit_event_json(event))
    out.write_char('\n')
  }
  out.to_string()
}

///|
/// Stateful runtime facade for one tool session.
pub struct Runtime {
  policy : Policy
  manifest : ToolManifest
  mut requests_used : Int
  log : AuditLog
}

///|
pub fn Runtime::new(
  policy : Policy,
  manifest : ToolManifest,
) -> Result[Runtime, String] {
  match (policy.validate(), manifest.validate()) {
    (Ok(_), Ok(_)) => {
      let policy = Policy::new(policy.rules.copy())
      let manifest = ToolManifest::with_limits(
        manifest.name,
        manifest.capabilities.copy(),
        manifest.limits,
      )
      Ok({ policy, manifest, requests_used: 0, log: AuditLog::new(), })
    }
    (Err(message), _) => Err("policy rejected: " + message)
    (_, Err(message)) => Err("manifest rejected: " + message)
  }
}

///|
/// Evaluate and record one request, enforcing the manifest request budget.
pub fn Runtime::request(self : Runtime, request : Request) -> Decision {
  if self.requests_used >= self.manifest.limits.max_requests {
    self.log.append(
      AuditEvent::new(
        request.tool,
        request.capability,
        request.resource,
        Deny,
        "request budget exhausted",
      ),
    )
    return Deny
  }
  self.requests_used += 1
  let (decision, event) = authorize_manifest(
    self.policy,
    self.manifest,
    request,
  )
  self.log.append(event)
  decision
}

///|
pub fn Runtime::audit_jsonl(self : Runtime) -> String {
  self.log.to_jsonl()
}

///|
/// Parse the MVP JSON policy format.
pub fn policy_from_json(text : String) -> Result[Policy, String] {
  let value = @json.parse(text) catch {
    _ => return Err("policy is not valid JSON")
  }
  match value {
    Json::Object(root) => {
      match validate_fields(root, ["rules"], "policy") {
        Err(message) => return Err(message)
        Ok(_) => ()
      }
      match root.get("rules") {
        Some(Json::Array(items)) => {
          let rules : Array[Rule] = []
          for item in items {
            match item {
              Json::Object(fields) => {
                match
                  validate_fields(
                    fields,
                    ["capability", "pattern", "decision"],
                    "policy rule",
                  ) {
                  Err(message) => return Err(message)
                  Ok(_) => ()
                }
                let cap = match fields.get("capability") {
                  Some(Json::String(value)) => capability_from_string(value)
                  _ => None
                }
                let pattern = match fields.get("pattern") {
                  Some(Json::String(value)) => Some(value)
                  _ => None
                }
                let decision = match fields.get("decision") {
                  Some(Json::String(value)) => decision_from_string(value)
                  _ => None
                }
                match (cap, pattern, decision) {
                  (Some(capability), Some(pattern), Some(decision)) =>
                    rules.push({ capability, pattern, decision, })
                  _ =>
                    return Err(
                      "each rule needs capability, pattern and decision",
                    )
                }
              }
              _ => return Err("each item in rules must be an object")
            }
          }
          let policy = Policy::new(rules)
          match policy.validate() {
            Ok(_) => Ok(policy)
            Err(message) => Err(message)
          }
        }
        _ => Err("policy.rules must be an array")
      }
    }
    _ => Err("policy root must be an object")
  }
}

///|
/// Normalize a resource before policy matching.
pub fn normalize_resource(resource : String) -> String? {
  if resource.is_empty() ||
    resource.has_prefix("/") ||
    resource.has_prefix("\\") {
    return None
  }
  let normalized = resource.replace(old="\\", new="/")
  let parts = normalized.split("/")
  let out : Array[String] = []
  for part in parts {
    if part.is_empty() || part == "." {
      continue
    }
    if part == ".." {
      return None
    }
    out.push(part.to_owned())
  }
  if out.is_empty() {
    None
  } else {
    Some(out.join("/"))
  }
}

///|
/// Parse the four capability names used by the policy file.
pub fn capability_from_string(value : String) -> Capability? {
  match value {
    "fs.read" => Some(FsRead)
    "fs.write" => Some(FsWrite)
    "net.connect" => Some(NetConnect)
    "env.read" => Some(EnvRead)
    _ => None
  }
}

///|
/// Parse a decision name.
pub fn decision_from_string(value : String) -> Decision? {
  match value {
    "allow" => Some(Allow)
    "deny" => Some(Deny)
    "ask" => Some(Ask)
    _ => None
  }
}

///|
/// Glob matching intentionally supports only an exact value or a trailing `/**`.
pub fn pattern_matches(pattern : String, resource : String) -> Bool {
  if pattern == "**" || pattern == resource {
    return true
  }
  if pattern.has_suffix("/**") {
    let prefix = pattern[:pattern.length() - 3].to_owned()
    return resource == prefix || resource.has_prefix(prefix + "/")
  }
  false
}

///|
/// Decide a request using the last matching rule. Default is deny.
pub fn decide(policy : Policy, request : Request) -> Decision {
  let mut result = Deny
  for rule in policy.rules {
    if rule.capability == request.capability &&
      pattern_matches(rule.pattern, request.resource) {
      result = rule.decision
    }
  }
  result
}

///|
/// Validate a request resource and apply the policy.
pub fn authorize(policy : Policy, request : Request) -> Decision {
  match request.capability {
    FsRead | FsWrite =>
      match normalize_resource(request.resource) {
        Some(path) => decide(policy, { ..request, resource: path, })
        None => Deny
      }
    _ => decide(policy, request)
  }
}

///|
/// A safe starter policy for a project-local tool.
pub fn project_policy() -> Policy {
  {
    rules: [
      { capability: FsRead, pattern: "workspace/src/**", decision: Allow, },
      { capability: FsRead, pattern: "workspace/test/**", decision: Allow, },
      { capability: FsWrite, pattern: "workspace/out/**", decision: Allow, },
      { capability: FsWrite, pattern: "workspace/_build/**", decision: Allow, },
      { capability: NetConnect, pattern: "**", decision: Deny, },
      { capability: EnvRead, pattern: "LANG", decision: Allow, },
    ],
  }
}

///|
fn validate_fields(
  fields : Map[String, Json],
  allowed : Array[String],
  context : String,
) -> Result[Unit, String] {
  for key, _ in fields {
    if !allowed.contains(key) {
      return Err(context + " contains unknown field: " + key)
    }
  }
  Ok(())
}
