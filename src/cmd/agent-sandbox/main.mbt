///|
let usage =
  #|usage:
  #|  agent-sandbox check --cap fs.read --resource workspace/src/main.mbt
  #|  agent-sandbox check --cap fs.write --resource workspace/out/result.json
  #|  agent-sandbox check --cap net.connect --resource api.example.com
  #|  agent-sandbox policy
  #|  agent-sandbox audit-demo
  #|  agent-sandbox runtime-demo

///|
fn print_decision(decision : @sandbox.Decision) -> Unit {
  match decision {
    @sandbox.Allow => println("ALLOW")
    @sandbox.Deny => println("DENY")
    @sandbox.Ask => println("ASK")
  }
}

///|
fn parse_capability(value : String) -> @sandbox.Capability? {
  @sandbox.capability_from_string(value)
}

///|
fn main {
  let args = @env.args()
  if args.length() == 2 && args[1] == "policy" {
    println("fs.read workspace/src/** allow")
    println("fs.read workspace/test/** allow")
    println("fs.write workspace/out/** allow")
    println("fs.write workspace/_build/** allow")
    println("net.connect ** deny")
    println("env.read LANG allow")
    return
  }
  if args.length() == 2 && args[1] == "audit-demo" {
    let manifest = @sandbox.ToolManifest::new("reader", [@sandbox.FsRead])
    let request = @sandbox.Request::new(
      "reader",
      @sandbox.FsRead,
      "../.ssh/id_rsa",
    )
    let (decision, event) = @sandbox.authorize_manifest(
      @sandbox.project_policy(),
      manifest,
      request,
    )
    match decision {
      @sandbox.Allow => println("ALLOW")
      @sandbox.Deny => println("DENY")
      @sandbox.Ask => println("ASK")
    }
    println(@sandbox.audit_event_json(event))
    return
  }
  if args.length() == 2 && args[1] == "runtime-demo" {
    let manifest = @sandbox.ToolManifest::with_limits(
      "reader",
      [@sandbox.FsRead],
      @sandbox.Limits::new(1000, 4096, 1),
    )
    match @sandbox.Runtime::new(@sandbox.project_policy(), manifest) {
      Ok(runtime) => {
        let decision = runtime.request(
          @sandbox.Request::new(
            "reader",
            @sandbox.FsRead,
            "workspace/src/main.mbt",
          ),
        )
        print_decision(decision)
        print_decision(
          runtime.request(
            @sandbox.Request::new(
              "reader",
              @sandbox.FsRead,
              "workspace/src/other.mbt",
            ),
          ),
        )
        println(runtime.audit_jsonl())
      }
      Err(message) => println("runtime rejected: " + message)
    }
    return
  }
  if args.length() != 6 ||
    args[1] != "check" ||
    args[2] != "--cap" ||
    args[4] != "--resource" {
    println(usage)
    return
  }
  match parse_capability(args[3]) {
    Some(capability) => {
      let request = @sandbox.Request::new("cli", capability, args[5])
      print_decision(@sandbox.authorize(@sandbox.project_policy(), request))
    }
    None => {
      println("unknown capability: " + args[3])
      println("valid capabilities: fs.read, fs.write, net.connect, env.read")
    }
  }
}
