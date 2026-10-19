# MoonSandbox：MoonBit Agent Tool Sandbox

> 让 Agent 能做事，但只能在被授予的空间里做事。

一个 Agent 正在帮你修复 MoonBit 项目。它需要读取源码、修改文件、运行测试；但仓库里的 README、依赖脚本或网页内容也可能诱导它读取 `~/.ssh`、上传源码，或者改写项目目录之外的文件。

每次操作都要求人工确认，Agent 就失去了自动化价值；完全放开权限，又等于把你的电脑交给一个会被上下文影响的程序。MoonSandbox 在两者之间提供一个明确的控制边界：工具请求先经过 capability policy；下一阶段的 WASM/WASI backend 将把获准的资源注入一个默认空白的工具工作空间。

## 它做什么

```text
Agent 请求调用工具
        ↓
MoonSandbox 检查 capability 和资源
        ↓
允许、拒绝或请求审批
        ↓
在受限的 WASM/WASI 工具环境中执行
        ↓
记录访问、结果和拒绝原因
```

当前 MVP 是可运行的权限控制面，已经实现了：

- `fs.read`、`fs.write`、`net.connect`、`env.read` 四类 capability；
- 默认拒绝；
- 精确资源和尾部 `/**` 目录匹配；
- 绝对路径、反斜杠路径和 `..` 路径穿越拒绝；
- 可解释的 `ALLOW` / `DENY` / `ASK` 决策；
- 工具 manifest 独立 capability 边界；
- JSONL-compatible 审计事件；
- 严格 JSON 配置校验：拒绝未知字段、重复 capability 和非整数预算；
- 固定会话权限快照，每次请求生成一条保留原始身份的有效 JSONL 审计事件；
- MoonBit CLI 走查、stateful runtime 和 26 个单元测试。

## 一个完整场景

用户说：“帮我修复这个项目并运行测试。”

Agent 可以：

```text
读取 workspace/src/main.mbt       ALLOW
写入 workspace/out/result.json    ALLOW
运行 MoonBit 测试                  ALLOW
```

当项目中的恶意内容诱导 Agent 执行下面的动作时：

```text
读取 ~/.ssh/id_rsa                DENY
访问未授权网络                    DENY
写入 workspace 外目录             DENY
```

拒绝来自运行时策略，而不是来自模型是否“听话”。

## 运行 MVP

```bash
# MoonBit 0.1.x currently reports backend-specific formatter differences as warnings.
moon fmt --warn
moon check --deny-warn
moon test --deny-warn

moon run src/cmd/agent-sandbox -- policy
moon run src/cmd/agent-sandbox -- check --cap fs.read --resource workspace/src/main.mbt
moon run src/cmd/agent-sandbox -- check --cap fs.read --resource ../.ssh/id_rsa
moon run src/cmd/agent-sandbox -- audit-demo
moon run src/cmd/agent-sandbox -- runtime-demo
```

## 从策略到执行事件

MVP 已经把一次工具调用拆成完整链路：工具先声明 manifest，随后请求 capability；运行时同时检查工具名、manifest 声明和策略规则，最后生成结构化审计事件。`audit-demo` 会展示一次被拒绝的读取请求及其原因。

## 为什么用 MoonBit

MoonBit 适合把工具权限建模为小而明确的 capability 类型，并面向 WASM/WASI 工具提供跨宿主的执行接口。MoonSandbox 不重新实现 Agent loop、MCP SDK 或 WASM 虚拟机；MoonBit 负责策略、授权、审计和工具协议，WASM/WASI runtime 负责底层模块隔离。

## 能力边界

MoonSandbox 保护的是受控的 WASM/WASI Agent 工具，不是已经拥有宿主权限的 Agent 主进程，也不是任意 native 二进制的操作系统沙箱。它不解决内核漏洞、物理侧信道，也不保证工具返回的恶意文本不会影响模型。纯 MoonBit MVP 是 capability policy engine；后续 WASI backend 才负责代码级隔离。

## 路线

1. 当前：capability、默认拒绝策略、路径安全和 CLI。
2. 下一步：策略文件、WIT 工具接口、WASI 执行后端、资源限制和 JSONL 审计。
3. 后续：审批 token、MCP stdio adapter、可替换的 macOS/Linux process backend。

详见 [快速开始](docs/getting-started.md)、[架构说明](docs/architecture.md)、[Runtime 契约](docs/runtime.md)、[威胁模型](docs/threat-model.md) 和 [JSON 策略示例](examples/policy.json)。申报材料不放入公开仓库。

## 参考

- [WASI capability-based security](https://wasi.dev/security)
- [MCP Security](https://github.com/modelcontextprotocol/modelcontextprotocol/security)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

## Public repository boundary

This repository contains only final product source, tests, user documentation, architecture notes, examples and license files. Never commit proposals, handoff notes, transcripts, prompts, session state, agent traces, private plans, scratch files, credentials or other development-process artifacts. Keep submission materials outside the repository.

## License

Apache-2.0
