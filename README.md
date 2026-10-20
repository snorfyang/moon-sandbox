# MoonSandbox：MoonBit Agent Tool Sandbox

> 让 Agent 能做事，但只能在被授予的空间里做事。

一个 Agent 正在帮你修复 MoonBit 项目。它需要读取源码、修改文件、运行测试；但仓库里的 README、依赖脚本或网页内容也可能诱导它读取 `~/.ssh`、上传源码，或者改写项目目录之外的文件。

每次操作都要求人工确认，Agent 就失去了自动化价值；完全放开权限，又等于把你的电脑交给一个会被上下文影响的程序。MoonSandbox 在两者之间提供一个明确的控制边界：工具请求先经过 MoonBit capability policy；当前 MCP 文件工具会在 Wasmtime 中执行，仅获得管理员批准的只读目录。调用前检查和实际执行隔离分别验证。

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

当前 MVP 包含 MoonBit 权限控制面和一个实际运行的 MCP → WASI 只读文件工具：

- `fs.read`、`fs.write`、`net.connect`、`env.read` 四类 capability；
- 默认拒绝；
- 精确资源和尾部 `/**` 目录匹配；
- 路径规范化、绝对路径和 `..` 路径穿越拒绝；
- 可解释的 `ALLOW` / `DENY` / `ASK` 决策；
- 工具 manifest 独立 capability 边界；
- JSONL-compatible 审计事件；
- 严格 JSON 配置校验：拒绝未知字段、重复 capability 和非整数预算；
- 固定会话权限快照，每次请求生成一条保留原始身份的有效 JSONL 审计事件；
- MoonBit CLI 走查、stateful runtime 和 26 个单元测试；
- 官方 MCP SDK stdio 接入，注册制品 SHA-256 绑定，Wasmtime 只读目录执行；
- 17 个集成测试覆盖真实文件读取、模块内部越权、符号链接越界、写权限拒绝、资源限制等。

## 一个实际执行的场景

管理员批准一个只读工作目录，并注册文件读取 WASM 制品。MCP client 发现 `read_text_file` 后发起调用：

```text
请求 notes.txt → MoonBit ALLOW → WASI 读取实际文件 → 返回内容
请求 ../canary.txt → MoonBit DENY → 不启动工具
请求 notes.txt，但恶意模块内部改读 ../canary.txt
  → MoonBit ALLOW → WASI 权限错误 → 未返回目录外 canary
```

第三条不是参数过滤测试：模块内部直接调用 WASI `path_open`，由 Wasmtime 的目录权限边界拒绝。测试只使用临时 canary，不访问真实用户密钥。

当前执行后端授权整个只读目录，不提供任意 native MCP server 隔离，也不声称逐文件访问控制。MCP 描述和工具 manifest 不会自行授予权限。

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

MoonBit 适合把工具权限建模为小而明确的 capability 类型，并面向 WASM/WASI 工具提供跨宿主的执行接口。MoonSandbox 不重新实现 Agent loop、MCP SDK 或 WASM 虚拟机；MoonBit 负责策略、manifest 校验和授权审计；Python 适配层使用官方 MCP SDK 与 Wasmtime 管理协议和执行生命周期，WAT 参考工具实际调用 WASI 文件接口。具体实现分工和可信边界见执行文档。

## 能力边界

MoonSandbox 保护的是受控的 WASM/WASI Agent 工具，不是已经拥有宿主权限的 Agent 主进程，也不是任意 native 二进制的操作系统沙箱。它不解决内核漏洞、物理侧信道，也不保证工具返回的恶意文本不会影响模型。纯 MoonBit 库是 capability policy engine；当前只读文件工具的执行边界由 Wasmtime 后端提供，宿主适配器与配置属于可信计算基。

## 路线

1. 当前：MoonBit capability 控制面、严格 JSON 配置、CLI、MCP stdio 文件工具和 WASI 只读目录执行。
2. 下一步：更通用的 WASI 工具 ABI、细粒度可信 hostcall 代理与执行审计。
3. 后续：审批 token、更多工具类型；native server 隔离需要独立设计与验证。

真实链路的复现、授权来源和适用范围见 [MCP → WASI 执行案例](docs/mcp-wasi.md)。

详见 [快速开始](docs/getting-started.md)、[架构说明](docs/architecture.md)、[Runtime 契约](docs/runtime.md)、[威胁模型](docs/threat-model.md) 和 [JSON 策略示例](examples/policy.json)。申报材料不放入公开仓库。

## 参考

- [WASI capability-based security](https://wasi.dev/security)
- [MCP Security](https://github.com/modelcontextprotocol/modelcontextprotocol/security)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)

## Public repository boundary

This repository contains only final product source, tests, user documentation, architecture notes, examples and license files. Never commit proposals, handoff notes, transcripts, prompts, session state, agent traces, private plans, scratch files, credentials or other development-process artifacts. Keep submission materials outside the repository.

## License

Apache-2.0
