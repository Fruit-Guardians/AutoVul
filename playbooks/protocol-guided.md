# Playbook 3: Protocol-Guided 状态机与生命周期时序确认

## 1. 适用场景

当审计对象具有严格的生命周期或协议状态约束（例如认证会话、加密信道握手、文件锁与资源释放、事务提交等）时，宿主需要：
- 审查同一资源对象在时序上的状态变迁是否合法；
- 识别“状态复用、跨越状态跳跃、未授权状态迁移或未重新初始化”引发的时序漏洞；
- 消除“两个独立对象的正常调用被误判为同一对象时序冲突”的误报，生成具有同一实例身份保证的因果证据（`typestate` 验证）。

---

## 2. 宿主原生自主阶段（无需 AutoVul）

宿主使用自身的代码阅读与协议逻辑分析能力：

1. **识别安全敏感的有状态资源**：
   - 会话上下文（如 `req.session`、`userSession`）；
   - 连接/句柄（如 socket、文件句柄、DB 事务）；
   - 权限凭证或安全标志位（如 `isAuthenticated`、`csrfToken`）。
2. **绘制合规状态变迁图（State Machine）**：
   - 合法时序通常为：`未认证 (Init) -> 验证凭据 -> 销毁旧会话/重建新标识 -> 已认证 (Authenticated)`。
3. **寻找协议不变量违背（Invariant Violations）**：
   - 检查是否存在绕过重置逻辑（如登录成功后未调用 `regenerateSession`，直接将用户身份绑定在登录前由攻击者预种的匿名会话上——会话固定漏洞）；
   - 检查是否存在资源关闭后的悬挂调用（Use-After-Free / Double-Release）。
4. **自主交付准则**：
   - 若状态机极其直观且作用域局限，宿主可直接在审计 Finding 中画出状态时序对照图并输出结论，**无需调用 AutoVul**。

---

## 3. 触发 AutoVul 的增强条件

当存在以下诉求时，宿主按需调用 AutoVul：
1. **严格绑定同一资源身份（Identity-Sensitive）**：人工代码审计常常混淆两个命名相同但实际不同的资源对象（如两个独立的 request 或临时 session 字典）。AutoVul `typestate` 要求证明违背时序的各事件发生在**同一个词法/数据流身份**的对象上。
2. **控制流可达性判定**：确保从非法前置状态到达敏感后置状态确实存在一条未被截断的真实执行分支。
3. **差分验证修复效果**：确保修复版本在状态机中引入了正确的终结事件或重置事件，使原本被禁止的跃迁彻底无法发生。

---

## 4. 工具接口与调用规约

调用 `autovul_research`，选择 `capability: "typestate"`：

```json
{
  "action": "execute",
  "capability": "typestate",
  "hypothesis_version": "autovul.typestate/1",
  "hypothesis": {
    "schema_version": "autovul.typestate/1",
    "hypothesis_id": "typestate-session-fixation-01",
    "language": "javascript",
    "resource": {
      "kind": "lexical_variable",
      "name": "session",
      "scope": "src/controllers/auth.js"
    },
    "states": ["unauthenticated", "authenticated"],
    "initial_state": "unauthenticated",
    "events": [
      { "name": "authenticate_user", "kind": "method_call", "method": "login" },
      { "name": "bind_user_data", "kind": "property_write", "property": "userId" },
      { "name": "regenerate_id", "kind": "method_call", "method": "regenerate" }
    ],
    "prohibited_transition": {
      "from": "unauthenticated",
      "event": "bind_user_data",
      "without_preceding": "regenerate_id"
    }
  },
  "analyzer_id": "codeql",
  "mode": "differential",
  "target": {
    "vulnerable": {
      "kind": "codeql_database",
      "path": "/path/to/vulnerable-db"
    },
    "fixed": {
      "kind": "codeql_database",
      "path": "/path/to/fixed-db"
    }
  },
  "budget": { "timeout_ms": 60000 },
  "idempotency_key": "session-fixation-run-01"
}
```

---

## 5. 结论回填与假设修正

1. **违规确认（`reproduced` / `differential`）**：
   - 裁决指标：漏洞版本产生 `prohibited_transition_observed`，证据中附带同一资源身份的事件调用行号；修复版本中由于加入重置事件，未发生非法跃迁（`fixed_policy_satisfied == true`）。
   - 宿主操作：在交付报告中强调时序逻辑缺陷及同一对象身份的确定性证明。
2. **无违规或事件未识别**：
   - 若观察返回 `events_not_found`：检查事件 matcher 的方法名或属性名是否与实际 AST 匹配；
   - 若观察返回 `different_resource_witness`：说明代码中涉及的是两个不同的资源实例，当前假设存在误报，宿主应据此撤销虚假报警。

---

## 6. 真实端到端案例：Ghost CMS CVE-2026-70594 会话固定漏洞

- **组件**：Ghost 身份认证模块
- **漏洞说明**：用户完成身份校验后，直接向现有的未认证会话对象写入 `user_id`，缺少 `req.session.regenerate()` 会话重生成步骤，攻击者可预先诱导目标复用已知 session id 劫持登录态。
- **宿主分析过程**：
  1. 宿主阅读认证入口代码，发现登录成功分支直接赋值 `session.user = user`。
  2. 宿主通过 `typestate` 建立假设：检查 `session` 对象在从未认证跃迁至已认证时，是否未经历 `regenerate`。
  3. AutoVul CodeQL 状态机分析器证实：同一词法变量 `session` 在缺少重置事件的情况下直接触发特权属性写入。
  4. 对比修复版本：修复代码在 `authenticate` 与 `bind` 之间插入了显式 `regenerate` 调用，AutoVul 差分对比确认非法跃迁被阻断。
  5. 宿主向用户输出会话固定漏洞分析报告与修复确认。
