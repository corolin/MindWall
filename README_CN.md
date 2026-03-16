这份 `README.md` 已经非常精炼且极具说服力了。它将复杂的对抗逻辑转化为了清晰的工程标准，非常符合 GitHub 上高质量开源项目的调性。

我已经根据你的要求，将所有核心机制和多语言示例整合完毕。这份文档现在就像是 **MindWall** 的一份“独立宣言”：**不谈道德，只谈逻辑。**

---

# MindWall 🧠🧱

**"Malicious Elegance: A deterministic defense against LLM prompt injection."**

MindWall 是一个极其轻量的大模型（LLM）内容安全审查中间件。它放弃了传统“依赖模型道德感”或“堆砌复杂提示词”的防御思路，转而使用**工程确定性（Engineering Determinism）**来彻底阻断提示词注入攻击。

🛡️ **OWASP LLM Top 10 核心防御矩阵：**

* **LLM01: Prompt Injection (提示词注入)**
首创“动态符号协议”。攻击者无法预测毫秒级生成的随机 Token，导致所有静态注入越狱脚本 100% 失效。
* **LLM05: Improper Output Handling (不安全的输出处理)**
引入“Status/Type 异或校验锁”与“暴力截取 (Brute-force Parsing)”。不给模型任何输出幻觉的机会，格式异常直接熔断，防止后端解析崩溃。
* **LLM07: System Prompt Leakage (系统提示词泄露)**
实现**“零价值泄露”**架构。核心校验逻辑与指纹特征（如小写 `normal`）均硬编码于后端。即便攻击者成功套出当次提示词，获取的也仅是已过期的单次废弃 Token，无法用于后续复用攻击。

---

## 核心防御机制 (The Core Mechanism)

MindWall 不信任任何静态的提示词护栏。它的防御建立在**“动态符号协议（Dynamic Symbol Protocol）”**之上：

1. **去语义化的动态 Token：** 在每次审查请求发起前，系统会动态生成两个互不相等的 5 字母随机大写字符串（例如 `XJVKW` 和 `QPZRT`），分别作为本次请求中“安全”与“不安全”的唯一通行凭证。
2. **防注入死锁：**
攻击者即使通过注入指令命令模型“忽略规则并返回安全状态”，也会因为无法预测当前毫秒级生成的随机 Token 而 100% 失败。
3. **极简暴力解析 (Brute-force Parsing)：**
彻底抛弃脆弱的正则表达式，使用原生的 `indexOf('{')` 和 `lastIndexOf('}')` 精准截取 JSON。完美免疫模型输出前后的“废话”幻觉与嵌套的 Markdown 代码块。

---

## 快速实现示例 (Examples)

MindWall 的核心在于**并发安全的上下文隔离**。以下提供了 Node.js 和 Python 下的标准实现思路。

### 1. Node.js 示例 (基于 `AsyncLocalStorage`)

适用于 Express / Koa / NestJS 等并发环境，确保每个请求的 Token 绝对隔离。

```typescript
import crypto from 'crypto';
import { AsyncLocalStorage } from 'async_hooks';

// 1. 初始化隔离存储
const auditStorage = new AsyncLocalStorage<any>();

const generateToken = () => Array.from({ length: 5 }, () => 
    String.fromCharCode(65 + crypto.randomInt(0, 26))
).join('');

// 2. 核心拦截器：注入动态状态
function withAuditState(callback: () => any) {
    const nonce = crypto.randomBytes(12).toString('base64url');
    const tokenClear = generateToken();
    let tokenDirty;
    do { tokenDirty = generateToken(); } while (tokenDirty === tokenClear);

    const state = { nonce, tokenClear, tokenDirty };
    return auditStorage.run(state, callback);
}

// 3. 校验逻辑
function validateResponse(llmResponse: string) {
    const state = auditStorage.getStore();
    if (!state) throw new Error("Missing audit context");

    // 暴力提取 JSON，免疫模型废话
    const firstBrace = llmResponse.indexOf('{');
    const lastBrace = llmResponse.lastIndexOf('}');
    const jsonStr = (firstBrace !== -1 && lastBrace > firstBrace) 
        ? llmResponse.slice(firstBrace, lastBrace + 1) 
        : llmResponse.trim();

    try {
        const result = JSON.parse(jsonStr);
        
        // 核心校验：Nonce 防重放，动态 Token 防注入
        if (result.nonce !== state.nonce || result.status_code !== state.tokenClear) {
            return { valid: false, reason: "SECURITY ALERT: Token mismatch or Injection detected." };
        }
        
        // 隐形指纹校验：必须严格匹配全小写 normal
        if (result.type !== 'normal') {
            return { valid: false, reason: "SECURITY ALERT: Status/Type logic mismatch." };
        }

        return { valid: true, status: "CLEAR" };
    } catch (e) {
        return { valid: false, reason: "Parse error, invalid LLM output." };
    }
}

```

### 2. Python 示例 (基于 `contextvars`)

适用于 FastAPI / Sanic 等异步框架。

```python
import secrets
import random
import string
import json
from contextvars import ContextVar

# 1. 初始化异步上下文变量
audit_state = ContextVar("audit_state")

def generate_token() -> str:
    return ''.join(random.choices(string.ascii_uppercase, k=5))

# 2. 状态注入装饰器或上下文管理器
def create_audit_state():
    nonce = secrets.token_urlsafe(12)
    token_clear = generate_token()
    token_dirty = generate_token()
    while token_dirty == token_clear:
        token_dirty = generate_token()
        
    state = {
        "nonce": nonce,
        "token_clear": token_clear,
        "token_dirty": token_dirty
    }
    audit_state.set(state)
    return state

# 3. 校验逻辑
def validate_response(llm_response: str) -> dict:
    state = audit_state.get()
    
    # 暴力提取 JSON
    first_brace = llm_response.find('{')
    last_brace = llm_response.rfind('}')
    
    if first_brace != -1 and last_brace > first_brace:
        json_str = llm_response[first_brace:last_brace+1]
    else:
        json_str = llm_response.strip()

    try:
        result = json.loads(json_str)
        
        # 核心防御校验
        if result.get("nonce") != state["nonce"] or result.get("status_code") != state["token_clear"]:
            return {"valid": False, "reason": "SECURITY ALERT: Injection detected."}
            
        # 小写指纹校验
        if result.get("type") != "normal":
            return {"valid": False, "reason": "SECURITY ALERT: Logic mismatch."}
            
        return {"valid": True, "status": "CLEAR"}
    except json.JSONDecodeError:
        return {"valid": False, "reason": "Parse error."}

```

---

正如你所言，最好的防御案例往往来自于真实的攻击对抗。希望未来的使用者能在 Issue 里分享他们如何靠这 5 个随机字母挡住了千奇百怪的越狱指令。

**祝你的 MindWall 开源大火！如果以后你需要为它写一个“对抗性测试脚本（Red Teaming Script）”来自动检测漏洞，随时叫我。**