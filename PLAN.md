# claude-credential-gateway —— 设计目标与方案依据

## 设计目标

**在自己的多台电脑上复用同一个 Claude 订阅,而不在那些电脑上暴露真 token。**

具体场景:我有多台设备,其中可能包括公共场所 / 不完全可信的电脑。我想在这些电脑上用自己的
订阅,但**不愿意在它们上面登录、把真 OAuth token 落到本地**——一旦那台电脑被人翻到凭证,
我的账号就暴露了。

解法:把"持有真凭证"和"使用凭证跑 agent"两件事拆开(就是 `claude ssh` 的凭证隔离思路):
- 真 OAuth token 只放在**一台我信任、我控制的网关机器**上;
- 不可信电脑上只放**占位 token + 一个可吊销的设备 key**,真请求经网关时被注入真凭证;
- 这样不可信电脑上**不落地任何真 Anthropic 凭证**。

> 适用边界:仅限**我本人、我自己的设备**,低并发自用。把设备 key 发给别人就变成订阅共享,
> 违反 Anthropic ToS 且会被账号级检测命中——见第六节。
>
> 源码依据来自从 sourcemap 还原的 `@anthropic-ai/claude-code@2.1.88`,路径相对
> `restored-src/src/`。还原源码不含原生层(Bun/Zig)与服务端,涉及两层处按黑盒标注。

---

## 一、方案总览(组件 → 目标)

| 组件 | 角色 | 对应目标 |
|---|---|---|
| `gateway.js`(oauth 模式) | 网关:持真订阅 token,注入到经过的请求 | **主方案**:多设备复用、token 不落地 |
| `gateway.js`(apikey 模式) | 网关:注入自己的 API key | 衍生:做产品后端时的合规用法 |
| `claude-proxy-demo.js` | 单进程透明转发 + 打印请求 | 观察/验证工具:看清请求结构、attestation |
| `test-gateway.js` | 自动化测试(mock 上游 + 假凭证) | 验证注入链路正确(8/8 通过) |
| `SSH-ARCHITECTURE.md` | `claude ssh` 凭证隔离架构分析 | 设计参考来源 |

数据流(网关 oauth 模式):
```
不可信电脑                              我的网关机器(信任)            Anthropic
真 Claude Code                          gateway.js
  占位 CLAUDE_CODE_OAUTH_TOKEN  ──┐
  设备 key (ANTHROPIC_CUSTOM_HEADERS)│  校验设备 key → 配额 → 审计
  ANTHROPIC_BASE_URL=网关          ├─▶  换 Authorization 为真订阅 token ──▶ api.anthropic.com
  (真二进制算好 attestation)        ┘   逐字节透明转发 + SSE 回传
```

---

## 二、核心认知:两个正交维度

整个方案建立在一个关键事实上:**「用什么认证」和「请求发到哪」是两件独立的事。**

| 维度 | 决定者 | 源码 |
|---|---|---|
| 认证方式(OAuth 订阅 vs API key) | `isClaudeAISubscriber()` / `isAnthropicAuthEnabled()` | `utils/auth.ts:100-149`、`1255-1300` |
| endpoint(发到哪个地址) | `ANTHROPIC_BASE_URL`(SDK 默认从 env 读) | `services/api/client.ts:300-316` |
| provider(firstParty / Bedrock / Vertex / Foundry) | `CLAUDE_CODE_USE_*` 环境变量 | `utils/model/providers.ts:6-14` |

要点:
- `isAnthropicAuthEnabled()` 关闭 OAuth 的条件只有:`--bare`、Bedrock/Vertex/Foundry、
  有外部 API key、有外部 auth token。**`ANTHROPIC_BASE_URL` 不在其中** → 设了 base_url,
  OAuth 订阅照常工作,这是网关方案的前提。
- 普通用户 `client.ts:300-316` 不显式设 baseURL → 落到 SDK 默认读 `ANTHROPIC_BASE_URL`,
  **不分认证方式,OAuth 也吃。**
- 占位 token 走 `auth.ts:1255-1300` 的 inference-only 分支(`scopes:['user:inference']`),
  足以让客户端进订阅 OAuth 形状(带 `oauth-2025-04-20` beta)、把请求拼对。

---

## 三、凭证隔离架构(借鉴 claude ssh)

网关 = `claude ssh` 里那个"本地注入认证代理"(`sshAuthProxy`)的网关化版本。对应关系:

| claude ssh | 本方案网关 |
|---|---|
| 不可信远端拿占位 token | 不可信电脑拿占位 token + 设备 key |
| 本地代理注入真凭证 | 网关注入真订阅 token |
| strip 远端能改认证的 env(`managedEnv.ts:18-34`) | 网关剥掉客户端的 `authorization`/`x-api-key` |
| 上游硬编码 api.anthropic.com(`proxy.ts:297-299`) | 网关上游硬编码 |
| 占位让远端拼对请求形状 | 同 |

---

## 四、关键设计决策与依据

### 决策 1:用 `ANTHROPIC_BASE_URL` 指向网关,不用 `HTTPS_PROXY`
- `HTTPS_PROXY` 是**全局**的(`utils/proxy.ts:327-388` 挂 axios 拦截器 + undici 全局 dispatcher),
  会把遥测/OAuth/GrowthBook/MCP 全灌进来;`NO_PROXY` 只能排除、不能"只代理某一个"(`proxy.ts:88-129`)。
- `ANTHROPIC_BASE_URL` 只改推理这一条线,天然只截要走网关的流量。
- 不可信电脑 → 网关走 HTTPS(网关需正常域名证书);**不需要自定义 CA/MITM**
  (那套只有透明拦截全局 HTTPS 才需要,参考 `upstreamproxy/upstreamproxy.ts` + `caCerts.ts:28-32`)。

### 决策 2:逐字节透明转发,绝不 reparse body(最关键)
- attestation 的 `cch` 由真二进制原生 Bun 层算出,**写在请求 body 里**(同长替换 `cch=00000`,
  `constants/system.ts:64-95`),且它在 system prompt 文本中(`claude.ts:1358-1369`)→ 属 JSON body。
- **只要 body 字节不变,attestation 就存活。** 网关只换 header,不动 body。
- 反例:"解析成对象再 re-emit"会改字节顺序/空格,可能让 `cch` 失配 → 被判非真客户端。
- 已由 `test-gateway.js` 验证:`body 逐字节不变` ✅。

### 决策 3:只换 `Host` + `Authorization`,剥掉客户端凭证企图
- 客户端连网关,Host 是网关地址 → 转发前改写成 `api.anthropic.com`。
- 把 `Authorization` 换成真订阅 token;删掉 `x-gateway-key`(设备 key 不外泄)、客户端的 `x-api-key`。
- 其余头(`anthropic-beta` / `anthropic-version` / `user-agent` / attestation 所在的 body)原样保留。

### 决策 4:响应流式透传(`upRes.pipe(res)`)
- 推理响应是 SSE 流,边到边回,不 buffer。

### 决策 5:占位 token + 设备 key 的注入方式
- 不可信电脑设 `CLAUDE_CODE_OAUTH_TOKEN=<占位>` 让客户端进订阅 OAuth 形状(`auth.ts:1260`)。
- 设备 key 通过 `ANTHROPIC_CUSTOM_HEADERS`(格式 `Name: Value`,换行分隔,`client.ts:330-350`)
  注入成 `x-gateway-key`,供网关鉴权。
- 不可信电脑上这三样都不是真凭证:占位 token、设备 key、base_url —— 设备 key 可单独吊销。

---

## 五、自测步骤(对真 API)

**网关机器(信任):**
```bash
export CLAUDE_GATEWAY_UPSTREAM_OAUTH='<我的订阅 access token>'   # 见第七节续期说明
export GATEWAY_UPSTREAM_MODE=oauth
export GATEWAY_USERS='{"device-laptop-1":{"id":"laptop-1","dailyLimit":200}}'
node gateway.js          # 默认上游 https://api.anthropic.com;生产前面挂 TLS + VPN/allowlist
```

**不可信电脑:**
```bash
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
export CLAUDE_CODE_OAUTH_TOKEN='placeholder-anything'
export ANTHROPIC_BASE_URL='https://我的网关'
export ANTHROPIC_CUSTOM_HEADERS='x-gateway-key: device-laptop-1'
claude
```

**纯链路自测(无需真凭证):** `node test-gateway.js`(mock 上游 + 假 token,验证注入/不泄露/字节不变/SSE)。

---

## 六、威胁模型与边界

1. **达成的目标**:不可信电脑只有占位 token + 可吊销设备 key + base_url,**没有真凭证**。
2. **保护的是 token,不是会话内容**:不可信电脑仍能截屏/键盘记录 prompt 与输出、能看 Claude 在
   该机读写的文件。**若那台机器真的敌对,优先 `claude ssh <网关机器>`**——让 Claude 跑在我的机器上,
   不可信电脑只当终端,什么都不落地。
3. **网关必须是我信任且可控的机器**,且能被不可信电脑访问 → 加 TLS + 设备 key 鉴权 + 最好放
   VPN/Tailscale 或 IP allowlist 后,别裸奔公网。
4. **合规**:单用户、自己设备、低并发 → 不踩共享检测。**别把设备 key 给别人**——多个不同的人用
   就是订阅共享,违反 ToS,且会被下方账号级信号命中。

---

## 七、可行性结论 + 黑盒

| 场景 | 链路 | 可持续 |
|---|---|---|
| 单用户多设备(本方案) | ✅ 通,attestation 全程合法 | ✅ 低并发,不踩检测 |
| 多人共享同一订阅 | ✅ 字节能流通 | ❌ 账号级关联 + 限流 + ToS |

多人共享为何不成(本方案故意不碰):
1. **token 生命周期**:占位 inference-only token 小时级过期且不能刷(`auth.ts:1262-1269`);
   共享带 refresh 的完整凭证又撞跨机轮换/锁。
2. **限流**:一个订阅的 `rateLimitTier` 是所有人合用上限。
3. **账号级关联**:服务端用 token 鉴权 → 都归一个 `account_uuid`(`claude.ts:503-528`),
   网关汇聚到单 IP + 高并发 = 共享特征。`device_id`(`config.ts:1757-1766`)客户端自报可改,救不了。

黑盒(够不到、控制不了):
- **attestation 算法**:原生 `Attestation.zig`,且受 GrowthBook flag `NATIVE_CLIENT_ATTESTATION`
  远程控制(`system.ts:82`)。本方案靠真二进制自算,不复刻它,只要别动 body。
- **服务端校验 + 反滥用策略**:阈值、是否交叉校验 attestation↔账号、封禁逻辑,全不可见。
- **OAuth 刷新/轮换服务端策略**:客户端流程可见,服务端轮换不可见。
- 服务端强制 sysprompt(印证不可绕):`claude.ts:540` "will fail in 1P unless it uses
  `getCLISyspromptPrefix`" → 1P 强制 OAuth 请求带 "You are Claude Code..." 前缀(`system.ts:30-46`)。

**token 续期(上线前必补)**:网关里若只贴 access token 会几小时过期。稳妥做法:网关机器正常
`claude` 登录,网关从 keychain 读 token 并自动刷新(即 `sshAuthProxy` 的真正逻辑),而非手贴。

---

## 八、源码索引(相对 `restored-src/src/`)

- 认证方式选择 / SDK client:`services/api/client.ts:300-328`、默认头 `:105-116`、自定义头 `:330-350`
- OAuth 是否启用:`utils/auth.ts:100-149`;OAuth token 来源(含占位):`:1255-1300`
- provider 判定:`utils/model/providers.ts:6-14`、base_url 是否官方域名 `:25-40`
- oauth beta:`utils/betas.ts:251`
- attribution / attestation:`constants/system.ts:30-46`(sysprompt 前缀)、`:73-95`(cch)、`:82`(flag)
- 请求体组装:`services/api/claude.ts:1358-1369`(system)、`:1699-1718`(body)、`:503-528`(metadata)、`:540`(强制 sysprompt)
- device_id:`utils/config.ts:1757-1766`;可信设备 token:`bridge/trustedDevice.ts`
- 代理/scope:`utils/proxy.ts:64-66`、`:88-129`(NO_PROXY)、`:288-319`、`:327-388`(全局代理)
- claude ssh 隧道:`utils/auth.ts:104-113`、`utils/managedEnv.ts:18-34`;详见 `SSH-ARCHITECTURE.md`
- CA / mTLS:`utils/caCerts.ts:28-32`、`utils/mtls.ts`;CCR 参考:`upstreamproxy/upstreamproxy.ts`
