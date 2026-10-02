# oidctenant —— 多租户 OIDC 登录与账号关联 API

无前端的后端服务，演示并落地以下安全目标：

1. **业务身份只基于已核实的提供方组合** `(tenant_id, issuer, subject)`，
   `email` 仅作展示，绝不参与账号匹配 —— 两家企业的员工邮箱相同也不会串号。
2. 完整校验 OIDC 授权码流程的**签名、受众（aud/azp）、issuer、有效期、nonce、state、PKCE**。
3. **账号关联要求两个身份各自重新认证**（OIDC `prompt=login` + `auth_time` 新鲜度窗口）。
4. **登录/关联回调重复到达不会创建多个成员**（state 一次性消费 + 咨询锁 + 唯一约束）。
5. **只允许已配置的回调地址**（精确白名单匹配）。
6. **身份令牌绝不写进日志**（只记录错误分类，不记录 code/token）。

## 目录结构

```
cmd/server/             HTTP 服务入口（含过期 state 定时清理）
cmd/seed/               幂等写入租户与 IdP 配置
internal/config/        环境配置
internal/db/            pgx 连接池 + 嵌入式 SQL 迁移
internal/models/        持久化数据结构
internal/store/         所有 PostgreSQL 访问（事务、咨询锁、原子关联）
internal/oidcx/         go-oidc + oauth2 封装（发现/校验/交换/PKCE/nonce）
internal/auth/          state/nonce/PKCE/会话令牌随机值与哈希、回调白名单
internal/api/           HTTP handler：登录、回调、me、登出、账号关联
deploy/keycloak/import  acme / globex 两个测试 realm（含同邮箱用户）
deploy/seed.json        租户/IdP 的 seed 规格
integration/            针对真实 Keycloak + 真实 PostgreSQL 的端到端集成测试
```

## 数据模型要点

| 表 | 关键约束 / 含义 |
| --- | --- |
| `tenants` | 租户 |
| `identity_providers` | 租户**授权**的 `(issuer, client_id, secret, redirect_uris[])`，按 `(tenant_id, issuer)` 唯一 |
| `members` | 租户内的成员（业务账号） |
| `identities` | 已核实身份；**`UNIQUE(tenant_id, issuer, subject)` 是身份锚点**；`email` 无唯一约束 |
| `auth_requests` | 进行中的授权请求：`state` 主键 + `nonce` + `pkce_verifier`，一次性消费（`consumed_at`） |
| `sessions` | 不透明会话令牌（数据库存 SHA-256 哈希） |
| `link_sessions` | 账号关联会话：A/B 两条 leg 的 issuer/subject/auth_time，一次性 token |
| `handoff_requests` | 身份交接申请：显式状态机 `owner_pending → target_pending → completed`，以及 `rejected/cancelled/expired` 终态；双方各自绑定当前会话与一次性确认 state；部分唯一索引保证同一身份至多一个活申请 |
| `handoff_records` | 交接完成审计记录：身份锚点、双方成员/会话、双方 OIDC 证明锚点与 auth_time；**刻意不含邮箱与任何令牌** |

> 关联外部身份时，身份行的 `tenant_id` 是**发起关联的租户**。
> 因此 A 公司成员关联 B 公司 IdP 的身份，锚点是 `(A租户, B的issuer, subject)`，
> 与 B 公司自己的同名身份互不影响。

## API

所有业务错误返回稳定的 JSON：

```json
{ "error": "<error_type>", "message": "<human readable>" }
```

| error_type | HTTP | 触发场景 |
| --- | --- | --- |
| `authentication_failed` | 401 | 签名/受众/issuer/过期/nonce/PKCE/授权码交换失败、会话无效 |
| `tenant_unauthorized` | 403 | 租户未启用该 issuer、provider 被禁用、跨租户使用会话 |
| `binding_conflict` | 409 | 目标身份已绑给别的成员、自关联、关联会话重放 |
| `invalid_request` | 400 | state 缺失/已用/伪造、回调地址不在白名单、参数非法 |
| `reauthentication_required` | 401 | 关联/交接确认时某一身份未在 `auth_time_max_age` 窗口内重新认证 |
| `handoff_conflict` | 409 | 交接申请处于不允许该操作的状态（重复确认、回调乱序、申请已取消/拒绝/完成、同一身份已有活申请、身份不属调用方） |
| `handoff_expired` | 410 | 交接申请已超过有效期 |
| `handoff_not_found` | 404 | 申请不存在，或当前成员/租户不是参与方（不区分二者，避免枚举） |

端点：

| 方法/路径 | 说明 |
| --- | --- |
| `GET  /healthz` | 健康检查 |
| `GET  /t/{slug}/login?issuer=...&return_to=/...` | 发起登录，302 到 IdP |
| `GET  /oauth/callback` | 登录回调（固定路径） |
| `GET  /t/{slug}/api/me` | 当前成员与其已绑定身份（需会话 Cookie `sid`） |
| `POST /t/{slug}/api/logout` | 吊销会话 |
| `POST /t/{slug}/api/links` | 发起账号关联，返回 `link_token` 与 `link_url`；body `{"issuer":"..."}` |
| `GET  /oauth/link/callback` | 关联第二身份的回调（强制重认证） |
| `GET  /t/{slug}/api/links/{token}` | 查询关联会话状态（一次性） |
| `POST /t/{slug}/api/handoffs` | 发起身份交接申请：`{"identity":{"issuer","subject"},"target":{"issuer","subject"}}`（目标成员只用已核实锚点定位，绝不按邮箱）；返回 201 申请视图（`owner_pending`） |
| `GET  /t/{slug}/api/handoffs` | 列出**本人参与**的全部申请（原绑定方或目标方） |
| `GET  /t/{slug}/api/handoffs/{id}` | 查询单个申请（仅参与方，且必须同租户） |
| `POST /t/{slug}/api/handoffs/{id}/confirm` | 发起本人这一方的确认，返回 `confirm_url`（强制 `prompt=login`） |
| `GET  /oauth/handoff/callback` | 双方确认共用的 OIDC 回调（一次性 state；目标方确认通过即在同请求内完成） |
| `POST /t/{slug}/api/handoffs/{id}/reject` | 原绑定方在 `owner_pending`、目标方在 `target_pending` 拒绝 |
| `POST /t/{slug}/api/handoffs/{id}/cancel` | 任意参与方在申请存活时取消（双方在各自阶段均可） |
| `POST /t/{slug}/api/handoffs/{id}/complete` | 幂等完成入口（目标方回调通常已自动完成；用于双方确认都已新鲜提交后的显式完成） |

## 安全实现细节

- **state / nonce / PKCE**：均为 ≥256/128-bit 加密随机值，服务端持久化；
  PKCE 使用 S256；回调时 state 行被 `SELECT ... FOR UPDATE` 原子取出并标记消费，
  未知 state 与已消费 state 返回完全一致的错误（不泄露有效性）。
- **ID token 校验**（`internal/oidcx`，基于 coreos/go-oidc v3）：
  - 签名经 IdP JWKS 验证；go-oidc 的远程 KeySet 在遇到未知 `kid` 时自动重取 JWKS，
    **密钥轮换对应用透明**；
  - `iss` 必须等于发现文档 issuer；`aud` 必须包含本 client_id；`azp`（若有）必须等于本 client；
  - 过期/nbf/iat 由 go-oidc 校验；`nonce` 与 state 行中的值逐字节比较。
- **重复回调不重复建成员**：`LoginOrRegisterMember` 在事务内先取
  `pg_advisory_xact_lock(hashtextextended(issuer|subject))`，再查/插成员与身份；
  叠加 `UNIQUE(tenant_id, issuer, subject)`，并发首次登录也只产生一个成员。
- **账号关联双重认证**：发起记录 A 的认证时刻；对 B 的授权请求强制
  `prompt=login&max_age=0`，回调核对 IdP 的 `auth_time`；
  `CompleteLink` 在单事务里复核两条 leg 的新鲜度、A 锚点未被改动、B 非自身、
  B 是否已属于他人（冲突则整体回滚，不写入）。
- **回调白名单**：`redirect_uri` 与 `identity_providers.redirect_uris` 做**精确**匹配，
  不做前缀/通配，杜绝 open redirect。
- **日志脱敏**：访问日志把 query 中的 `code/id_token/access_token/refresh_token/state/token`
  统一替换为 `[REDACTED]`；认证失败只记录分类（signature/audience/nonce/...），
  全代码路径不打印原始令牌。
- **身份交接（离职成员 → 新员工）**：
  - 显式状态机 `owner_pending → target_pending → completed`，终态
    `rejected / cancelled / expired`；**完成前 `identities.member_id` 绝不改变**。
  - 双方确认都强制 `prompt=login,max_age=0` 并核对 IdP `auth_time` 新鲜度；
    每次确认绑定“发起确认的当前会话”与一次性 state，回调时逐字节复核
    会话、成员、租户、角色、state 与 OIDC 锚点 `(issuer,subject)`（邮箱从不参与）。
  - 同一身份的“活”申请由部分唯一索引裁决，并发申请只有一个进入完成路径；
    完成事务与登录路径共用按 `(issuer,subject)` 的事务级咨询锁 + 行锁，
    回调乱序/重复确认/并发完成都不可能产生双归属。
  - `CompleteHandoff` 单事务复核 tenant、issuer、subject、身份当前所有者、
    目标锚点当前归属、双方会话有效性与双方证明新鲜度，再移动 `member_id`，
    并写一条**不含令牌与邮箱**的 `handoff_records` 审计记录。
  - 取消/拒绝/过期会清空待消费 state 绑定：迟到或重放的 OIDC 回调一律
    `handoff_conflict`/`invalid_request`，无法复活终态申请。
  - owner 证明在目标确认前变陈旧时，可在 `target_pending` 重新确认刷新证明，
    原归属在整个过程中保持不变。

## 本地运行

需要 Go 1.23+、Docker（用于 Postgres 与 Keycloak）。

```bash
# 1) 起 Postgres + Keycloak（自动导入两个 realm）
docker compose -f deploy/docker-compose.yml up -d

# 2) 等 Keycloak 就绪后，写入租户/IdP 配置
export DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable
go run ./cmd/seed -file deploy/seed.json

# 3) 启动应用（回调固定为 BASE_URL + /oauth/callback）
BASE_URL=http://localhost:8080 ADDR=:8080 \
DATABASE_URL=postgres://oidc:oidc@localhost:5432/oidctenant?sslmode=disable \
  go run ./cmd/server
```

测试账号（两个 realm 各有一个 `alice@example.com`，刻意同邮箱）：

| realm | 用户名 | 密码 | 邮箱 |
| --- | --- | --- | --- |
| acme | `alice` | `alice-pass` | alice@example.com |
| acme | `carol` | `carol-pass` | carol@example.com |
| globex | `alice.globex` | `aliceg-pass` | alice@example.com |
| globex | `bob` | `bobg-pass` | bob@example.com |

浏览器手动走一遍（无前端，直接访问启动 URL）：

```
http://localhost:8080/t/acme/login?issuer=http://localhost:8180/realms/acme
```

## 测试

### 加密校验单元测试（不需要外部依赖）

```bash
go test ./internal/oidcx/...
```

覆盖：合法令牌基线、错误 nonce、错误受众、过期、伪造 issuer、不受信密钥签名。

### 端到端集成测试（真实 Keycloak + 真实 PostgreSQL）

测试用 `fergusstrange/embedded-postgres` 在进程内拉起真实 PostgreSQL，
但需要一个已导入 realm 的本地 Keycloak（见上）。可用 `KC_BASE_URL` 覆盖地址。

```bash
# Keycloak 已运行且导入了 acme/globex realm（并为测试端口注册回调）后：
KC_BASE_URL=http://localhost:8180 go test ./integration/... -v
```

> 集成测试默认把应用起在 **18080** 端口，因此需要在两个 realm 的 `*-rp` 客户端
> 额外注册 `http://localhost:18080/oauth/callback` 与
> `http://localhost:18080/oauth/link/callback`（生产部署只注册真实端口即可）。

集成用例与题目要求一一对应：

| 用例 | 验证内容 |
| --- | --- |
| `TestCrossTenantSameEmailIsolation` | **跨租户同邮箱**：两个 alice@example.com 落到不同 member；跨租户会话 403 |
| `TestLoginCallbackReplayDoesNotDuplicateMember` | 登录回调重放：第二次 400，成员/身份仍各 1 条 |
| `TestConcurrentFirstLoginsDoNotDuplicateMember` | 并发首次登录（咨询锁+唯一约束）只建一个成员 |
| `TestAuthorizationCodeReplay` | **授权码重复使用**：state 已消费即拒绝 |
| `TestStaleCodeWithFreshStateIsAuthnFailure` | 新 state + 旧 code：Keycloak invalid_grant → 401 `authentication_failed` |
| `TestUnknownAndReplayedState` | 伪造/已用 state 行为一致 |
| `TestSigningKeyRotation` | **密钥轮换**：新增更高优先级 RSA key 后不重启应用即可验证新 kid，旧 kid 仍在 JWKS |
| `TestAccountLinkingHappyPath` | 两个身份各自重认证后关联，一个成员持有两条已核实身份 |
| `TestLinkConflictWhenTargetAlreadyBound` | **绑定冲突**：目标身份已属他人 → 409 `binding_conflict`，不被抢占 |
| `TestLinkSameEmailAcrossTenants` | 跨租户**同邮箱**两身份也能正确关联（按 issuer+subject 而非邮箱） |
| `TestLinkRequiresReauthentication` | 认证超过新鲜度窗口 → 401 `reauthentication_required` |
| `TestLinkCannotBeReplayed` | 关联 state/token 一次性，重放 400，不产生第三条身份 |
| `TestUnauthorizedIssuerForTenant` | 未授权 issuer → 403 `tenant_unauthorized` |
| `TestRedirectURIMustBeWhitelisted` | 未登记回调地址 → 400 `invalid_request` |
| `TestLinkRejectsDisabledProvider` | 关联前禁用 provider 授权 → 403 `tenant_unauthorized` |
| `TestWrongPasswordIsAuthnFailure` | IdP 凭证错误不产生会话/成员 |
| `TestHandoffHappyPath` | 双方确认完成交接：身份只归目标成员，原成员再用它登录落到目标成员；审计记录无令牌/邮箱；参与方/非参与方/跨租户/未认证查询边界 |
| `TestHandoffOwnerRejectKeepsBinding` / `TestHandoffTargetRejectKeepsBinding` | 任一方在自己的窗口拒绝 → `rejected`，原绑定不变，无审计记录 |
| `TestHandoffExpiryKeepsBinding` | `owner_pending`/`target_pending` 阶段过期 → 410 `handoff_expired`，原绑定不变 |
| `TestHandoffConcurrentRequestsOnlyOneActive` | 同身份并发申请只有 1 行活申请，只有它能完成；终态后可再建新申请 |
| `TestHandoffConcurrentCompleteOnlyOneMoves` | 双方证明就位后并发完成，恰好一个成功，无双重归属/双审计记录 |
| `TestHandoffCancelledLateCallbackCannotRevive` | 取消后迟到的 OIDC 回调 409、重放 400，申请不复活、身份不移动 |
| `TestHandoffWrongSessionAndTenantCannotParticipate` | 错误会话、跨租户会话/锚点、同邮箱跨租户用户都不能参与交接 |
| `TestHandoffOwnerStaleProofMustReconfirm` | owner 证明陈旧时完成被拒 401，重新新近确认后才完成，期间归属不变 |
| `TestHandoffProofAnchorMismatchRejected` | 确认时认证成别的身份 → 401，证明不写入、状态不推进 |
| `TestHandoffCreateValidation` | 交接他人身份 409、自我交接 400、锚点不存在 404、坏请求体 400；普通关联冲突行为不受影响 |

## 生产化前还应补充（本项目刻意省略）

- provider `client_secret` / 会话存储的 KMS 加密与静态加密；
- CSRF 防护（state 已绑定浏览器会话，仍建议对发起端点加 CSRF token）；
- issuer 级别允许的签名算法/时钟偏移（leeway）做成可配置；
- refresh token 轮转、会话固定防护、`sid`/`jti` 反向注销（back-channel logout）；
- 普通账号关联也补一份与 `handoff_records` 同规格的审计记录
  （目前交接已留审计，关联仅依赖应用日志）；
- 交接申请支持目标方主动“接受/拒绝”的通知通道（当前目标方需轮询 `GET /api/handoffs`）。
