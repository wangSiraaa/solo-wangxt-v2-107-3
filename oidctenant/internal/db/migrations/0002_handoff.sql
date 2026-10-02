-- 0002_handoff.sql
-- 租户内“身份交接申请”流程。
--
-- 核心不变量：
--   * 申请进入 completed 之前，identities.member_id 绝不改变，身份始终归原成员；
--   * 同一身份同一时刻至多存在一个“活”申请（部分唯一索引），并发申请只有一个能进入完成路径；
--   * 完成在单事务内复核 tenant/issuer/subject/当前所有者/双方会话/双方新近 OIDC 证明，
--     再移动归属，并写一条不含令牌与邮箱的审计记录。

-- auth_requests.kind 增加交接双方的两类授权请求。
ALTER TABLE auth_requests DROP CONSTRAINT IF EXISTS auth_requests_kind_check;
ALTER TABLE auth_requests ADD CONSTRAINT auth_requests_kind_check
    CHECK (kind IN ('login', 'link_a', 'link_b', 'handoff_owner', 'handoff_target'));

CREATE TABLE handoff_requests (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id      uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    -- 冗余锚点：完成事务里必须与 identities 当前行逐字段一致（绝不按邮箱判定）。
    issuer           text NOT NULL,
    subject          text NOT NULL,
    owner_member_id  uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    target_member_id uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    -- 目标成员在本租户内的一条已核实身份锚点：目标方必须用它新近认证，
    -- 完成事务里复核该锚点此刻仍属于目标成员（绝不按邮箱判定）。
    target_anchor_issuer  text NOT NULL,
    target_anchor_subject text NOT NULL,

    -- 双方各自“当前会话”的绑定：发起方在创建时绑定，另一方在首次发起确认时绑定。
    owner_session_id  uuid REFERENCES sessions(id) ON DELETE CASCADE,
    target_session_id uuid REFERENCES sessions(id) ON DELETE CASCADE,

    -- 待一次性消费的 OIDC state（与 auth_requests 行对应），消费/终态后清空。
    owner_confirm_state  text NOT NULL DEFAULT '',
    target_confirm_state text NOT NULL DEFAULT '',

    -- 双方新近 OIDC 证明的锚点与 auth_time；只存锚点，绝不存令牌，绝不存邮箱。
    owner_auth_issuer   text NOT NULL DEFAULT '',
    owner_auth_subject  text NOT NULL DEFAULT '',
    owner_auth_time     timestamptz,
    target_auth_issuer  text NOT NULL DEFAULT '',
    target_auth_subject text NOT NULL DEFAULT '',
    target_auth_time    timestamptz,

    status text NOT NULL CHECK (status IN (
        'owner_pending',  -- 已申请，等待原绑定成员确认
        'target_pending', -- 原绑定成员已确认，等待目标成员确认
        'completed',      -- 双方确认完成，归属已移动
        'rejected',       -- 一方拒绝（终态）
        'cancelled',      -- 一方取消（终态）
        'expired'         -- 超过 expires_at（终态）
    )),

    created_at         timestamptz NOT NULL DEFAULT now(),
    expires_at         timestamptz NOT NULL,
    owner_confirmed_at timestamptz,
    target_confirmed_at timestamptz,
    completed_at       timestamptz,
    decided_at         timestamptz,

    CHECK (owner_member_id <> target_member_id)
);

-- 同一身份至多一个活申请：并发插入由数据库裁决，只有一行能成功。
CREATE UNIQUE INDEX uq_handoff_active_identity
    ON handoff_requests (identity_id)
    WHERE status IN ('owner_pending', 'target_pending');
-- 参与方查询本人申请。
CREATE INDEX idx_handoff_participants
    ON handoff_requests (tenant_id, owner_member_id, target_member_id);
-- 过期清扫。
CREATE INDEX idx_handoff_expires
    ON handoff_requests (status, expires_at);

-- 交接确认授权请求指向的申请（link 场景继续使用 link_token）。
ALTER TABLE auth_requests ADD COLUMN handoff_id uuid
    REFERENCES handoff_requests(id) ON DELETE CASCADE;

-- 交接审计记录：只记录身份锚点、双方成员/会话与证明锚点/认证时刻。
-- 刻意不含 email、不含任何令牌；FK 也不加（成员后续删除不影响审计可追溯性）。
CREATE TABLE handoff_records (
    id                 uuid PRIMARY KEY,
    handoff_id         uuid NOT NULL,
    tenant_id          uuid NOT NULL,
    identity_id        uuid NOT NULL,
    issuer             text NOT NULL,
    subject            text NOT NULL,
    from_member_id     uuid NOT NULL,
    to_member_id       uuid NOT NULL,
    owner_session_id   uuid NOT NULL,
    target_session_id  uuid NOT NULL,
    owner_auth_issuer  text NOT NULL DEFAULT '',
    owner_auth_subject text NOT NULL DEFAULT '',
    owner_auth_time    timestamptz,
    target_auth_issuer  text NOT NULL DEFAULT '',
    target_auth_subject text NOT NULL DEFAULT '',
    target_auth_time    timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz NOT NULL
);
CREATE INDEX idx_handoff_records_identity ON handoff_records (identity_id, created_at);
CREATE INDEX idx_handoff_records_handoff ON handoff_records (handoff_id);
