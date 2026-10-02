-- 0002_identity_handovers.sql
-- 租户内已核实身份交接。
--
-- 交接完成前 identities.member_id 绝不改变；所有活跃申请由部分唯一索引限制为
-- 每个 (tenant_id, identity_id) 最多一条。审计表只保存锚点/成员/会话/状态，
-- 不保存 OIDC state、nonce、PKCE、令牌或邮箱。

ALTER TABLE auth_requests DROP CONSTRAINT auth_requests_kind_check;
ALTER TABLE auth_requests ADD CONSTRAINT auth_requests_kind_check
    CHECK (kind IN ('login', 'link_a', 'link_b', 'handover_source', 'handover_target'));
ALTER TABLE auth_requests ADD COLUMN handover_id uuid;

CREATE TABLE identity_handovers (
    id                    uuid PRIMARY KEY,
    tenant_id             uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id           uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    identity_issuer       text NOT NULL,
    identity_subject      text NOT NULL,
    source_member_id      uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    target_member_id      uuid NOT NULL REFERENCES members(id) ON DELETE CASCADE,
    created_by_session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,

    status                text NOT NULL DEFAULT 'pending'
                          CHECK (status IN (
                              'pending',
                              'source_confirmed',
                              'target_confirmed',
                              'completed',
                              'rejected',
                              'cancelled',
                              'expired'
                          )),

    source_session_id     uuid REFERENCES sessions(id) ON DELETE SET NULL,
    source_idp_id         uuid REFERENCES identity_providers(id) ON DELETE SET NULL,
    source_issuer         text NOT NULL DEFAULT '',
    source_subject        text NOT NULL DEFAULT '',
    source_auth_time      timestamptz,
    source_confirmed_at   timestamptz,

    target_session_id     uuid REFERENCES sessions(id) ON DELETE SET NULL,
    target_idp_id         uuid REFERENCES identity_providers(id) ON DELETE SET NULL,
    target_issuer         text NOT NULL DEFAULT '',
    target_subject        text NOT NULL DEFAULT '',
    target_auth_time      timestamptz,
    target_confirmed_at   timestamptz,

    created_at            timestamptz NOT NULL DEFAULT now(),
    expires_at            timestamptz NOT NULL,
    completed_at          timestamptz,
    decided_at            timestamptz,

    CHECK (source_member_id <> target_member_id),
    CHECK (identity_issuer <> '' AND identity_subject <> '')
);

CREATE UNIQUE INDEX unique_active_identity_handover
    ON identity_handovers (tenant_id, identity_id)
    WHERE status IN ('pending', 'source_confirmed', 'target_confirmed');
CREATE INDEX idx_handovers_source_member ON identity_handovers (tenant_id, source_member_id);
CREATE INDEX idx_handovers_target_member ON identity_handovers (tenant_id, target_member_id);
CREATE INDEX idx_handovers_status_expires ON identity_handovers (status, expires_at);

ALTER TABLE auth_requests
    ADD CONSTRAINT auth_requests_handover_fkey
    FOREIGN KEY (handover_id) REFERENCES identity_handovers(id) ON DELETE CASCADE;

-- Append-only 审计事件。事件本身不包含邮箱或任何 OIDC/会话令牌；
-- session_id 只是用于追溯的数据库内引用。
CREATE TABLE identity_handover_events (
    id               uuid PRIMARY KEY,
    handover_id      uuid NOT NULL REFERENCES identity_handovers(id) ON DELETE CASCADE,
    tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    identity_id      uuid NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    actor_member_id  uuid REFERENCES members(id) ON DELETE SET NULL,
    actor_session_id uuid REFERENCES sessions(id) ON DELETE SET NULL,
    event_type       text NOT NULL CHECK (event_type IN (
                         'created',
                         'source_confirmed',
                         'target_confirmed',
                         'completed',
                         'rejected',
                         'cancelled',
                         'expired'
                     )),
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_handover_events_handover ON identity_handover_events (handover_id, created_at);
