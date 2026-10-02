// Package models 定义持久化层的数据结构。
package models

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// NullString / NullTime 复用标准库可空标量类型，便于 pgx 直接互操作。
type (
	NullString = sql.NullString
	NullTime   = sql.NullTime
)

type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	CreatedAt time.Time
}

type Provider struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	Issuer         string
	ClientID       string
	ClientSecret   string
	RedirectURIs   []string
	AuthTimeMaxAge int
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Member struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	DisplayName string
	CreatedAt   time.Time
}

type Identity struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	MemberID      uuid.UUID
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
}

type AuthRequest struct {
	State        string
	Kind         string
	TenantID     uuid.UUID
	IDPID        uuid.UUID
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
	LinkToken    NullString
	HandoffID    *uuid.UUID
	SessionID    *uuid.UUID
	CreatedAt    time.Time
}

type Session struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	MemberID  uuid.UUID
	TokenHash []byte
	ExpiresAt time.Time
}

type LinkSession struct {
	Token          string
	TenantID       uuid.UUID
	AnchorMemberID uuid.UUID
	SessionID      uuid.UUID
	TargetIDPID    uuid.UUID
	AIssuer        string
	ASubject       string
	AAuthTime      NullTime
	BIssuer        string
	BSubject       string
	BEmail         string
	BAuthTime      NullTime
	BIDPID         uuid.UUID
	BState         string
	Status         string
	ExpiresAt      time.Time
}

// 交接申请状态机（DB CHECK 与之一一对应）：
//
//	owner_pending  -> target_pending -> completed
//	       |               |
//	       v               v
//	    rejected / cancelled / expired（均为终态）
const (
	HandoffOwnerPending  = "owner_pending"
	HandoffTargetPending = "target_pending"
	HandoffCompleted     = "completed"
	HandoffRejected      = "rejected"
	HandoffCancelled     = "cancelled"
	HandoffExpired       = "expired"
)

// HandoffRequest 是一条租户内身份交接申请。
// 令牌与邮箱绝不持久化：OIDC 证明只保留 (issuer,subject) 锚点与 auth_time。
type HandoffRequest struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	IdentityID     uuid.UUID
	Issuer         string
	Subject        string
	OwnerMemberID  uuid.UUID
	TargetMemberID uuid.UUID

	// TargetAnchorIssuer/TargetAnchorSubject 是目标成员当前持有的已核实身份锚点。
	TargetAnchorIssuer  string
	TargetAnchorSubject string

	OwnerSessionID  *uuid.UUID
	TargetSessionID *uuid.UUID

	OwnerConfirmState  string
	TargetConfirmState string

	OwnerAuthIssuer   string
	OwnerAuthSubject  string
	OwnerAuthTime     NullTime
	TargetAuthIssuer  string
	TargetAuthSubject string
	TargetAuthTime    NullTime

	Status    string
	CreatedAt time.Time
	ExpiresAt time.Time

	OwnerConfirmedAt  NullTime
	TargetConfirmedAt NullTime
	CompletedAt       NullTime
	DecidedAt         NullTime
}

// IsParticipant 判断成员是否为该申请的一方。
func (h *HandoffRequest) IsParticipant(memberID uuid.UUID) bool {
	return h.OwnerMemberID == memberID || h.TargetMemberID == memberID
}

// HandoffRecord 是完成时留下的审计记录：无令牌、无邮箱。
type HandoffRecord struct {
	ID                uuid.UUID
	HandoffID         uuid.UUID
	TenantID          uuid.UUID
	IdentityID        uuid.UUID
	Issuer            string
	Subject           string
	FromMemberID      uuid.UUID
	ToMemberID        uuid.UUID
	OwnerSessionID    uuid.UUID
	TargetSessionID   uuid.UUID
	OwnerAuthIssuer   string
	OwnerAuthSubject  string
	OwnerAuthTime     NullTime
	TargetAuthIssuer  string
	TargetAuthSubject string
	TargetAuthTime    NullTime
	CreatedAt         time.Time
	CompletedAt       time.Time
}
