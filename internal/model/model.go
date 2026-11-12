// Package model is the gateway record set.
// Audit field names used by Project 1 stay on the event so the records can be compared.
package model

type Agent struct {
	ID          string `json:"agent_id"`
	TenantID    string `json:"tenant_id"`
	Owner       string `json:"owner"`
	Runtime     string `json:"runtime"`
	Environment string `json:"environment"`
	Status      string `json:"status"`
}

type Server struct {
	ID       string `json:"server_id"`
	TenantID string `json:"tenant_id"`
	Owner    string `json:"owner"`
	Endpoint string `json:"endpoint"`
	Audience string `json:"audience"`
	Status   string `json:"status"`
}

type Tool struct {
	ID            string `json:"tool_id"`
	ServerID      string `json:"server_id"`
	Name          string `json:"name"`
	Operation     string `json:"operation"`
	ResourceScope string `json:"resource_scope"`
	Risk          string `json:"risk"`
	Sensitive     bool   `json:"sensitive"`
	ReviewStatus  string `json:"review_status"`
}

type Permission struct {
	ID       string `json:"permission_id"`
	AgentID  string `json:"agent_id"`
	ServerID string `json:"server_id"`
	Tool     string `json:"tool"`
	Effect   string `json:"effect"`
}

type AccessRequest struct {
	ID          string `json:"request_id"`
	TenantID    string `json:"tenant_id"`
	RequesterID string `json:"requester"`
	AgentID     string `json:"agent_id"`
	ResourceID  string `json:"resource"`
	Action      string `json:"action"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
}

type Grant struct {
	ID            string `json:"grant_id"`
	TenantID      string `json:"tenant_id"`
	RequestID     string `json:"request_id"`
	SubjectID     string `json:"subject_id"`
	ResourceID    string `json:"resource_id"`
	Action        string `json:"action"`
	Scope         string `json:"scope"`
	ExpiresAtUnix int64  `json:"expiry"`
	RevokedAtUnix int64  `json:"revoked_at"`
}

type AuditEvent struct {
	ID        string `json:"event_id"`
	TenantID  string `json:"tenant_id"`
	Principal string `json:"principal"`
	Action    string `json:"action"`
	Decision  string `json:"decision"`
	PolicyID  string `json:"policy_id"`
	Revision  uint64 `json:"policy_revision"`
	Detail    string `json:"detail,omitempty"`
	AtUnix    int64  `json:"at_unix"`
	Server    string `json:"mcp_server"`
	Tool      string `json:"tool"`
	Resource  string `json:"target_resource"`
	Outcome   string `json:"outcome,omitempty"`
}

type Result struct {
	Allow    bool   `json:"allow"`
	Reason   string `json:"reason"`
	AgentID  string `json:"agent_id,omitempty"`
	ServerID string `json:"mcp_server,omitempty"`
	Tool     string `json:"tool,omitempty"`
	Resource string `json:"target_resource,omitempty"`
	Revision uint64 `json:"policy_revision"`
	Outcome  string `json:"outcome,omitempty"`
}

type Finding struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Detail  string `json:"detail"`
}

type Identity struct {
	ID       string   `json:"identity_id"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

func HasRole(id Identity, role string) bool {
	for _, item := range id.Roles {
		if item == role {
			return true
		}
	}
	return false
}
