package platform

import (
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/analytics"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/auth"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/gates"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
)

func (l *Lab) Authenticate(raw string) (model.Identity, error) {
	claims, err := l.Tokens.Parse(raw)
	if err != nil {
		return model.Identity{}, err
	}
	if claims.Audience != auth.GatewayAudience {
		return model.Identity{}, apperr.New("audience_mismatch", "admin token audience must be the gateway", 401)
	}
	return model.Identity{ID: claims.Subject, TenantID: claims.TenantID, Roles: claims.Roles}, nil
}

func (l *Lab) Call(raw, serverID, tool, resource string) model.Result {
	return l.Proxy.Call(raw, serverID, tool, resource)
}

func (l *Lab) RequestAccess(caller model.Identity, agentID, serverID, tool, resource, reason string) (model.AccessRequest, error) {
	if !model.HasRole(caller, RoleRequester) && !model.HasRole(caller, RoleAdmin) && !model.HasRole(caller, RoleApprover) {
		return model.AccessRequest{}, apperr.New("forbidden", "requester role is required", 403)
	}
	agent, err := l.Registry.Agent(agentID)
	if err != nil {
		return model.AccessRequest{}, err
	}
	if agent.TenantID != caller.TenantID {
		return model.AccessRequest{}, apperr.New("tenant_forbidden", "agent tenant does not match the caller", 403)
	}
	return l.Approvals.Request(caller.TenantID, caller.ID, agentID, serverID, tool, resource, reason, l.Clock.Now().Unix())
}

func (l *Lab) Approve(caller model.Identity, requestID string) (model.Grant, error) {
	item, err := l.Approvals.Get(requestID)
	if err != nil {
		return model.Grant{}, err
	}
	if item.RequesterID == caller.ID {
		return model.Grant{}, apperr.New("self_approval", "requester cannot approve their own request", 403)
	}
	if !model.HasRole(caller, RoleApprover) {
		return model.Grant{}, apperr.New("forbidden", "approver role is required", 403)
	}
	return l.Approvals.Approve(caller.ID, requestID, l.Clock.Now().Unix())
}

func (l *Lab) RevokeGrant(caller model.Identity, requestID string) (model.Grant, error) {
	if !model.HasRole(caller, RoleApprover) && !model.HasRole(caller, RoleAdmin) {
		return model.Grant{}, apperr.New("forbidden", "approver role is required", 403)
	}
	return l.Approvals.Revoke(requestID, l.Clock.Now().Unix())
}

func (l *Lab) RevokeAgent(caller model.Identity, agentID string) error {
	if !model.HasRole(caller, RoleAdmin) || caller.TenantID == "" {
		return apperr.New("forbidden", "registry-admin role is required", 403)
	}
	agent, err := l.Registry.Agent(agentID)
	if err != nil {
		return err
	}
	if agent.TenantID != caller.TenantID {
		return apperr.New("not_found", "agent was not found", 404)
	}
	return l.Registry.SetStatus(agentID, "revoked")
}

func (l *Lab) UpdateTool(caller model.Identity, serverID, name, operation, risk, scope string) (model.Tool, error) {
	if !model.HasRole(caller, RoleAdmin) {
		return model.Tool{}, apperr.New("forbidden", "registry-admin role is required", 403)
	}
	return l.Registry.UpdateCapability(serverID, name, operation, risk, scope)
}

func (l *Lab) AcceptReview(caller model.Identity, serverID, name string) (model.Tool, error) {
	if !model.HasRole(caller, RoleAdmin) {
		return model.Tool{}, apperr.New("forbidden", "registry-admin role is required", 403)
	}
	tool, err := l.Registry.AcceptReview(serverID, name)
	if err != nil {
		return model.Tool{}, err
	}
	l.Policy.Bump()
	return tool, nil
}

func (l *Lab) Events(caller model.Identity) ([]model.AuditEvent, error) {
	if caller.TenantID == "" || !model.HasRole(caller, RoleAdmin) {
		return nil, apperr.New("forbidden", "registry-admin role is required", 403)
	}
	var out []model.AuditEvent
	for _, event := range l.AuditLog.Events() {
		if event.TenantID == caller.TenantID || event.TenantID == "" {
			out = append(out, event)
		}
	}
	return out, nil
}

func (l *Lab) Findings(caller model.Identity) ([]model.Finding, error) {
	if !model.HasRole(caller, RoleAdmin) {
		return nil, apperr.New("forbidden", "registry-admin role is required", 403)
	}
	return analytics.Findings(l.Registry.Tools(), l.Registry.Permissions(), l.AuditLog.Events(), l.Registry.Changes()), nil
}

func (l *Lab) Gates(model.Identity) ([]gates.Gate, error) {
	l.mu.Lock()
	env := map[string]string{}
	for key, value := range l.env {
		env[key] = value
	}
	l.mu.Unlock()
	return gates.Evaluate(env), nil
}

func (l *Lab) Identity(name string) (model.Identity, error) {
	return l.Authenticate(l.Token(name))
}
