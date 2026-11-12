// Package mcp is the gateway proxy.
// It forwards a call only after authentication and authorization, and only with a new credential.
package mcp

import (
	"context"
	"strings"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/approval"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/audit"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/auth"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/clock"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/policy"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/registry"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/telemetry"
)

type Backend interface {
	Call(credential, tool, resource string) (string, error)
}

type Proxy struct {
	Clock     *clock.Clock
	Tokens    *auth.Issuer
	Registry  *registry.Store
	Policy    *policy.Engine
	Approvals *approval.Service
	Audit     *audit.Log
	Telemetry *telemetry.Hub
	Backends  map[string]Backend
	GatewayUp bool
	CredTTL   time.Duration
}

func (p *Proxy) Call(rawToken, serverID, toolName, resource string) model.Result {
	_, end := p.Telemetry.Start(context.Background(), "mcp.call")
	defer end()
	result := model.Result{ServerID: serverID, Tool: toolName, Resource: resource, Reason: "denied"}
	if !p.GatewayUp {
		return p.finish(result, "gateway_unavailable", "")
	}
	claims, err := p.Tokens.Parse(rawToken)
	if err != nil {
		return p.finish(result, codeOf(err), "")
	}
	result.AgentID = claims.Subject
	if claims.Delegated {
		return p.finish(result, "credential_rejected", "")
	}
	if claims.Audience != auth.Audience(serverID) {
		return p.finish(result, "audience_mismatch", "")
	}
	if !p.Registry.Available() {
		return p.finish(result, "registry_unavailable", "")
	}
	agent, err := p.Registry.Agent(claims.Subject)
	if err != nil {
		return p.finish(result, codeOf(err), "")
	}
	if agent.TenantID != claims.TenantID {
		return p.finish(result, "tenant_forbidden", "")
	}
	switch agent.Status {
	case "active":
	case "revoked":
		return p.finish(result, "identity_revoked", "")
	default:
		return p.finish(result, "identity_inactive", "")
	}
	server, err := p.Registry.Server(serverID)
	if err != nil {
		return p.finish(result, codeOf(err), "")
	}
	if server.TenantID != agent.TenantID || server.Audience != auth.Audience(serverID) {
		return p.finish(result, "tenant_forbidden", "")
	}
	tool, err := p.Registry.Tool(serverID, toolName)
	if err != nil {
		return p.finish(result, codeOf(err), "")
	}
	if tool.ResourceScope != "" && resource != tool.ResourceScope {
		return p.finish(result, "denied", "")
	}
	result.Revision = p.Policy.Revision()
	if tool.ReviewStatus != "approved" {
		return p.finish(result, "policy_review_required", "")
	}
	if !p.Policy.Available() {
		return p.finish(result, "policy_unavailable", "")
	}
	perm, ok := p.Registry.Permission(agent.ID, serverID, toolName)
	if !ok {
		return p.finish(result, "denied", "")
	}
	grantValid := false
	if tool.Sensitive {
		switch p.Approvals.State(agent.ID, serverID, toolName, resource, p.Clock.Now().Unix()) {
		case "valid":
			grantValid = true
		case "expired":
			return p.finish(result, "grant_expired", "")
		case "revoked":
			return p.finish(result, "grant_revoked", "")
		default:
			return p.finish(result, "approval_required", "")
		}
	}
	allowed, err := p.Policy.Allow(map[string]any{
		"subject":    claims.Subject,
		"agent":      map[string]any{"id": agent.ID, "status": agent.Status, "tenant_id": agent.TenantID},
		"server":     map[string]any{"id": server.ID, "tenant_id": server.TenantID},
		"tool":       map[string]any{"name": tool.Name, "review_status": tool.ReviewStatus, "sensitive": tool.Sensitive},
		"permission": map[string]any{"effect": perm.Effect, "tool": perm.Tool, "server_id": perm.ServerID},
		"grant":      map[string]any{"valid": grantValid, "required": tool.Sensitive},
	})
	if err != nil {
		return p.finish(result, "policy_unavailable", "")
	}
	if !allowed {
		return p.finish(result, "denied", "")
	}
	minted, err := p.Tokens.Issue(agent.ID, auth.Audience(serverID), agent.TenantID, nil, p.CredTTL, true, toolName)
	if err != nil {
		return p.finish(result, codeOf(err), "")
	}
	if minted == rawToken || strings.Contains(minted, rawToken) {
		return p.finish(result, "credential_rejected", "")
	}
	backend := p.Backends[serverID]
	if backend == nil {
		return p.finish(result, "unknown_server", "")
	}
	outcome, err := backend.Call(minted, toolName, resource)
	if err != nil {
		return p.finish(result, codeOf(err), "")
	}
	reason := "permit"
	if tool.Sensitive {
		reason = "grant_permit"
	}
	result.Allow = true
	return p.finish(result, reason, outcome)
}

func codeOf(err error) string {
	item, ok := apperr.As(err)
	if !ok {
		return "denied"
	}
	return item.Code
}

func (p *Proxy) finish(result model.Result, reason, outcome string) model.Result {
	result.Reason = reason
	result.Outcome = outcome
	if result.Revision == 0 && p.Policy != nil {
		result.Revision = p.Policy.Revision()
	}
	tenant := ""
	principal := result.AgentID
	if principal == "" {
		principal = "unknown"
	}
	if result.AgentID != "" && p.Registry != nil {
		if agent, err := p.Registry.Agent(result.AgentID); err == nil {
			tenant = agent.TenantID
		}
	}
	p.Audit.Add(model.AuditEvent{
		TenantID: tenant, Principal: principal, Action: "tools/call", Decision: reason,
		PolicyID: p.Policy.ID(), Revision: result.Revision, Detail: reason, AtUnix: p.Clock.Now().Unix(),
		Server: result.ServerID, Tool: result.Tool, Resource: result.Resource, Outcome: outcome,
	})
	if result.Allow {
		p.Telemetry.Decision("allow")
	} else {
		p.Telemetry.Decision("deny")
	}
	return result
}
