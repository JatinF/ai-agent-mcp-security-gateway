package platform

import (
	"net/http"
	"sync"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/examples/mock-mcp-servers"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/approval"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/audit"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/auth"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/clock"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/config"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/mcp"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/policy"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/registry"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/telemetry"
)

type Lab struct {
	Clock     *clock.Clock
	Tokens    *auth.Issuer
	Registry  *registry.Store
	Policy    *policy.Engine
	Approvals *approval.Service
	AuditLog  *audit.Log
	Proxy     *mcp.Proxy
	Telemetry *telemetry.Hub
	Limits    config.Limits
	Handler   http.Handler
	raw       map[string]string
	env       map[string]string
	mu        sync.Mutex
	mocks     map[string]*mockmcp.Server
}

func NewLab() (*Lab, error) {
	return New(config.Defaults(), time.Date(2026, 11, 12, 15, 0, 0, 0, time.UTC))
}

func New(limits config.Limits, now time.Time) (*Lab, error) {
	clk := clock.New(now)
	issuer, err := auth.NewIssuer(clk)
	if err != nil {
		return nil, err
	}
	engine, err := policy.New(PolicyID)
	if err != nil {
		return nil, err
	}
	reg := registry.New()
	approvals := approval.New(limits.GrantTTL)
	log := audit.New()
	hub := telemetry.New("gateway")
	inventory := mockmcp.New(ServerInventory, issuer, map[string]string{
		ToolQuery: `{"resource":"SYN-INV-TEST","state":"present"}`,
		ToolPing:  `{"pong":true}`,
	})
	admin := mockmcp.New(ServerAdmin, issuer, map[string]string{
		ToolAdmin: `{"admin":true}`,
		ToolApply: `{"simulated":true,"applied":false}`,
	})
	lab := &Lab{
		Clock: clk, Tokens: issuer, Registry: reg, Policy: engine, Approvals: approvals,
		AuditLog: log, Telemetry: hub, Limits: limits, raw: map[string]string{}, env: map[string]string{},
		mocks: map[string]*mockmcp.Server{ServerInventory: inventory, ServerAdmin: admin},
	}
	lab.Proxy = &mcp.Proxy{
		Clock: clk, Tokens: issuer, Registry: reg, Policy: engine, Approvals: approvals,
		Audit: log, Telemetry: hub, GatewayUp: true, CredTTL: limits.DownstreamTTL,
		Backends: map[string]mcp.Backend{ServerInventory: inventory, ServerAdmin: admin},
	}
	if err := lab.seed(); err != nil {
		return nil, err
	}
	lab.Handler = newHTTP(lab)
	return lab, nil
}

func (l *Lab) seed() error {
	agents := []model.Agent{
		{ID: AgentLang, TenantID: TenantCedar, Owner: UserAda, Runtime: "langgraph", Environment: "lab", Status: "active"},
		{ID: AgentGo, TenantID: TenantCedar, Owner: UserJules, Runtime: "go", Environment: "lab", Status: "active"},
		{ID: AgentTest, TenantID: TenantCedar, Owner: UserKiran, Runtime: "test-automation", Environment: "lab", Status: "active"},
		{ID: AgentBirch, TenantID: TenantBirch, Owner: "SYN-USER-BIRCH", Runtime: "go", Environment: "lab", Status: "active"},
	}
	for _, agent := range agents {
		if err := l.Registry.PutAgent(agent); err != nil {
			return err
		}
	}
	servers := []model.Server{
		{ID: ServerInventory, TenantID: TenantCedar, Owner: UserAda, Endpoint: "inprocess://SYN-MCP-INVENTORY", Audience: auth.Audience(ServerInventory), Status: "approved"},
		{ID: ServerAdmin, TenantID: TenantCedar, Owner: UserAda, Endpoint: "inprocess://SYN-MCP-ADMIN", Audience: auth.Audience(ServerAdmin), Status: "approved"},
	}
	for _, server := range servers {
		if err := l.Registry.PutServer(server); err != nil {
			return err
		}
	}
	tools := []model.Tool{
		{ID: "tool-query", ServerID: ServerInventory, Name: ToolQuery, Operation: "read", ResourceScope: ResourceInv, Risk: "low", ReviewStatus: "approved"},
		{ID: "tool-ping", ServerID: ServerInventory, Name: ToolPing, Operation: "ping", ResourceScope: ResourceTest, Risk: "low", ReviewStatus: "approved"},
		{ID: "tool-admin", ServerID: ServerAdmin, Name: ToolAdmin, Operation: "admin", ResourceScope: ResourceInv, Risk: "high", ReviewStatus: "approved"},
		{ID: "tool-apply", ServerID: ServerAdmin, Name: ToolApply, Operation: "apply", ResourceScope: ResourceInv, Risk: "high", Sensitive: true, ReviewStatus: "approved"},
	}
	for _, tool := range tools {
		if err := l.Registry.PutTool(tool); err != nil {
			return err
		}
	}
	allows := [][3]string{
		{AgentLang, ServerInventory, ToolQuery},
		{AgentGo, ServerInventory, ToolQuery},
		{AgentGo, ServerAdmin, ToolApply},
		{AgentTest, ServerInventory, ToolPing},
	}
	for _, item := range allows {
		if err := l.Registry.Allow(item[0], item[1], item[2]); err != nil {
			return err
		}
	}
	pairs := []struct {
		name, subject, audience, tenant string
		roles                           []string
	}{
		{"ada", UserAda, auth.GatewayAudience, TenantCedar, []string{RoleAdmin}},
		{"jules", UserJules, auth.GatewayAudience, TenantCedar, []string{RoleRequester}},
		{"kiran", UserKiran, auth.GatewayAudience, TenantCedar, []string{RoleApprover}},
		{"go-inventory", AgentGo, auth.Audience(ServerInventory), TenantCedar, nil},
		{"go-admin", AgentGo, auth.Audience(ServerAdmin), TenantCedar, nil},
		{"lang-inventory", AgentLang, auth.Audience(ServerInventory), TenantCedar, nil},
		{"test-inventory", AgentTest, auth.Audience(ServerInventory), TenantCedar, nil},
		{"birch-inventory", AgentBirch, auth.Audience(ServerInventory), TenantBirch, nil},
	}
	for _, pair := range pairs {
		raw, err := l.Tokens.Issue(pair.subject, pair.audience, pair.tenant, pair.roles, l.Limits.TokenTTL, false, "")
		if err != nil {
			return err
		}
		l.raw[pair.name] = raw
	}
	return nil
}

func (l *Lab) Token(name string) string { return l.raw[name] }

func (l *Lab) SetEnv(key, value string) {
	l.mu.Lock()
	l.env[key] = value
	l.mu.Unlock()
}

func (l *Lab) MockCalls(serverID string) int { return l.mocks[serverID].Calls }

func (l *Lab) LastCredential(serverID string) string { return l.mocks[serverID].LastCredential }
