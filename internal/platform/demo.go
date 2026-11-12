package platform

import (
	"strings"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
)

type DemoReport struct {
	Tenant             string `json:"tenant"`
	Agents             int    `json:"agents"`
	Servers            int    `json:"servers"`
	InventoryQuery     string `json:"inventory_query"`
	TestPing           string `json:"test_ping"`
	AdminTool          string `json:"admin_tool"`
	ApprovalRequired   string `json:"approval_required"`
	SelfApproval       string `json:"self_approval"`
	GrantTTLSeconds    int    `json:"grant_ttl_seconds"`
	SensitiveAllowed   string `json:"sensitive_allowed"`
	SensitiveExpired   string `json:"sensitive_expired"`
	WrongAudience      string `json:"wrong_audience"`
	ToolChange         string `json:"tool_change"`
	ReviewRevision     uint64 `json:"review_revision"`
	ReviewAccepted     string `json:"review_accepted"`
	Revoked            string `json:"revoked"`
	CrossTenant        string `json:"cross_tenant"`
	PolicyDown         string `json:"policy_down"`
	GatewayDown        string `json:"gateway_down"`
	InboundForwarded   bool   `json:"inbound_forwarded"`
	UnauthorizedGrants int    `json:"unauthorized_grants"`
	AuditMissing       int    `json:"audit_missing"`
	ProtectedCalls     int    `json:"protected_calls_during_outage"`
	Price              string `json:"price"`
}

// Demo runs the synthetic MCP scenarios. It does not contact Project 1 or a customer agent.
func (l *Lab) Demo() (DemoReport, error) {
	cedarAgents := 0
	for _, agent := range l.Registry.Agents() {
		if agent.TenantID == TenantCedar {
			cedarAgents++
		}
	}
	report := DemoReport{Tenant: TenantCedar, Price: "none", Agents: cedarAgents, Servers: len(l.Registry.Servers())}
	ada, err := l.Identity("ada")
	if err != nil {
		return report, err
	}
	jules, err := l.Identity("jules")
	if err != nil {
		return report, err
	}
	kiran, err := l.Identity("kiran")
	if err != nil {
		return report, err
	}
	query := l.Call(l.Token("go-inventory"), ServerInventory, ToolQuery, ResourceInv)
	report.InventoryQuery = query.Reason
	report.InboundForwarded = l.forwarded(ServerInventory, l.Token("go-inventory"))
	ping := l.Call(l.Token("test-inventory"), ServerInventory, ToolPing, ResourceTest)
	report.TestPing = ping.Reason
	beforeAdmin := l.MockCalls(ServerAdmin)
	adminCall := l.Call(l.Token("go-admin"), ServerAdmin, ToolAdmin, ResourceInv)
	report.AdminTool = adminCall.Reason
	if l.MockCalls(ServerAdmin) != beforeAdmin {
		report.UnauthorizedGrants = 1
	}
	needs := l.Call(l.Token("go-admin"), ServerAdmin, ToolApply, ResourceInv)
	report.ApprovalRequired = needs.Reason
	request, err := l.RequestAccess(jules, AgentGo, ServerAdmin, ToolApply, ResourceInv, "token eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.sig")
	if err != nil {
		return report, err
	}
	if _, err := l.Approve(jules, request.ID); err != nil {
		report.SelfApproval = codeOf(err)
	}
	grant, err := l.Approve(kiran, request.ID)
	if err != nil {
		return report, err
	}
	report.GrantTTLSeconds = int(grant.ExpiresAtUnix - l.Clock.Now().Unix())
	allowed := l.Call(l.Token("go-admin"), ServerAdmin, ToolApply, ResourceInv)
	report.SensitiveAllowed = allowed.Reason
	l.Clock.Advance(6 * time.Minute)
	expired := l.Call(l.Token("go-admin"), ServerAdmin, ToolApply, ResourceInv)
	report.SensitiveExpired = expired.Reason
	wrong := l.Call(l.Token("go-admin"), ServerInventory, ToolQuery, ResourceInv)
	report.WrongAudience = wrong.Reason
	if _, err := l.UpdateTool(ada, ServerInventory, ToolQuery, "export", "", ""); err != nil {
		return report, err
	}
	changed := l.Call(l.Token("lang-inventory"), ServerInventory, ToolQuery, ResourceInv)
	report.ToolChange = changed.Reason
	if _, err := l.AcceptReview(ada, ServerInventory, ToolQuery); err != nil {
		return report, err
	}
	report.ReviewRevision = l.Policy.Revision()
	accepted := l.Call(l.Token("lang-inventory"), ServerInventory, ToolQuery, ResourceInv)
	report.ReviewAccepted = accepted.Reason
	if err := l.RevokeAgent(ada, AgentGo); err != nil {
		return report, err
	}
	revoked := l.Call(l.Token("go-inventory"), ServerInventory, ToolQuery, ResourceInv)
	report.Revoked = revoked.Reason
	cross := l.Call(l.Token("birch-inventory"), ServerInventory, ToolQuery, ResourceInv)
	report.CrossTenant = cross.Reason
	calls := l.MockCalls(ServerInventory) + l.MockCalls(ServerAdmin)
	l.Policy.SetAvailable(false)
	down := l.Call(l.Token("lang-inventory"), ServerInventory, ToolQuery, ResourceInv)
	report.PolicyDown = down.Reason
	l.Policy.SetAvailable(true)
	l.Proxy.GatewayUp = false
	closed := l.Call(l.Token("lang-inventory"), ServerInventory, ToolQuery, ResourceInv)
	report.GatewayDown = closed.Reason
	l.Proxy.GatewayUp = true
	report.ProtectedCalls = (l.MockCalls(ServerInventory) + l.MockCalls(ServerAdmin)) - calls
	for _, grant := range l.Approvals.Grants() {
		if grant.Action == ToolAdmin {
			report.UnauthorizedGrants++
		}
	}
	report.AuditMissing = l.missingAudit()
	return report, nil
}

func (l *Lab) forwarded(serverID, inbound string) bool {
	seen := l.LastCredential(serverID)
	return seen == "" || seen == inbound || strings.Contains(seen, inbound)
}

func (l *Lab) missingAudit() int {
	required := []string{"permit", "denied", "approval_required", "grant_permit", "grant_expired", "audience_mismatch", "policy_review_required", "identity_revoked", "policy_unavailable", "gateway_unavailable"}
	seen := map[string]modelEvent{}
	for _, event := range l.AuditLog.Events() {
		seen[event.Decision] = modelEvent{ok: event.Principal != "" && event.Server != "" && event.Tool != "" && event.Resource != "" && event.Revision > 0 && event.Decision != ""}
	}
	missing := 0
	for _, decision := range required {
		item, ok := seen[decision]
		if !ok || !item.ok {
			missing++
		}
	}
	return missing
}

type modelEvent struct{ ok bool }

func codeOf(err error) string {
	item, ok := apperr.As(err)
	if !ok {
		return ""
	}
	return item.Code
}
