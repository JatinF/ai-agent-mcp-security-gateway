package integration_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/platform"
)

func TestDemoScenarios(t *testing.T) {
	lab := newLab(t)
	report, err := lab.Demo()
	if err != nil {
		t.Fatal(err)
	}
	if report.Tenant != platform.TenantCedar || report.Agents != 3 || report.Servers != 2 {
		t.Fatalf("registration: %+v", report)
	}
	if report.InventoryQuery != "permit" || report.TestPing != "permit" || report.AdminTool != "denied" {
		t.Fatalf("tools: %+v", report)
	}
	if report.ApprovalRequired != "approval_required" || report.SelfApproval != "self_approval" || report.GrantTTLSeconds != 300 {
		t.Fatalf("approval: %+v", report)
	}
	if report.SensitiveAllowed != "grant_permit" || report.SensitiveExpired != "grant_expired" {
		t.Fatalf("grant: %+v", report)
	}
	if report.WrongAudience != "audience_mismatch" || report.ToolChange != "policy_review_required" {
		t.Fatalf("audience or review: %+v", report)
	}
	if report.ReviewRevision != 2 || report.ReviewAccepted != "permit" || report.Revoked != "identity_revoked" {
		t.Fatalf("review or revoke: %+v", report)
	}
	if report.CrossTenant != "tenant_forbidden" || report.PolicyDown != "policy_unavailable" || report.GatewayDown != "gateway_unavailable" {
		t.Fatalf("failures: %+v", report)
	}
	if report.InboundForwarded || report.UnauthorizedGrants != 0 || report.AuditMissing != 0 || report.ProtectedCalls != 0 {
		t.Fatalf("safety: %+v", report)
	}
	if report.Price != "none" {
		t.Fatal(report.Price)
	}
	blob, _ := json.Marshal(report)
	if strings.Contains(string(blob), "eyJ") {
		t.Fatal("demo report contains a token")
	}
	if len(lab.Telemetry.SpanNames()) == 0 {
		t.Fatal("no spans")
	}
}

func TestHTTPCallAndGates(t *testing.T) {
	lab := newLab(t)
	denied := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/mcp/call", strings.NewReader(`{"server_id":"SYN-MCP-ADMIN","tool":"inventory.admin","resource":"SYN-INV-TEST"}`))
	lab.Handler.ServeHTTP(denied, req)
	if denied.Code != http.StatusUnauthorized {
		t.Fatal(denied.Code)
	}
	body := strings.NewReader(`{"server_id":"SYN-MCP-INVENTORY","tool":"inventory.query","resource":"SYN-INV-TEST"}`)
	ok := httptest.NewRecorder()
	call := httptest.NewRequest(http.MethodPost, "/v1/mcp/call", body)
	call.Header.Set("Authorization", "Bearer "+lab.Token("go-inventory"))
	lab.Handler.ServeHTTP(ok, call)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), `"allow":true`) {
		t.Fatalf("%d %s", ok.Code, ok.Body.String())
	}
	if strings.Contains(ok.Body.String(), lab.Token("go-inventory")) {
		t.Fatal("response echoed the inbound token")
	}
	lab.SetEnv("MCP_CONTROL_PLANE_URL", "http://synthetic.invalid/secret-value")
	gates := httptest.NewRecorder()
	greq := httptest.NewRequest(http.MethodGet, "/v1/gates", nil)
	greq.Header.Set("Authorization", "Bearer "+lab.Token("ada"))
	lab.Handler.ServeHTTP(gates, greq)
	if gates.Code != http.StatusOK || !strings.Contains(gates.Body.String(), "blocked") || strings.Contains(gates.Body.String(), "secret-value") {
		t.Fatalf("%s", gates.Body.String())
	}
}

func newLab(t *testing.T) *platform.Lab {
	t.Helper()
	lab, err := platform.NewLab()
	if err != nil {
		t.Fatal(err)
	}
	return lab
}
