package authorization_test

import (
	"strings"
	"testing"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/analytics"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/platform"
)

func TestUnauthorizedAdminDoesNotReachTheServer(t *testing.T) {
	lab := newLab(t)
	before := lab.MockCalls(platform.ServerAdmin)
	result := lab.Call(lab.Token("go-admin"), platform.ServerAdmin, platform.ToolAdmin, platform.ResourceInv)
	if result.Allow || result.Reason != "denied" || lab.MockCalls(platform.ServerAdmin) != before {
		t.Fatalf("%+v calls=%d", result, lab.MockCalls(platform.ServerAdmin))
	}
}

func TestSensitiveGrantExpires(t *testing.T) {
	lab := newLab(t)
	jules, _ := lab.Identity("jules")
	kiran, _ := lab.Identity("kiran")
	request, err := lab.RequestAccess(jules, platform.AgentGo, platform.ServerAdmin, platform.ToolApply, platform.ResourceInv, "maintenance window")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lab.Approve(kiran, request.ID); err != nil {
		t.Fatal(err)
	}
	allowed := lab.Call(lab.Token("go-admin"), platform.ServerAdmin, platform.ToolApply, platform.ResourceInv)
	if !allowed.Allow || allowed.Reason != "grant_permit" {
		t.Fatalf("%+v", allowed)
	}
	lab.Clock.Advance(6 * time.Minute)
	expired := lab.Call(lab.Token("go-admin"), platform.ServerAdmin, platform.ToolApply, platform.ResourceInv)
	if expired.Allow || expired.Reason != "grant_expired" {
		t.Fatalf("%+v", expired)
	}
}

func TestToolChangeRequiresReview(t *testing.T) {
	lab := newLab(t)
	ada, _ := lab.Identity("ada")
	if _, err := lab.UpdateTool(ada, platform.ServerInventory, platform.ToolQuery, "export", "high", ""); err != nil {
		t.Fatal(err)
	}
	blocked := lab.Call(lab.Token("lang-inventory"), platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if blocked.Allow || blocked.Reason != "policy_review_required" {
		t.Fatalf("%+v", blocked)
	}
	findings, err := lab.Findings(ada)
	if err != nil {
		t.Fatal(err)
	}
	if !hasKind(findings, "tool_changed") {
		t.Fatalf("%+v", findings)
	}
	if _, err := lab.AcceptReview(ada, platform.ServerInventory, platform.ToolQuery); err != nil {
		t.Fatal(err)
	}
	if lab.Policy.Revision() != 2 {
		t.Fatal(lab.Policy.Revision())
	}
	allowed := lab.Call(lab.Token("lang-inventory"), platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if !allowed.Allow || allowed.Revision != 2 {
		t.Fatalf("%+v", allowed)
	}
}

func TestStandingHighRiskIsExcessive(t *testing.T) {
	lab := newLab(t)
	if err := lab.Registry.Allow(platform.AgentTest, platform.ServerAdmin, platform.ToolAdmin); err != nil {
		t.Fatal(err)
	}
	findings := analytics.Findings(lab.Registry.Tools(), lab.Registry.Permissions(), nil, nil)
	if !hasKind(findings, "excessive_permission") {
		t.Fatalf("%+v", findings)
	}
}

func TestReasonRedaction(t *testing.T) {
	lab := newLab(t)
	jules, _ := lab.Identity("jules")
	request, err := lab.RequestAccess(jules, platform.AgentGo, platform.ServerAdmin, platform.ToolApply, platform.ResourceInv, "eyJhbGciOiJFZDI1NiJ9.eyJzdWIiOiJ4In0.sig")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(request.Reason, "eyJ") {
		t.Fatal(request.Reason)
	}
}

func hasKind(findings []model.Finding, kind string) bool {
	for _, item := range findings {
		if item.Kind == kind {
			return true
		}
	}
	return false
}

func newLab(t *testing.T) *platform.Lab {
	t.Helper()
	lab, err := platform.NewLab()
	if err != nil {
		t.Fatal(err)
	}
	return lab
}
