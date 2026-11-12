package token_test

import (
	"strings"
	"testing"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/auth"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/platform"
)

func TestWrongAudienceIsRejected(t *testing.T) {
	lab := newLab(t)
	before := lab.MockCalls(platform.ServerInventory)
	result := lab.Call(lab.Token("go-admin"), platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if result.Allow || result.Reason != "audience_mismatch" || lab.MockCalls(platform.ServerInventory) != before {
		t.Fatalf("%+v", result)
	}
}

func TestExpiredAndTamperedTokens(t *testing.T) {
	lab := newLab(t)
	raw, err := lab.Tokens.Issue(platform.AgentGo, auth.Audience(platform.ServerInventory), platform.TenantCedar, nil, time.Minute, false, "")
	if err != nil {
		t.Fatal(err)
	}
	lab.Clock.Advance(2 * time.Minute)
	expired := lab.Call(raw, platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if expired.Allow || expired.Reason != "token_expired" {
		t.Fatalf("%+v", expired)
	}
	parts := strings.Split(lab.Token("go-inventory"), ".")
	parts[2] = strings.Repeat("a", len(parts[2]))
	tampered := lab.Call(strings.Join(parts, "."), platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if tampered.Allow || tampered.Reason != "signature_invalid" {
		t.Fatalf("%+v", tampered)
	}
}

func TestDownstreamCredentialIsNotTheInboundToken(t *testing.T) {
	lab := newLab(t)
	inbound := lab.Token("go-inventory")
	result := lab.Call(inbound, platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if !result.Allow {
		t.Fatal(result.Reason)
	}
	seen := lab.LastCredential(platform.ServerInventory)
	if seen == inbound || strings.Contains(seen, inbound) {
		t.Fatal("inbound bearer was forwarded")
	}
	claims, err := lab.Tokens.Parse(seen)
	if err != nil || !claims.Delegated || claims.Audience != auth.Audience(platform.ServerInventory) || claims.Tool != platform.ToolQuery {
		t.Fatalf("%+v %v", claims, err)
	}
	direct := lab.Call(seen, platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if direct.Allow || direct.Reason != "credential_rejected" {
		t.Fatalf("delegated credential was accepted as a caller token: %+v", direct)
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
