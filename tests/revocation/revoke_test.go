package revocation_test

import (
	"testing"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/platform"
)

func TestRevokedAgentIsDeniedWhileTheTokenStillVerifies(t *testing.T) {
	lab := newLab(t)
	ada, err := lab.Identity("ada")
	if err != nil {
		t.Fatal(err)
	}
	before := lab.Call(lab.Token("go-inventory"), platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if !before.Allow {
		t.Fatal(before.Reason)
	}
	if err := lab.RevokeAgent(ada, platform.AgentGo); err != nil {
		t.Fatal(err)
	}
	after := lab.Call(lab.Token("go-inventory"), platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if after.Allow || after.Reason != "identity_revoked" {
		t.Fatalf("%+v", after)
	}
	if _, err := lab.Tokens.Parse(lab.Token("go-inventory")); err != nil {
		t.Fatal("revocation should not depend on destroying the signature")
	}
}

func TestRegistryOutageDoesNotAllow(t *testing.T) {
	lab := newLab(t)
	lab.Registry.SetAvailable(false)
	before := lab.MockCalls(platform.ServerInventory)
	result := lab.Call(lab.Token("go-inventory"), platform.ServerInventory, platform.ToolQuery, platform.ResourceInv)
	if result.Allow || result.Reason != "registry_unavailable" || lab.MockCalls(platform.ServerInventory) != before {
		t.Fatalf("%+v", result)
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
