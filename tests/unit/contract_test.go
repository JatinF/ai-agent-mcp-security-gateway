package unit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/config"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/httpapi"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/policy"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/upstream"
	"github.com/JatinF/ai-agent-mcp-security-gateway/policies"
)

func TestRegoDeniesEmptyInput(t *testing.T) {
	if err := policy.Validate(policies.AgentAccess, policies.ToolPermissions); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New("SYN-POL-MCP")
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := engine.Allow(map[string]any{})
	if err != nil || allowed {
		t.Fatalf("empty allow=%v err=%v", allowed, err)
	}
}

func TestAuditShapeCoversProject1Fields(t *testing.T) {
	event := model.AuditEvent{
		ID: "aud-0001", TenantID: "SYN-TENANT-CEDAR", Principal: "SYN-AGENT-GO",
		Action: "tools/call", Decision: "permit", PolicyID: "SYN-POL-MCP", Revision: 1,
		AtUnix: 1, Server: "SYN-MCP-INVENTORY", Tool: "inventory.query", Resource: "SYN-INV-TEST",
	}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"event_id", "tenant_id", "principal", "action", "decision", "policy_id", "policy_revision", "at_unix", "mcp_server", "tool", "target_resource"} {
		if _, ok := body[key]; !ok {
			t.Fatal(key)
		}
	}
}

func TestUpstreamClientUsesProject1AccessRequestBody(t *testing.T) {
	var seen upstream.AccessRequest
	var authz string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/access-requests" || r.Method != http.MethodPost {
			t.Fatalf("%s %s", r.Method, r.URL.Path)
		}
		authz = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&seen)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	err := upstream.New().PostAccessRequest(t.Context(), server.URL, "lab-exporter", upstream.AccessRequest{
		Resource: "SYN-MCP-ADMIN", Action: "maintenance.apply", Reason: "simulated",
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen.Resource != "SYN-MCP-ADMIN" || seen.Action != "maintenance.apply" || !strings.HasPrefix(authz, "Bearer ") {
		t.Fatalf("%+v %s", seen, authz)
	}
}

func TestOpenAPIListsRoutes(t *testing.T) {
	raw, err := os.ReadFile(filepath())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, route := range httpapi.Routes {
		if !strings.Contains(text, route.Path) {
			t.Fatal(route.Path)
		}
	}
}

func TestConfigLimits(t *testing.T) {
	limits, err := config.Load(root("configs/gateway.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if limits.GrantTTL.Seconds() != 300 || limits.DownstreamTTL.Seconds() != 60 {
		t.Fatal(limits)
	}
}

func filepath() string { return root("docs/api/openapi.yaml") }

func root(rel string) string {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(dir + "/go.mod"); err == nil {
			return dir + "/" + rel
		}
		next := dir[:strings.LastIndex(dir, string(os.PathSeparator))]
		if next == dir {
			return rel
		}
		dir = next
	}
}
