// Package gates reports integrations that were not executed.
// A set variable becomes blocked. This process does not dial it.
package gates

type Gate struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type item struct {
	name string
	env  string
	idle string
	busy string
}

var catalog = []item{
	{"control-plane", "MCP_CONTROL_PLANE_URL", "MCP_CONTROL_PLANE_URL is unset. Project 1 was not contacted.", "MCP_CONTROL_PLANE_URL is set. This process does not connect."},
	{"oidc-provider", "MCP_OIDC_ISSUER", "MCP_OIDC_ISSUER is unset. No OIDC provider was contacted.", "MCP_OIDC_ISSUER is set. This process does not connect."},
	{"docker-local", "MCP_DOCKER", "Docker is not installed on this workstation. A local image build was not run.", "MCP_DOCKER is set. This process does not run Docker."},
	{"kubernetes", "MCP_KUBECONFIG", "kubectl is not installed. No manifest was applied.", "MCP_KUBECONFIG is set. This process does not use it."},
	{"otlp-collector", "MCP_OTLP_ENDPOINT", "MCP_OTLP_ENDPOINT is unset. No collector was contacted.", "MCP_OTLP_ENDPOINT is set. This process does not export spans."},
	{"customer-deployment", "MCP_CUSTOMER", "SYN-TENANT-CEDAR is synthetic. No customer deployment was made.", "MCP_CUSTOMER is set. This process does not deploy."},
}

func Evaluate(env map[string]string) []Gate {
	out := make([]Gate, 0, len(catalog))
	for _, item := range catalog {
		if env[item.env] == "" {
			out = append(out, Gate{Name: item.name, Status: "not-run", Reason: item.idle})
			continue
		}
		out = append(out, Gate{Name: item.name, Status: "blocked", Reason: item.busy})
	}
	return out
}
