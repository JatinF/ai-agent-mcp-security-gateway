package platform

import (
	"net/http"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/httpapi"
)

func newHTTP(lab *Lab) http.Handler {
	return httpapi.New(lab, lab.Telemetry.Handler())
}
