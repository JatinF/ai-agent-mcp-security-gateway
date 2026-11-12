// Package upstream speaks the Project 1 access-request JSON.
// The lab does not call this client. Project 1 has no audit-ingest route and no token-introspection route.
package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
)

type AccessRequest struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
}

type Client struct {
	HTTP *http.Client
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 2 * time.Second}}
}

// PostAccessRequest sends the Project 1 body. The caller must pass a base URL that this test controls.
// A live Project 1 process is not a default target.
func (c *Client) PostAccessRequest(ctx context.Context, baseURL, bearer string, body AccessRequest) error {
	if strings.TrimSpace(baseURL) == "" {
		return apperr.New("not_run", "control plane URL is unset", 503)
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/access-requests", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return apperr.New("upstream_rejected", "control plane did not accept the access request", response.StatusCode)
	}
	return nil
}
