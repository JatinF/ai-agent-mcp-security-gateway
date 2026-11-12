package httpapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/gates"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/redact"
)

type Core interface {
	Authenticate(raw string) (model.Identity, error)
	Call(raw, serverID, tool, resource string) model.Result
	RequestAccess(caller model.Identity, agentID, serverID, tool, resource, reason string) (model.AccessRequest, error)
	Approve(caller model.Identity, requestID string) (model.Grant, error)
	RevokeGrant(caller model.Identity, requestID string) (model.Grant, error)
	RevokeAgent(caller model.Identity, agentID string) error
	UpdateTool(caller model.Identity, serverID, name, operation, risk, scope string) (model.Tool, error)
	AcceptReview(caller model.Identity, serverID, name string) (model.Tool, error)
	Events(caller model.Identity) ([]model.AuditEvent, error)
	Findings(caller model.Identity) ([]model.Finding, error)
	Gates(caller model.Identity) ([]gates.Gate, error)
}

type Route struct {
	Method string
	Path   string
}

var Routes = []Route{
	{"POST", "/v1/mcp/call"},
	{"POST", "/v1/access-requests"},
	{"POST", "/v1/access-requests/{id}/approve"},
	{"POST", "/v1/access-requests/{id}/revoke"},
	{"POST", "/v1/agents/{id}/revoke"},
	{"POST", "/v1/tools/{id}/review"},
	{"GET", "/v1/audit/events"},
	{"GET", "/v1/analytics/findings"},
	{"GET", "/v1/gates"},
}

func New(core Core, metrics http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"service": "gateway", "status": "ok"})
	})
	mux.Handle("GET /metrics", metrics)
	mux.HandleFunc("POST /v1/mcp/call", func(w http.ResponseWriter, r *http.Request) {
		raw, body, ok := bearer(w, r)
		if !ok {
			return
		}
		var input struct {
			ServerID string `json:"server_id"`
			Tool     string `json:"tool"`
			Resource string `json:"resource"`
		}
		if !decode(w, body, &input) {
			return
		}
		result := core.Call(raw, input.ServerID, input.Tool, input.Resource)
		if !result.Allow {
			writeErr(w, apperr.New(result.Reason, result.Reason, statusFor(result.Reason)))
			return
		}
		finish(w, result, nil)
	})
	mux.HandleFunc("POST /v1/access-requests", func(w http.ResponseWriter, r *http.Request) {
		caller, body, ok := admin(w, r, core)
		if !ok {
			return
		}
		var input struct {
			AgentID  string `json:"agent_id"`
			ServerID string `json:"server_id"`
			Tool     string `json:"tool"`
			Resource string `json:"resource"`
			Reason   string `json:"reason"`
		}
		if !decode(w, body, &input) {
			return
		}
		item, err := core.RequestAccess(caller, input.AgentID, input.ServerID, input.Tool, input.Resource, input.Reason)
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/access-requests/{id}/approve", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := admin(w, r, core)
		if !ok {
			return
		}
		item, err := core.Approve(caller, r.PathValue("id"))
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/access-requests/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := admin(w, r, core)
		if !ok {
			return
		}
		item, err := core.RevokeGrant(caller, r.PathValue("id"))
		finish(w, item, err)
	})
	mux.HandleFunc("POST /v1/agents/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := admin(w, r, core)
		if !ok {
			return
		}
		err := core.RevokeAgent(caller, r.PathValue("id"))
		finish(w, map[string]string{"status": "revoked"}, err)
	})
	mux.HandleFunc("POST /v1/tools/{id}/review", func(w http.ResponseWriter, r *http.Request) {
		caller, body, ok := admin(w, r, core)
		if !ok {
			return
		}
		var input struct {
			ServerID  string `json:"server_id"`
			Operation string `json:"operation"`
			Risk      string `json:"risk"`
			Scope     string `json:"resource_scope"`
			Accept    bool   `json:"accept"`
		}
		if !decode(w, body, &input) {
			return
		}
		if input.Accept {
			item, err := core.AcceptReview(caller, input.ServerID, r.PathValue("id"))
			finish(w, item, err)
			return
		}
		item, err := core.UpdateTool(caller, input.ServerID, r.PathValue("id"), input.Operation, input.Risk, input.Scope)
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/audit/events", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := admin(w, r, core)
		if !ok {
			return
		}
		item, err := core.Events(caller)
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/analytics/findings", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := admin(w, r, core)
		if !ok {
			return
		}
		item, err := core.Findings(caller)
		finish(w, item, err)
	})
	mux.HandleFunc("GET /v1/gates", func(w http.ResponseWriter, r *http.Request) {
		caller, _, ok := admin(w, r, core)
		if !ok {
			return
		}
		item, err := core.Gates(caller)
		finish(w, item, err)
	})
	return mux
}

func bearer(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	raw := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(raw) <= len(prefix) || raw[:len(prefix)] != prefix {
		writeErr(w, apperr.New("unauthenticated", "bearer token is required", http.StatusUnauthorized))
		return "", nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErr(w, apperr.New("policy_format", "request body is too large", http.StatusRequestEntityTooLarge))
		return "", nil, false
	}
	return raw[len(prefix):], body, true
}

func admin(w http.ResponseWriter, r *http.Request, core Core) (model.Identity, []byte, bool) {
	raw, body, ok := bearer(w, r)
	if !ok {
		return model.Identity{}, nil, false
	}
	caller, err := core.Authenticate(raw)
	if err != nil {
		writeErr(w, err)
		return model.Identity{}, nil, false
	}
	return caller, body, true
}

func decode(w http.ResponseWriter, body []byte, dest any) bool {
	if len(body) == 0 {
		return true
	}
	if err := json.Unmarshal(body, dest); err != nil {
		writeErr(w, apperr.New("policy_format", "request body is not valid JSON", http.StatusUnprocessableEntity))
		return false
	}
	return true
}

func finish(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, payload)
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	code := "error"
	message := "request failed"
	if item, ok := apperr.As(err); ok {
		if item.Status != 0 {
			status = item.Status
		}
		code = item.Code
		message = item.Message
	}
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": redact.Secret(message)}})
}

func statusFor(reason string) int {
	switch reason {
	case "token_expired", "token_invalid", "signature_invalid", "audience_mismatch", "unauthenticated":
		return http.StatusUnauthorized
	case "gateway_unavailable", "policy_unavailable", "registry_unavailable":
		return http.StatusServiceUnavailable
	case "policy_review_required":
		return http.StatusConflict
	default:
		return http.StatusForbidden
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
