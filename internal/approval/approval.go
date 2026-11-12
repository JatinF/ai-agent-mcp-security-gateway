// Package approval issues short-lived grants for sensitive tools.
// A requester cannot approve their own request.
package approval

import (
	"sync"
	"time"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/redact"
)

type Service struct {
	mu       sync.Mutex
	ttl      time.Duration
	requests map[string]model.AccessRequest
	grants   []model.Grant
	seq      int
}

func New(ttl time.Duration) *Service {
	return &Service{ttl: ttl, requests: map[string]model.AccessRequest{}}
}

func (s *Service) Request(tenant, requester, agent, server, tool, resource, reason string, now int64) (model.AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	item := model.AccessRequest{
		ID: "req-" + pad(s.seq), TenantID: tenant, RequesterID: requester, AgentID: agent,
		ResourceID: server + "/" + resource, Action: tool, State: "pending", Reason: redact.Secret(reason),
	}
	s.requests[item.ID] = item
	return item, nil
}

func (s *Service) Get(requestID string) (model.AccessRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.requests[requestID]
	if !ok {
		return model.AccessRequest{}, apperr.New("not_found", "access request was not found", 404)
	}
	return item, nil
}

func (s *Service) Approve(approver, requestID string, now int64) (model.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.requests[requestID]
	if !ok {
		return model.Grant{}, apperr.New("not_found", "access request was not found", 404)
	}
	if item.RequesterID == approver {
		return model.Grant{}, apperr.New("self_approval", "requester cannot approve their own request", 403)
	}
	if item.State != "pending" {
		return model.Grant{}, apperr.New("conflict", "request is not pending", 409)
	}
	item.State = "approved"
	s.requests[requestID] = item
	s.seq++
	grant := model.Grant{
		ID: "grn-" + pad(s.seq), TenantID: item.TenantID, RequestID: item.ID, SubjectID: item.AgentID,
		ResourceID: item.ResourceID, Action: item.Action, Scope: item.ResourceID,
		ExpiresAtUnix: now + int64(s.ttl/time.Second),
	}
	s.grants = append(s.grants, grant)
	return grant, nil
}

func (s *Service) Revoke(requestID string, now int64) (model.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.requests[requestID]
	if !ok {
		return model.Grant{}, apperr.New("not_found", "access request was not found", 404)
	}
	item.State = "revoked"
	s.requests[requestID] = item
	var found model.Grant
	for i := range s.grants {
		if s.grants[i].RequestID == requestID && s.grants[i].RevokedAtUnix == 0 {
			s.grants[i].RevokedAtUnix = now
			found = s.grants[i]
		}
	}
	return found, nil
}

// State reports the grant that applies to a sensitive call.
// A valid grant wins. Otherwise an expired grant wins over a revoked one.
func (s *Service) State(agent, server, tool, resource string, now int64) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := server + "/" + resource
	expired := false
	revoked := false
	for _, grant := range s.grants {
		if grant.SubjectID != agent || grant.Action != tool || grant.ResourceID != want {
			continue
		}
		if grant.RevokedAtUnix == 0 && now < grant.ExpiresAtUnix {
			return "valid"
		}
		if grant.RevokedAtUnix == 0 && now >= grant.ExpiresAtUnix {
			expired = true
			continue
		}
		revoked = true
	}
	if expired {
		return "expired"
	}
	if revoked {
		return "revoked"
	}
	return "none"
}

func (s *Service) Grants() []model.Grant {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]model.Grant(nil), s.grants...)
}

func pad(n int) string {
	text := itoa(n)
	for len(text) < 4 {
		text = "0" + text
	}
	return text
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
