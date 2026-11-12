// Package mockmcp is an in-process MCP tool server.
// It accepts only a gateway-minted credential for its own audience.
package mockmcp

import (
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/auth"
)

type Server struct {
	id              string
	tokens          *auth.Issuer
	tools           map[string]string
	Calls           int
	LastCredential  string
	RejectedInbound int
}

func New(id string, tokens *auth.Issuer, tools map[string]string) *Server {
	copied := map[string]string{}
	for name, outcome := range tools {
		copied[name] = outcome
	}
	return &Server{id: id, tokens: tokens, tools: copied}
}

func (s *Server) ID() string { return s.id }

// Call refuses the caller's original token. The credential must be delegated and audience-bound.
func (s *Server) Call(credential, tool, resource string) (string, error) {
	claims, err := s.tokens.Parse(credential)
	if err != nil {
		return "", err
	}
	s.LastCredential = credential
	if !claims.Delegated {
		s.RejectedInbound++
		return "", apperr.New("inbound_token_rejected", "downstream server rejected a non-delegated token", 403)
	}
	if claims.Audience != auth.Audience(s.id) {
		return "", apperr.New("audience_mismatch", "credential audience is not this MCP server", 403)
	}
	if claims.Tool != "" && claims.Tool != tool {
		return "", apperr.New("denied", "credential is bound to a different tool", 403)
	}
	outcome, ok := s.tools[tool]
	if !ok {
		return "", apperr.New("unknown_tool", "tool is not exposed by this server", 404)
	}
	s.Calls++
	if resource == "" {
		return outcome, nil
	}
	return outcome, nil
}
