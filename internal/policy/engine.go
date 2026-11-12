// Package policy evaluates the embedded Rego modules.
// OPA does not decide token expiry, audience, or grant lifetime.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/policies"
	"github.com/open-policy-agent/opa/v1/rego"
)

type Engine struct {
	mu       sync.Mutex
	agent    *rego.PreparedEvalQuery
	tool     *rego.PreparedEvalQuery
	revision uint64
	digest   string
	up       bool
	policyID string
}

func New(policyID string) (*Engine, error) {
	if err := Validate(policies.AgentAccess, policies.ToolPermissions); err != nil {
		return nil, err
	}
	agent, err := prepare("data.mcp.agent.allow", "agent-access.rego", policies.AgentAccess)
	if err != nil {
		return nil, err
	}
	tool, err := prepare("data.mcp.tool.allow", "tool-permissions.rego", policies.ToolPermissions)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(policies.AgentAccess + policies.ToolPermissions))
	return &Engine{
		agent: agent, tool: tool, revision: 1, digest: hex.EncodeToString(sum[:]),
		up: true, policyID: policyID,
	}, nil
}

func (e *Engine) SetAvailable(up bool) {
	e.mu.Lock()
	e.up = up
	e.mu.Unlock()
}

func (e *Engine) Available() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.up
}

func (e *Engine) Revision() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.revision
}

func (e *Engine) ID() string { return e.policyID }

func (e *Engine) Bump() uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.revision++
	return e.revision
}

func (e *Engine) Allow(input map[string]any) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.up {
		return false, apperr.New("policy_unavailable", "policy service is unavailable", 503)
	}
	agentAllow, err := decide(e.agent, input)
	if err != nil {
		return false, err
	}
	toolAllow, err := decide(e.tool, input)
	if err != nil {
		return false, err
	}
	return agentAllow && toolAllow, nil
}

func Validate(agentRego, toolRego string) error {
	if !strings.Contains(agentRego, "package mcp.agent") || !strings.Contains(toolRego, "package mcp.tool") {
		return apperr.New("policy_format", "policy package names are wrong", 422)
	}
	if strings.Contains(agentRego, "default allow := true") || strings.Contains(toolRego, "default allow := true") {
		return apperr.New("policy_format", "default allow must be false", 422)
	}
	agent, err := prepare("data.mcp.agent.allow", "agent-access.rego", agentRego)
	if err != nil {
		return apperr.New("policy_format", "agent policy did not compile", 422)
	}
	tool, err := prepare("data.mcp.tool.allow", "tool-permissions.rego", toolRego)
	if err != nil {
		return apperr.New("policy_format", "tool policy did not compile", 422)
	}
	agentAllow, err := decide(agent, map[string]any{})
	if err != nil {
		return apperr.New("policy_format", "agent policy did not evaluate", 422)
	}
	toolAllow, err := decide(tool, map[string]any{})
	if err != nil {
		return apperr.New("policy_format", "tool policy did not evaluate", 422)
	}
	if agentAllow || toolAllow {
		return apperr.New("policy_format", "empty input must be denied", 422)
	}
	return nil
}

func prepare(query, name, module string) (*rego.PreparedEvalQuery, error) {
	prepared, err := rego.New(rego.Query(query), rego.Module(name, module)).PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}
	return &prepared, nil
}

func decide(prepared *rego.PreparedEvalQuery, input map[string]any) (bool, error) {
	results, err := prepared.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return false, err
	}
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return false, nil
	}
	value, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		return false, apperr.New("policy_format", "allow decision was not a boolean", 422)
	}
	return value, nil
}
