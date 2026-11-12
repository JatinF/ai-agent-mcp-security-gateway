// Package registry stores agents, MCP servers, tools, and permissions.
// It does not dial server endpoints.
package registry

import (
	"sort"
	"sync"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/apperr"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
)

type Change struct {
	ToolID    string
	Name      string
	Before    string
	After     string
	Attribute string
}

type Store struct {
	mu          sync.Mutex
	agents      map[string]model.Agent
	servers     map[string]model.Server
	tools       map[string]model.Tool
	permissions []model.Permission
	changes     []Change
	nextPerm    int
	available   bool
}

func New() *Store {
	return &Store{
		agents: map[string]model.Agent{}, servers: map[string]model.Server{},
		tools: map[string]model.Tool{}, available: true,
	}
}

func (s *Store) SetAvailable(up bool) {
	s.mu.Lock()
	s.available = up
	s.mu.Unlock()
}

func (s *Store) Available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.available
}

func (s *Store) PutAgent(agent model.Agent) error {
	if agent.ID == "" || agent.TenantID == "" || agent.Status == "" {
		return apperr.New("policy_format", "agent identity is incomplete", 422)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[agent.ID] = agent
	return nil
}

func (s *Store) PutServer(server model.Server) error {
	if server.ID == "" || server.Audience == "" {
		return apperr.New("policy_format", "MCP server is incomplete", 422)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.servers[server.ID] = server
	return nil
}

func (s *Store) PutTool(tool model.Tool) error {
	if tool.Name == "" || tool.ServerID == "" || tool.ReviewStatus == "" {
		return apperr.New("policy_format", "tool is incomplete", 422)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[toolKey(tool.ServerID, tool.Name)] = tool
	return nil
}

func (s *Store) Allow(agentID, serverID, tool string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.permissions {
		if item.AgentID == agentID && item.ServerID == serverID && item.Tool == tool {
			return nil
		}
	}
	s.nextPerm++
	s.permissions = append(s.permissions, model.Permission{
		ID: "perm-" + pad(s.nextPerm), AgentID: agentID, ServerID: serverID, Tool: tool, Effect: "allow",
	})
	return nil
}

func (s *Store) Agent(id string) (model.Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.agents[id]
	if !ok {
		return model.Agent{}, apperr.New("unknown_agent", "agent is not registered", 404)
	}
	return item, nil
}

func (s *Store) SetStatus(id, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.agents[id]
	if !ok {
		return apperr.New("unknown_agent", "agent is not registered", 404)
	}
	item.Status = status
	s.agents[id] = item
	return nil
}

func (s *Store) Server(id string) (model.Server, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.servers[id]
	if !ok {
		return model.Server{}, apperr.New("unknown_server", "MCP server is not registered", 404)
	}
	return item, nil
}

func (s *Store) Tool(serverID, name string) (model.Tool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.tools[toolKey(serverID, name)]
	if !ok {
		return model.Tool{}, apperr.New("unknown_tool", "tool is not on this MCP server", 404)
	}
	return item, nil
}

func (s *Store) Permission(agentID, serverID, tool string) (model.Permission, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.permissions {
		if item.AgentID == agentID && item.ServerID == serverID && item.Tool == tool && item.Effect == "allow" {
			return item, true
		}
	}
	return model.Permission{}, false
}

// UpdateCapability records a tool change and holds the tool for policy review.
// The previous allow does not survive the change.
func (s *Store) UpdateCapability(serverID, name, operation, risk, scope string) (model.Tool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := toolKey(serverID, name)
	item, ok := s.tools[key]
	if !ok {
		return model.Tool{}, apperr.New("unknown_tool", "tool is not on this MCP server", 404)
	}
	changed := false
	if operation != "" && operation != item.Operation {
		s.changes = append(s.changes, Change{ToolID: item.ID, Name: item.Name, Before: item.Operation, After: operation, Attribute: "operation"})
		item.Operation = operation
		changed = true
	}
	if risk != "" && risk != item.Risk {
		s.changes = append(s.changes, Change{ToolID: item.ID, Name: item.Name, Before: item.Risk, After: risk, Attribute: "risk"})
		item.Risk = risk
		changed = true
	}
	if scope != "" && scope != item.ResourceScope {
		s.changes = append(s.changes, Change{ToolID: item.ID, Name: item.Name, Before: item.ResourceScope, After: scope, Attribute: "resource_scope"})
		item.ResourceScope = scope
		changed = true
	}
	if changed {
		item.ReviewStatus = "review_required"
		s.tools[key] = item
	}
	return item, nil
}

func (s *Store) AcceptReview(serverID, name string) (model.Tool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := toolKey(serverID, name)
	item, ok := s.tools[key]
	if !ok {
		return model.Tool{}, apperr.New("unknown_tool", "tool is not on this MCP server", 404)
	}
	item.ReviewStatus = "approved"
	s.tools[key] = item
	return item, nil
}

func (s *Store) Agents() []model.Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Agent, 0, len(s.agents))
	for _, item := range s.agents {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) Servers() []model.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Server, 0, len(s.servers))
	for _, item := range s.servers {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Store) Tools() []model.Tool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]model.Tool, 0, len(s.tools))
	for _, item := range s.tools {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ServerID == out[j].ServerID {
			return out[i].Name < out[j].Name
		}
		return out[i].ServerID < out[j].ServerID
	})
	return out
}

func (s *Store) Permissions() []model.Permission {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]model.Permission(nil), s.permissions...)
	return out
}

func (s *Store) Changes() []Change {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Change(nil), s.changes...)
}

func toolKey(serverID, name string) string { return serverID + "\x00" + name }

func pad(n int) string {
	if n < 10 {
		return "000" + itoa(n)
	}
	if n < 100 {
		return "00" + itoa(n)
	}
	return itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
