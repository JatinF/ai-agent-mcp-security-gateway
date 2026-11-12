// Package analytics reports standing high-risk allows, denials, and tools under review.
package analytics

import (
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/model"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/registry"
)

func Findings(tools []model.Tool, permissions []model.Permission, events []model.AuditEvent, changes []registry.Change) []model.Finding {
	risk := map[string]model.Tool{}
	for _, tool := range tools {
		risk[tool.ServerID+"/"+tool.Name] = tool
	}
	var out []model.Finding
	for _, perm := range permissions {
		tool, ok := risk[perm.ServerID+"/"+perm.Tool]
		if ok && perm.Effect == "allow" && tool.Risk == "high" && !tool.Sensitive {
			out = append(out, model.Finding{
				Kind: "excessive_permission", Subject: perm.AgentID,
				Detail: perm.Tool + " is a standing high-risk allow",
			})
		}
	}
	denials := 0
	for _, event := range events {
		if event.Decision != "" && event.Decision != "permit" && event.Decision != "grant_permit" {
			denials++
		}
	}
	if denials > 0 {
		out = append(out, model.Finding{Kind: "denials", Subject: "gateway", Detail: itoa(denials)})
	}
	seen := map[string]bool{}
	for _, change := range changes {
		if seen[change.ToolID] {
			continue
		}
		seen[change.ToolID] = true
		out = append(out, model.Finding{
			Kind: "tool_changed", Subject: change.Name,
			Detail: change.Attribute + " " + change.Before + " -> " + change.After,
		})
	}
	for _, tool := range tools {
		if tool.ReviewStatus == "review_required" && !seen[tool.ID] {
			out = append(out, model.Finding{Kind: "tool_changed", Subject: tool.Name, Detail: "review_required"})
		}
	}
	return out
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
