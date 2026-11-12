package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/service"
)

func main() {
	os.Exit(service.Run("audit-collector", "127.0.0.1:8093", os.Args[1:], check))
}

func check([]string) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"fields": []string{"principal", "mcp_server", "tool", "target_resource", "policy_revision", "decision"},
		"note":   "Audit rows are written by the in-process gateway. Project 1 was not contacted.",
	})
}
