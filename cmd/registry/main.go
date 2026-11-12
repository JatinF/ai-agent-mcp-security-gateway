package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/service"
)

func main() { os.Exit(service.Run("registry", "127.0.0.1:8091", os.Args[1:], check)) }

func check([]string) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"agents":  []string{"SYN-AGENT-LANGGRAPH", "SYN-AGENT-GO", "SYN-AGENT-TESTAUTO"},
		"servers": []string{"SYN-MCP-INVENTORY", "SYN-MCP-ADMIN"},
		"note":    "Registry records are served by the gateway lab. This process did not open a network listener for MCP servers.",
	})
}
