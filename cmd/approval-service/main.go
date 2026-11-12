package main

import (
	"encoding/json"
	"os"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/config"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/service"
)

func main() {
	os.Exit(service.Run("approval-service", "127.0.0.1:8092", os.Args[1:], check))
}

func check([]string) error {
	limits, err := config.Load("configs/gateway.yaml")
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"grant_ttl_seconds": int(limits.GrantTTL.Seconds()),
		"note":              "Approval runs inside the gateway lab. This process did not issue a grant.",
	})
}
