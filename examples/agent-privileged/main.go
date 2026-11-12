package main

import (
	"encoding/json"
	"os"
)

func main() {
	_ = json.NewEncoder(os.Stdout).Encode(Request())
}

func Request() map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      "call-privileged",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "maintenance.apply",
			"arguments": map[string]any{
				"resource": "SYN-INV-TEST",
				"agent":    "SYN-AGENT-GO",
			},
		},
		"note": "Sensitive calls stay denied until a different person approves a five-minute grant.",
	}
}
