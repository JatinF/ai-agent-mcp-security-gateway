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
		"id":      "call-readonly",
		"method":  "tools/call",
		"params": map[string]any{
			"name": "inventory.query",
			"arguments": map[string]any{
				"resource": "SYN-INV-TEST",
				"agent":    "SYN-AGENT-LANGGRAPH",
			},
		},
		"note": "The LangGraph runtime was not started. This is the Go stand-in for that agent identity.",
	}
}
