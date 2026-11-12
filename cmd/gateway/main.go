package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/platform"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/policy"
	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/service"
	"github.com/JatinF/ai-agent-mcp-security-gateway/policies"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 && args[0] == "health" {
		_ = json.NewEncoder(os.Stdout).Encode(service.Health("gateway"))
		return 0
	}
	if len(args) > 0 && args[0] == "check" {
		if err := policy.Validate(policies.AgentAccess, policies.ToolPermissions); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "valid"})
		return 0
	}
	if len(args) > 0 && (args[0] == "demo" || args[0] == "bench") {
		lab, err := platform.NewLab()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		if args[0] == "demo" {
			report, err := lab.Demo()
			if err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				return 1
			}
			_ = json.NewEncoder(os.Stdout).Encode(report)
			return 0
		}
		report, err := lab.Bench()
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return 0
	}
	fmt.Fprintln(os.Stderr, "gateway health on 127.0.0.1:8090. The multi-process stack was not started.")
	if err := http.ListenAndServe("127.0.0.1:8090", service.Mux("gateway")); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	return 0
}
