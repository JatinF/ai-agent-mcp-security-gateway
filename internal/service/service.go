package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/JatinF/ai-agent-mcp-security-gateway/internal/telemetry"
)

func Health(name string) map[string]string {
	return map[string]string{"service": name, "status": "ok"}
}

func Mux(name string) http.Handler {
	hub := telemetry.New(name)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Health(name))
	})
	mux.Handle("GET /metrics", hub.Handler())
	return mux
}

func Run(name, addr string, args []string, check func([]string) error) int {
	if len(args) > 0 && args[0] == "health" {
		_ = json.NewEncoder(os.Stdout).Encode(Health(name))
		return 0
	}
	if len(args) > 0 && args[0] == "check" {
		if check == nil {
			fmt.Fprintf(os.Stderr, "%s has no local check. The multi-process stack was not started.\n", name)
			return 1
		}
		if err := check(args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 1
		}
		return 0
	}
	fmt.Fprintf(os.Stderr, "%s health on %s. The multi-process stack was not started.\n", name, addr)
	if err := http.ListenAndServe(addr, Mux(name)); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	return 0
}
