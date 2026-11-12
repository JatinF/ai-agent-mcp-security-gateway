package platform

import (
	"runtime"
	"sort"
	"time"
)

type BenchReport struct {
	Go          string  `json:"go"`
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	CPUs        int     `json:"cpus"`
	Samples     int     `json:"samples"`
	P50Us       float64 `json:"p50_us"`
	P95Us       float64 `json:"p95_us"`
	MaxUs       float64 `json:"max_us"`
	Price       string  `json:"price"`
	Measurement string  `json:"measurement"`
}

func (l *Lab) Bench() (BenchReport, error) {
	report := BenchReport{
		Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH, CPUs: runtime.NumCPU(),
		Price:       "none",
		Measurement: "50 means of 20 in-process inventory.query permits. A single call on this Windows clock often reads 0 because it finishes inside one tick. Not a network of agents and not a pass gate.",
	}
	const batches = 50
	const perBatch = 20
	values := make([]time.Duration, batches)
	token := l.Token("go-inventory")
	for i := 0; i < batches; i++ {
		start := time.Now()
		for n := 0; n < perBatch; n++ {
			result := l.Call(token, ServerInventory, ToolQuery, ResourceInv)
			if !result.Allow {
				return report, errDenied(result.Reason)
			}
		}
		values[i] = time.Since(start) / perBatch
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	report.Samples = batches * perBatch
	report.P50Us = microseconds(values[index(len(values), 0.50)])
	report.P95Us = microseconds(values[index(len(values), 0.95)])
	report.MaxUs = microseconds(values[len(values)-1])
	return report, nil
}

func index(n int, p float64) int { return int(float64(n-1) * p) }

func microseconds(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1000
}

type denyError string

func (e denyError) Error() string { return string(e) }

func errDenied(reason string) error { return denyError(reason) }
