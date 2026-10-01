package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"text/tabwriter"
	"time"
)

// Environment는 측정이 이뤄진 실행 환경을 기록한다 — 다른 환경에서 측정한
// 결과와 비교할 때 조건이 같았는지 확인하기 위함이다.
type Environment struct {
	GoVersion  string `json:"go_version"`
	GOMAXPROCS int    `json:"gomaxprocs"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
}

// CollectEnvironment는 현재 프로세스의 실행 환경 정보를 모은다.
func CollectEnvironment() Environment {
	return Environment{
		GoVersion:  runtime.Version(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
	}
}

// LatencyReport는 LatencyStats를 JSON 출력용으로 초 단위 float64로 바꾼
// 것이다.
type LatencyReport struct {
	MinSeconds  float64 `json:"min_seconds"`
	MeanSeconds float64 `json:"mean_seconds"`
	P50Seconds  float64 `json:"p50_seconds"`
	P90Seconds  float64 `json:"p90_seconds"`
	P95Seconds  float64 `json:"p95_seconds"`
	P99Seconds  float64 `json:"p99_seconds"`
	MaxSeconds  float64 `json:"max_seconds"`
}

func newLatencyReport(s LatencyStats) LatencyReport {
	return LatencyReport{
		MinSeconds:  s.Min.Seconds(),
		MeanSeconds: s.Mean.Seconds(),
		P50Seconds:  s.P50.Seconds(),
		P90Seconds:  s.P90.Seconds(),
		P95Seconds:  s.P95.Seconds(),
		P99Seconds:  s.P99.Seconds(),
		MaxSeconds:  s.Max.Seconds(),
	}
}

// RunReport는 측정 한 번(한 RunConfig)의 결과를 JSON/표로 내보내기 위한
// 형태다.
type RunReport struct {
	Scenario        string        `json:"scenario"`
	Operation       string        `json:"operation"`
	PayloadBytes    int           `json:"payload_bytes"`
	Concurrency     int           `json:"concurrency"`
	Count           int           `json:"count,omitempty"`
	DurationSeconds float64       `json:"duration_requested_seconds,omitempty"`
	Warmup          int           `json:"warmup"`
	Keepalive       bool          `json:"keepalive"`
	StartedAt       time.Time     `json:"started_at"`
	EndedAt         time.Time     `json:"ended_at"`
	WallTimeSeconds float64       `json:"wall_time_seconds"`
	OpsPerSec       float64       `json:"ops_per_sec"`
	SuccessCount    int           `json:"success_count"`
	ErrorCount      int           `json:"error_count"`
	Latency         LatencyReport `json:"latency"`
	Errors          []string      `json:"errors,omitempty"`
}

// NewRunReport는 Execute의 원시 결과(RunResult)를 보고용 형태로 집계한다.
func NewRunReport(r RunResult) RunReport {
	wall := r.EndedAt.Sub(r.StartedAt)
	stats := ComputeLatencyStats(r.Samples)
	return RunReport{
		Scenario:        r.Config.Scenario,
		Operation:       r.Config.Operation,
		PayloadBytes:    r.Config.PayloadBytes,
		Concurrency:     r.Config.Concurrency,
		Count:           r.Config.Count,
		DurationSeconds: r.Config.Duration.Seconds(),
		Warmup:          r.Config.Warmup,
		Keepalive:       r.Config.Keepalive,
		StartedAt:       r.StartedAt,
		EndedAt:         r.EndedAt,
		WallTimeSeconds: wall.Seconds(),
		OpsPerSec:       OpsPerSec(r.SuccessCount, wall),
		SuccessCount:    r.SuccessCount,
		ErrorCount:      r.ErrorCount,
		Latency:         newLatencyReport(stats),
		Errors:          r.ErrorSamples,
	}
}

// Report는 한 번의 bench 실행 전체(여러 RunReport + 조건 라벨 + 환경 정보)를
// 담는 최상위 출력 구조다.
type Report struct {
	Label       string      `json:"label,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
	Addr        string      `json:"addr"`
	Key         string      `json:"key"`
	Environment Environment `json:"environment"`
	Runs        []RunReport `json:"runs"`
}

// WriteJSON은 report를 들여쓰기된 JSON으로 w에 쓴다.
func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteTable은 report.Runs를 사람이 읽기 쉬운 정렬된 표로 w에 쓴다.
func WriteTable(w io.Writer, report Report) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if report.Label != "" {
		fmt.Fprintf(tw, "label: %s\n", report.Label)
	}
	fmt.Fprintf(tw, "addr: %s  key: %s\n\n", report.Addr, report.Key)
	fmt.Fprintln(tw, "OPERATION\tPAYLOAD\tCONC\tOPS/SEC\tP50\tP90\tP95\tP99\tMAX\tERRORS")
	for _, r := range report.Runs {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%.1f\t%s\t%s\t%s\t%s\t%s\t%d\n",
			r.Operation,
			FormatSize(r.PayloadBytes),
			r.Concurrency,
			r.OpsPerSec,
			formatMillis(r.Latency.P50Seconds),
			formatMillis(r.Latency.P90Seconds),
			formatMillis(r.Latency.P95Seconds),
			formatMillis(r.Latency.P99Seconds),
			formatMillis(r.Latency.MaxSeconds),
			r.ErrorCount,
		)
	}
	return tw.Flush()
}

func formatMillis(seconds float64) string {
	return fmt.Sprintf("%.2fms", seconds*1000)
}
