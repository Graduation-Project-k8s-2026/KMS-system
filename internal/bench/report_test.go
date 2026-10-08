package bench_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

func sampleReport() bench.Report {
	started := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	result := bench.RunResult{
		Config: bench.RunConfig{
			Scenario: "basic", Operation: "encrypt",
			PayloadBytes: 1024, Concurrency: 1, Count: 2, Warmup: 1, Keepalive: true,
		},
		StartedAt:    started,
		EndedAt:      started.Add(2 * time.Millisecond),
		Samples:      []time.Duration{1 * time.Millisecond, 1 * time.Millisecond},
		SuccessCount: 2,
		ErrorCount:   0,
	}
	return bench.Report{
		Label:       "test-label",
		Timestamp:   started,
		Addr:        "http://localhost:8200",
		Key:         "demo",
		Environment: bench.CollectEnvironment(),
		Runs:        []bench.RunReport{bench.NewRunReport(result)},
	}
}

// TestWriteJSON_Schema는 JSON 출력이 기대하는 필드를 전부 담고 있는지
// (측정 시각, 조건 라벨, 대상 주소/키, 시나리오별 파라미터, 결과 지표,
// 환경 정보) 확인한다.
func TestWriteJSON_Schema(t *testing.T) {
	var buf bytes.Buffer
	if err := bench.WriteJSON(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	for _, field := range []string{"label", "timestamp", "addr", "key", "environment", "runs"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("top-level field %q missing from JSON output", field)
		}
	}

	env, ok := decoded["environment"].(map[string]any)
	if !ok {
		t.Fatal("environment is not an object")
	}
	for _, field := range []string{"go_version", "gomaxprocs", "os", "arch"} {
		if _, ok := env[field]; !ok {
			t.Errorf("environment.%s missing", field)
		}
	}

	runs, ok := decoded["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want a one-element array", decoded["runs"])
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("runs[0] is not an object")
	}
	for _, field := range []string{
		"scenario", "operation", "payload_bytes", "concurrency", "count",
		"warmup", "keepalive", "started_at", "ended_at", "wall_time_seconds",
		"ops_per_sec", "success_count", "error_count", "latency",
	} {
		if _, ok := run[field]; !ok {
			t.Errorf("runs[0].%s missing", field)
		}
	}

	latency, ok := run["latency"].(map[string]any)
	if !ok {
		t.Fatal("runs[0].latency is not an object")
	}
	for _, field := range []string{"min_seconds", "mean_seconds", "p50_seconds", "p90_seconds", "p95_seconds", "p99_seconds", "max_seconds"} {
		if _, ok := latency[field]; !ok {
			t.Errorf("runs[0].latency.%s missing", field)
		}
	}
}

func TestWriteJSON_RoundTripsIntoReportStruct(t *testing.T) {
	var buf bytes.Buffer
	want := sampleReport()
	if err := bench.WriteJSON(&buf, want); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var got bench.Report
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("Unmarshal into bench.Report failed: %v", err)
	}
	if got.Label != want.Label || got.Addr != want.Addr || got.Key != want.Key {
		t.Errorf("got = %+v, want = %+v", got, want)
	}
	if len(got.Runs) != 1 || got.Runs[0].OpsPerSec != want.Runs[0].OpsPerSec {
		t.Errorf("Runs mismatch: got %+v, want %+v", got.Runs, want.Runs)
	}
}

func TestWriteTable_ContainsExpectedColumns(t *testing.T) {
	var buf bytes.Buffer
	if err := bench.WriteTable(&buf, sampleReport()); err != nil {
		t.Fatalf("WriteTable failed: %v", err)
	}
	out := buf.String()

	for _, want := range []string{
		"OPERATION", "PAYLOAD", "CONC", "OPS/SEC", "P50", "P90", "P95", "P99", "MAX", "ERRORS",
		"encrypt", "1KB", "test-label", "demo",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}
