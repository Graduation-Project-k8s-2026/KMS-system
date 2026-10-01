package bench_test

import (
	"testing"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

// TestComputeLatencyStats_NearestRank는 1~100ms 100개 샘플에서 nearest-rank
// 백분위가 정확한지 확인한다. 정렬된 n개 샘플에서 p번째 백분위 인덱스는
// ceil(p/100*n)-1이므로, 1..100(ms) 데이터에서 p50=50ms, p90=90ms,
// p95=95ms, p99=99ms, max=100ms이어야 한다.
func TestComputeLatencyStats_NearestRank(t *testing.T) {
	samples := make([]time.Duration, 100)
	for i := 0; i < 100; i++ {
		samples[i] = time.Duration(i+1) * time.Millisecond
	}

	stats := bench.ComputeLatencyStats(samples)

	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"Min", stats.Min, 1 * time.Millisecond},
		{"Max", stats.Max, 100 * time.Millisecond},
		{"P50", stats.P50, 50 * time.Millisecond},
		{"P90", stats.P90, 90 * time.Millisecond},
		{"P95", stats.P95, 95 * time.Millisecond},
		{"P99", stats.P99, 99 * time.Millisecond},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	if stats.Count != 100 {
		t.Errorf("Count = %d, want 100", stats.Count)
	}

	wantMean := 50500 * time.Microsecond // (1+100)/2 = 50.5ms
	if stats.Mean != wantMean {
		t.Errorf("Mean = %v, want %v", stats.Mean, wantMean)
	}
}

// TestComputeLatencyStats_Unsorted는 입력 순서를 섞어도 결과가 같은지
// (내부적으로 정렬하는지) 확인한다.
func TestComputeLatencyStats_Unsorted(t *testing.T) {
	samples := []time.Duration{
		5 * time.Millisecond,
		1 * time.Millisecond,
		3 * time.Millisecond,
		2 * time.Millisecond,
		4 * time.Millisecond,
	}
	stats := bench.ComputeLatencyStats(samples)
	if stats.Min != 1*time.Millisecond {
		t.Errorf("Min = %v, want 1ms", stats.Min)
	}
	if stats.Max != 5*time.Millisecond {
		t.Errorf("Max = %v, want 5ms", stats.Max)
	}
}

// TestComputeLatencyStats_Empty는 샘플이 하나도 없을 때(모든 요청 실패)
// 전부 0인 결과를 반환하는지 확인한다 — Count==0으로 "유효 데이터 없음"을
// 판별할 수 있어야 한다.
func TestComputeLatencyStats_Empty(t *testing.T) {
	stats := bench.ComputeLatencyStats(nil)
	if stats.Count != 0 {
		t.Fatalf("Count = %d, want 0", stats.Count)
	}
	if stats.Max != 0 || stats.P99 != 0 {
		t.Fatalf("expected zero-value stats for empty input, got %+v", stats)
	}
}

// TestComputeLatencyStats_SingleSample은 샘플이 1개뿐이면 모든 백분위가
// 그 값과 같은지 확인한다.
func TestComputeLatencyStats_SingleSample(t *testing.T) {
	stats := bench.ComputeLatencyStats([]time.Duration{7 * time.Millisecond})
	if stats.Count != 1 {
		t.Fatalf("Count = %d, want 1", stats.Count)
	}
	for name, got := range map[string]time.Duration{
		"Min": stats.Min, "Max": stats.Max, "Mean": stats.Mean,
		"P50": stats.P50, "P90": stats.P90, "P95": stats.P95, "P99": stats.P99,
	} {
		if got != 7*time.Millisecond {
			t.Errorf("%s = %v, want 7ms", name, got)
		}
	}
}

// TestOpsPerSec는 처리량 계산이 올바른지, wall이 0 이하이면 0을 반환하는지
// 확인한다.
func TestOpsPerSec(t *testing.T) {
	if got := bench.OpsPerSec(1000, 2*time.Second); got != 500 {
		t.Errorf("OpsPerSec(1000, 2s) = %v, want 500", got)
	}
	if got := bench.OpsPerSec(100, 0); got != 0 {
		t.Errorf("OpsPerSec(100, 0) = %v, want 0", got)
	}
	if got := bench.OpsPerSec(100, -1*time.Second); got != 0 {
		t.Errorf("OpsPerSec(100, -1s) = %v, want 0", got)
	}
}
