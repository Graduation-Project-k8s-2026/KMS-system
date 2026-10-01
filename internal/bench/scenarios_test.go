package bench_test

import (
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

func TestResolveOps(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"encrypt", []string{"encrypt"}},
		{"decrypt", []string{"decrypt"}},
		{"rewrap", []string{"rewrap"}},
		{"all", []string{"encrypt", "decrypt", "rewrap"}},
		{"", []string{"encrypt", "decrypt", "rewrap"}},
	}
	for _, tc := range cases {
		got, err := bench.ResolveOps(tc.in)
		if err != nil {
			t.Fatalf("ResolveOps(%q) failed: %v", tc.in, err)
		}
		if len(got) != len(tc.want) {
			t.Fatalf("ResolveOps(%q) = %v, want %v", tc.in, got, tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("ResolveOps(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}

	if _, err := bench.ResolveOps("bogus"); err == nil {
		t.Fatal("ResolveOps(\"bogus\") succeeded, want error")
	}
}

func baseConfig() bench.BenchConfig {
	return bench.BenchConfig{
		Ops:                 []string{"encrypt", "decrypt"},
		Count:               100,
		BaselineConcurrency: 1,
		ConcurrencyLevels:   []int{1, 10, 50},
		BaselinePayload:     1024,
		PayloadSizes:        []int{1024, 10240},
		Warmup:              5,
	}
}

// TestBuildRunConfigs_Basic는 basic 시나리오가 각 operation마다 정확히
// 하나씩(고정 payload/concurrency로) RunConfig를 만드는지 확인한다.
func TestBuildRunConfigs_Basic(t *testing.T) {
	runs, err := bench.BuildRunConfigs(bench.ScenarioBasic, baseConfig())
	if err != nil {
		t.Fatalf("BuildRunConfigs failed: %v", err)
	}
	if len(runs) != 2 { // 2 ops × 1 (고정 payload/concurrency)
		t.Fatalf("len(runs) = %d, want 2", len(runs))
	}
	for _, r := range runs {
		if r.Scenario != bench.ScenarioBasic {
			t.Errorf("Scenario = %q, want %q", r.Scenario, bench.ScenarioBasic)
		}
		if r.PayloadBytes != 1024 {
			t.Errorf("PayloadBytes = %d, want 1024 (baseline)", r.PayloadBytes)
		}
		if r.Concurrency != 1 {
			t.Errorf("Concurrency = %d, want 1 (baseline)", r.Concurrency)
		}
	}
}

// TestBuildRunConfigs_Payload는 payload 시나리오가 operation × payload
// 크기 집합의 곱집합을 만드는지, concurrency는 baseline으로 고정되는지
// 확인한다.
func TestBuildRunConfigs_Payload(t *testing.T) {
	runs, err := bench.BuildRunConfigs(bench.ScenarioPayload, baseConfig())
	if err != nil {
		t.Fatalf("BuildRunConfigs failed: %v", err)
	}
	if len(runs) != 4 { // 2 ops × 2 payload sizes
		t.Fatalf("len(runs) = %d, want 4", len(runs))
	}
	for _, r := range runs {
		if r.Scenario != bench.ScenarioPayload {
			t.Errorf("Scenario = %q, want %q", r.Scenario, bench.ScenarioPayload)
		}
		if r.Concurrency != 1 {
			t.Errorf("Concurrency = %d, want 1 (baseline)", r.Concurrency)
		}
	}
}

// TestBuildRunConfigs_Concurrency는 concurrency 시나리오가 operation ×
// 동시성 수준 집합의 곱집합을 만드는지, payload는 baseline으로 고정되는지
// 확인한다.
func TestBuildRunConfigs_Concurrency(t *testing.T) {
	runs, err := bench.BuildRunConfigs(bench.ScenarioConcurrency, baseConfig())
	if err != nil {
		t.Fatalf("BuildRunConfigs failed: %v", err)
	}
	if len(runs) != 6 { // 2 ops × 3 concurrency levels
		t.Fatalf("len(runs) = %d, want 6", len(runs))
	}
	for _, r := range runs {
		if r.Scenario != bench.ScenarioConcurrency {
			t.Errorf("Scenario = %q, want %q", r.Scenario, bench.ScenarioConcurrency)
		}
		if r.PayloadBytes != 1024 {
			t.Errorf("PayloadBytes = %d, want 1024 (baseline)", r.PayloadBytes)
		}
	}
}

// TestBuildRunConfigs_All은 all이 basic+payload+concurrency를 순서대로
// 이어붙이는지 확인한다.
func TestBuildRunConfigs_All(t *testing.T) {
	runs, err := bench.BuildRunConfigs(bench.ScenarioAll, baseConfig())
	if err != nil {
		t.Fatalf("BuildRunConfigs failed: %v", err)
	}
	want := 2 + 4 + 6 // basic + payload + concurrency
	if len(runs) != want {
		t.Fatalf("len(runs) = %d, want %d", len(runs), want)
	}
	if runs[0].Scenario != bench.ScenarioBasic {
		t.Errorf("runs[0].Scenario = %q, want basic (basic should come first)", runs[0].Scenario)
	}
	if runs[len(runs)-1].Scenario != bench.ScenarioConcurrency {
		t.Errorf("last run's Scenario = %q, want concurrency (concurrency should come last)", runs[len(runs)-1].Scenario)
	}
}

func TestBuildRunConfigs_UnknownScenario(t *testing.T) {
	if _, err := bench.BuildRunConfigs("bogus", baseConfig()); err == nil {
		t.Fatal("BuildRunConfigs(\"bogus\", ...) succeeded, want error")
	}
}

func TestValidateWarmupForOps(t *testing.T) {
	if err := bench.ValidateWarmupForOps([]string{"encrypt"}, 0); err != nil {
		t.Errorf("encrypt with warmup=0 should be fine, got: %v", err)
	}
	if err := bench.ValidateWarmupForOps([]string{"decrypt"}, 0); err == nil {
		t.Error("decrypt with warmup=0 should fail")
	}
	if err := bench.ValidateWarmupForOps([]string{"rewrap"}, 0); err == nil {
		t.Error("rewrap with warmup=0 should fail")
	}
	if err := bench.ValidateWarmupForOps([]string{"decrypt"}, 1); err != nil {
		t.Errorf("decrypt with warmup=1 should be fine, got: %v", err)
	}
	if err := bench.ValidateWarmupForOps([]string{"encrypt", "decrypt"}, 0); err == nil {
		t.Error("mixed ops containing decrypt with warmup=0 should fail")
	}
}
