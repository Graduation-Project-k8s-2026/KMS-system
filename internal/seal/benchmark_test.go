package seal_test

import (
	"context"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
)

func TestRunBenchmark_ReturnsAllFourResults(t *testing.T) {
	results := seal.RunBenchmark(context.Background())
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}

	seen := make(map[string]bool, len(results))
	for _, r := range results {
		seen[r.Type] = true
		if r.InitMs < 0 {
			t.Errorf("%s: InitMs = %v, want >= 0", r.Type, r.InitMs)
		}
		if r.UnsealMs < 0 {
			t.Errorf("%s: UnsealMs = %v, want >= 0", r.Type, r.UnsealMs)
		}
	}

	for _, want := range []string{"dev", "shamir", "tpm", "k8s"} {
		if !seen[want] {
			t.Errorf("missing benchmark result for %q (results: %+v)", want, results)
		}
	}
}

// TestRunBenchmark_ShamirHumanCountMatchesThreshold는 shamir 결과의
// Profile.HumanCount가 RunBenchmark이 실제로 사용한 threshold와 일치하는지
// 확인한다. RunBenchmark은 threshold를 매개변수로 받지 않고 내부적으로
// 고정값(benchmark.go의 benchmarkShamirThreshold, 현재 3)을 쓰므로, 여기서도
// 같은 값을 기대값으로 둔다 — Profile()이 실제 ShamirSeal의 threshold
// 필드를 제대로 반영하는지 검증하는 회귀 테스트다.
func TestRunBenchmark_ShamirHumanCountMatchesThreshold(t *testing.T) {
	const wantThreshold = 3

	results := seal.RunBenchmark(context.Background())
	for _, r := range results {
		if r.Type != "shamir" {
			continue
		}
		if r.Error != "" {
			t.Fatalf("shamir benchmark failed unexpectedly: %s", r.Error)
		}
		if r.Profile.HumanCount != wantThreshold {
			t.Fatalf("shamir Profile.HumanCount = %d, want %d", r.Profile.HumanCount, wantThreshold)
		}
		return
	}
	t.Fatal("no shamir result found in RunBenchmark output")
}
