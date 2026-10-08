package authz_test

import (
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
)

func TestResolveRateLimit_Zero_UsesDefaults(t *testing.T) {
	qps, burst, disabled := authz.ResolveRateLimit(0, 0)
	if disabled {
		t.Fatal("disabled = true, want false (0 means use defaults)")
	}
	if qps != authz.DefaultQPS {
		t.Errorf("qps = %v, want %v", qps, authz.DefaultQPS)
	}
	if burst != authz.DefaultBurst {
		t.Errorf("burst = %v, want %v", burst, authz.DefaultBurst)
	}
}

func TestResolveRateLimit_Positive_UsesGivenValues(t *testing.T) {
	qps, burst, disabled := authz.ResolveRateLimit(20, 40)
	if disabled {
		t.Fatal("disabled = true, want false")
	}
	if qps != 20 {
		t.Errorf("qps = %v, want 20", qps)
	}
	if burst != 40 {
		t.Errorf("burst = %v, want 40", burst)
	}
}

func TestResolveRateLimit_NegativeEither_Disables(t *testing.T) {
	cases := []struct {
		name  string
		qps   float32
		burst int
	}{
		{"negative qps, positive burst", -5, 10},
		{"positive qps, negative burst", 10, -5},
		{"both negative", -1, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, disabled := authz.ResolveRateLimit(tc.qps, tc.burst)
			if !disabled {
				t.Fatalf("ResolveRateLimit(%v, %v) disabled = false, want true", tc.qps, tc.burst)
			}
		})
	}
}

func TestResolveRateLimit_MixedZeroAndPositive(t *testing.T) {
	// QPS만 지정하고 Burst는 기본값을 쓰는 경우(흔한 조합)를 확인한다.
	qps, burst, disabled := authz.ResolveRateLimit(30, 0)
	if disabled {
		t.Fatal("disabled = true, want false")
	}
	if qps != 30 {
		t.Errorf("qps = %v, want 30", qps)
	}
	if burst != authz.DefaultBurst {
		t.Errorf("burst = %v, want default %v", burst, authz.DefaultBurst)
	}
}
