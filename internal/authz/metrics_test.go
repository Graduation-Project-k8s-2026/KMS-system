package authz_test

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// TestAuthorizer_RecordsCacheHitAndMiss는 첫 호출이 miss로, 그 뒤 같은
// 조합의 두 번째 호출이 hit으로 정확히 기록되는지 확인한다.
func TestAuthorizer_RecordsCacheHitAndMiss(t *testing.T) {
	reactor, _ := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{})

	missBefore := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("hit"))

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt") // miss (첫 호출)
	a.Allowed(context.Background(), testIdentity, "demo", "encrypt") // hit (캐싱됨)

	missAfter := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("miss"))
	hitAfter := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("hit"))

	if missAfter-missBefore != 1 {
		t.Fatalf("cache_requests_total{miss} delta = %v, want 1", missAfter-missBefore)
	}
	if hitAfter-hitBefore != 1 {
		t.Fatalf("cache_requests_total{hit} delta = %v, want 1", hitAfter-hitBefore)
	}
}

// TestAuthorizer_RecordsSARResultAndCacheEntries는 SAR 호출 결과가
// sar_requests_total{allowed}로 집계되고, 캐시 항목 수 게이지가 늘어나는지
// 확인한다.
func TestAuthorizer_RecordsSARResultAndCacheEntries(t *testing.T) {
	reactor, _ := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{})

	allowedBefore := testutil.ToFloat64(metrics.AuthzSARRequestsTotal.WithLabelValues("allowed"))

	a.Allowed(context.Background(), testIdentity, "another-demo-key", "decrypt")

	allowedAfter := testutil.ToFloat64(metrics.AuthzSARRequestsTotal.WithLabelValues("allowed"))
	if allowedAfter-allowedBefore != 1 {
		t.Fatalf("sar_requests_total{allowed} delta = %v, want 1", allowedAfter-allowedBefore)
	}

	if got := testutil.ToFloat64(metrics.AuthzCacheEntries); got < 1 {
		t.Fatalf("cache_entries = %v, want >= 1 after a successful SAR call", got)
	}
}
