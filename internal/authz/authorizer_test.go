package authz_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

var testIdentity = authn.Identity{
	Namespace:      "team-a",
	ServiceAccount: "app",
	Subject:        "system:serviceaccount:team-a:app",
	Groups:         []string{"system:serviceaccounts", "system:serviceaccounts:team-a"},
}

// newCountingReactor는 매번 지정된 결과(allowed 또는 err)를 돌려주면서,
// 실제로 몇 번 불렸는지 세는 리액터를 만든다 — 캐시가 apiserver 호출을
// 줄여주는지 확인하는 데 쓴다.
func newCountingReactor(allowed bool, err error) (k8stesting.ReactionFunc, *atomic.Int32) {
	var calls atomic.Int32
	fn := func(action k8stesting.Action) (bool, runtime.Object, error) {
		calls.Add(1)
		if err != nil {
			return true, nil, err
		}
		create := action.(k8stesting.CreateAction)
		sar := create.GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		sar.Status = authorizationv1.SubjectAccessReviewStatus{Allowed: allowed}
		return true, sar, nil
	}
	return fn, &calls
}

func newFakeAuthorizer(t *testing.T, reactor k8stesting.ReactionFunc, cfg authz.Config) *authz.Authorizer {
	t.Helper()
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "subjectaccessreviews", reactor)
	return authz.NewAuthorizer(client.AuthorizationV1().SubjectAccessReviews(), cfg)
}

// TestAuthorizer_Allowed_PassesThrough은 apiserver가 허용을 응답하면
// Allowed가 true를 반환하는지 확인한다.
func TestAuthorizer_Allowed_PassesThrough(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{})

	if !a.Allowed(context.Background(), testIdentity, "demo", "encrypt") {
		t.Fatal("Allowed = false, want true")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("SAR calls = %d, want 1", got)
	}
}

// TestAuthorizer_Denied_ReturnsFalse는 apiserver가 거부를 응답하면 Allowed가
// false를 반환하는지 확인한다.
func TestAuthorizer_Denied_ReturnsFalse(t *testing.T) {
	reactor, _ := newCountingReactor(false, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{})

	if a.Allowed(context.Background(), testIdentity, "demo", "decrypt") {
		t.Fatal("Allowed = true, want false")
	}
}

// TestAuthorizer_Cache_AvoidsSecondAPICall은 같은 (주체, namespace, 키,
// verb) 조합을 두 번 물으면 apiserver 호출이 한 번만 일어나는지 확인한다.
func TestAuthorizer_Cache_AvoidsSecondAPICall(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{TTL: time.Minute})

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")

	if got := calls.Load(); got != 1 {
		t.Fatalf("SAR calls = %d, want 1 (second call should hit the cache)", got)
	}
}

// TestAuthorizer_Cache_TTLExpiry_Requeries는 TTL이 지나면 캐시가 만료돼
// 다시 apiserver를 부르는지 확인한다.
func TestAuthorizer_Cache_TTLExpiry_Requeries(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{TTL: 20 * time.Millisecond})

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	time.Sleep(40 * time.Millisecond)
	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")

	if got := calls.Load(); got != 2 {
		t.Fatalf("SAR calls = %d, want 2 (cache should have expired)", got)
	}
}

// TestAuthorizer_CacheIsolatedByKeyAndVerb는 캐시 키가 (주체, namespace,
// 키 이름, verb) 전부를 구분하는지 확인한다 — 한 키에 대한 encrypt 허용이
// 다른 키나 다른 verb에까지 잘못 적용되면 안 된다.
func TestAuthorizer_CacheIsolatedByKeyAndVerb(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{TTL: time.Minute})

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	a.Allowed(context.Background(), testIdentity, "demo", "decrypt")
	a.Allowed(context.Background(), testIdentity, "other-key", "encrypt")

	if got := calls.Load(); got != 3 {
		t.Fatalf("SAR calls = %d, want 3 (each key/verb combination should be queried separately)", got)
	}
}

// TestAuthorizer_APIServerError_FailClosed_ReturnsFalse는 apiserver 호출이
// 실패하고 fail-open이 꺼져 있으면(기본) 거부하는지 확인한다.
func TestAuthorizer_APIServerError_FailClosed_ReturnsFalse(t *testing.T) {
	reactor, _ := newCountingReactor(false, errors.New("apiserver unreachable"))
	a := newFakeAuthorizer(t, reactor, authz.Config{FailOpen: false})

	if a.Allowed(context.Background(), testIdentity, "demo", "encrypt") {
		t.Fatal("Allowed = true, want false (fail-closed on apiserver error)")
	}
}

// TestAuthorizer_APIServerError_FailOpen_ReturnsTrue는 fail-open이 켜져
// 있으면 apiserver 호출 실패 시 허용하는지 확인한다.
func TestAuthorizer_APIServerError_FailOpen_ReturnsTrue(t *testing.T) {
	reactor, _ := newCountingReactor(false, errors.New("apiserver unreachable"))
	a := newFakeAuthorizer(t, reactor, authz.Config{FailOpen: true})

	if !a.Allowed(context.Background(), testIdentity, "demo", "encrypt") {
		t.Fatal("Allowed = false, want true (fail-open on apiserver error)")
	}
}

// TestAuthorizer_NegativeTTL_DisablesCache_AlwaysQueriesAPIServer는 TTL이
// 음수면 캐시를 전혀 쓰지 않고 같은 (주체, 키, verb) 조합도 매번
// apiserver에 다시 묻는지 확인한다.
func TestAuthorizer_NegativeTTL_DisablesCache_AlwaysQueriesAPIServer(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{TTL: -1 * time.Second})

	for i := 0; i < 5; i++ {
		a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	}

	if got := calls.Load(); got != 5 {
		t.Fatalf("SAR calls = %d, want 5 (caching must be fully disabled for negative TTL)", got)
	}
}

// TestAuthorizer_ZeroTTL_UsesDefaultCaching는 TTL을 설정하지 않으면(0,
// 제로값) 기존 동작대로 기본 캐시(10초)가 그대로 적용돼 두 번째 호출이
// 캐시로 처리되는지 확인한다 — 이번 변경이 기본 동작을 깨지 않았는지
// 보는 하위호환성 테스트다.
func TestAuthorizer_ZeroTTL_UsesDefaultCaching(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{}) // TTL 제로값 = 0

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")

	if got := calls.Load(); got != 1 {
		t.Fatalf("SAR calls = %d, want 1 (TTL=0 should still default to caching enabled)", got)
	}
}

// TestAuthorizer_PositiveTTL_UsesThatValue는 TTL에 양수를 주면 그 값이
// 그대로 적용되는지 확인한다(짧은 TTL이 실제로 만료를 일으키는지로 간접
// 검증) — TestAuthorizer_Cache_TTLExpiry_Requeries와 같은 방식이지만, 이번
// 작업(음수/영 구분)이 양수 경로를 건드리지 않았음을 명시적으로 확인하는
// 회귀 테스트다.
func TestAuthorizer_PositiveTTL_UsesThatValue(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{TTL: 15 * time.Millisecond})

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	if got := calls.Load(); got != 1 {
		t.Fatalf("SAR calls = %d, want 1 (first call always misses)", got)
	}

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	if got := calls.Load(); got != 1 {
		t.Fatalf("SAR calls = %d, want 1 (second call within TTL should hit the cache)", got)
	}

	time.Sleep(30 * time.Millisecond)
	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	if got := calls.Load(); got != 2 {
		t.Fatalf("SAR calls = %d, want 2 (TTL should have expired by now)", got)
	}
}

// TestAuthorizer_NegativeTTL_MetricsStillRecorded는 캐시가 비활성화돼
// 있어도 kms_authz_cache_requests_total{result="miss"}는 계속 늘어나고
// (이것이 곧 "캐시가 꺼져 있다"는 신호다), kms_authz_cache_entries는
// 전혀 건드리지 않는지(값이 바뀌지 않는지) 확인한다. 다른 테스트들도
// 같은 프로세스에서 같은 전역 지표를 공유하므로 절대값이 아니라 델타로
// 비교한다.
func TestAuthorizer_NegativeTTL_MetricsStillRecorded(t *testing.T) {
	reactor, _ := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{TTL: -1 * time.Second})

	missBefore := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("miss"))
	hitBefore := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("hit"))
	entriesBefore := testutil.ToFloat64(metrics.AuthzCacheEntries)

	const calls = 3
	for i := 0; i < calls; i++ {
		a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	}

	missAfter := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("miss"))
	hitAfter := testutil.ToFloat64(metrics.AuthzCacheRequestsTotal.WithLabelValues("hit"))
	entriesAfter := testutil.ToFloat64(metrics.AuthzCacheEntries)

	if missAfter != missBefore+calls {
		t.Errorf("cache misses increased by %v, want %d (every request should count as a miss when the cache is disabled)", missAfter-missBefore, calls)
	}
	if hitAfter != hitBefore {
		t.Errorf("cache hits increased by %v, want 0 (a disabled cache can never hit)", hitAfter-hitBefore)
	}
	if entriesAfter != entriesBefore {
		t.Errorf("kms_authz_cache_entries changed from %v to %v, want unchanged (disabled cache must never be populated)", entriesBefore, entriesAfter)
	}
}

// TestAuthorizer_APIServerError_NotCached는 apiserver 에러로 인한 폴백
// 결정은 캐싱되지 않아, 다음 호출에서도 다시 apiserver를 부르는지 확인한다
// — 일시적 장애가 복구되면 곧바로 실제 판단으로 돌아가야 하기 때문이다.
func TestAuthorizer_APIServerError_NotCached(t *testing.T) {
	reactor, calls := newCountingReactor(false, errors.New("apiserver unreachable"))
	a := newFakeAuthorizer(t, reactor, authz.Config{FailOpen: true, TTL: time.Minute})

	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")
	a.Allowed(context.Background(), testIdentity, "demo", "encrypt")

	if got := calls.Load(); got != 2 {
		t.Fatalf("SAR calls = %d, want 2 (a failed call's fallback decision must not be cached)", got)
	}
}
