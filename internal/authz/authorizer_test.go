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

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
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
