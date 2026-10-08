package authz_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
)

// TestMiddleware_Allowed_PassesThrough는 Authorizer가 허용하면 다음
// 핸들러로 통과하는지 확인한다.
func TestMiddleware_Allowed_PassesThrough(t *testing.T) {
	reactor, _ := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{})

	r := chi.NewRouter()
	r.With(withTestIdentity, authz.Middleware(a, "encrypt")).Post("/v1/encrypt/{name}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/v1/encrypt/demo", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestMiddleware_Denied_Returns403는 Authorizer가 거부하면 403을 반환하고
// 다음 핸들러가 호출되지 않는지 확인한다.
func TestMiddleware_Denied_Returns403(t *testing.T) {
	reactor, _ := newCountingReactor(false, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{})

	called := false
	r := chi.NewRouter()
	r.With(withTestIdentity, authz.Middleware(a, "encrypt")).Post("/v1/encrypt/{name}", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/v1/encrypt/demo", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if called {
		t.Fatal("inner handler was called despite denial")
	}
}

// TestMiddleware_NoIdentityInContext_Returns403은 (배선 실수로) 인증
// 미들웨어를 거치지 않아 컨텍스트에 신원이 없는 경우에도 안전하게
// 거부(403)하는지 확인한다.
func TestMiddleware_NoIdentityInContext_Returns403(t *testing.T) {
	reactor, calls := newCountingReactor(true, nil)
	a := newFakeAuthorizer(t, reactor, authz.Config{})

	r := chi.NewRouter()
	r.With(authz.Middleware(a, "encrypt")).Post("/v1/encrypt/{name}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/v1/encrypt/demo", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("SAR calls = %d, want 0 (should fail before ever calling apiserver)", got)
	}
}

// withTestIdentity는 authn.Middleware가 정상적으로 앞서 실행됐을 때와
// 같은 상태(컨텍스트에 신원이 실린 상태)를 흉내내는 테스트용 미들웨어다.
func withTestIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(authn.WithIdentity(r.Context(), testIdentity)))
	})
}
