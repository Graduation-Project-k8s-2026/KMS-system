package authn_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
)

func newTestMiddlewareServer(t *testing.T, v *authn.Verifier) (*httptest.Server, *authn.Identity) {
	t.Helper()

	var captured authn.Identity
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := authn.IdentityFromContext(r.Context()); ok {
			captured = id
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(authn.Middleware(v)(inner))
	t.Cleanup(srv.Close)
	return srv, &captured
}

// TestMiddleware_MissingAuthorizationHeader_Returns401는 Authorization
// 헤더가 없으면 401로 거부되고, 응답 본문에 상세 사유가 노출되지 않는지
// 확인한다.
func TestMiddleware_MissingAuthorizationHeader_Returns401(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})
	srv, _ := newTestMiddlewareServer(t, v)

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestMiddleware_MalformedAuthorizationHeader_Returns401는 "Bearer " 접두사가
// 없는 헤더도 401로 거부되는지 확인한다.
func TestMiddleware_MalformedAuthorizationHeader_Returns401(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})
	srv, _ := newTestMiddlewareServer(t, v)

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestMiddleware_InvalidToken_Returns401는 형식은 맞지만 검증에 실패하는
// 토큰(다른 키로 서명)도 401로 거부되는지 확인한다.
func TestMiddleware_InvalidToken_Returns401(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})
	srv, _ := newTestMiddlewareServer(t, v)

	token := signRSA(t, keys.otherRSAKey, legacyClaims{Subject: "system:serviceaccount:default:mysa"})

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestMiddleware_ValidToken_PassesThroughAndSetsIdentity는 유효한 토큰이면
// 다음 핸들러로 통과시키고, 그 핸들러가 컨텍스트에서 신원을 꺼낼 수 있는지
// 확인한다.
func TestMiddleware_ValidToken_PassesThroughAndSetsIdentity(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})
	srv, captured := newTestMiddlewareServer(t, v)

	token := signRSA(t, keys.rsaKey, legacyClaims{
		Subject:              "system:serviceaccount:default:mysa",
		LegacyNamespace:      "default",
		LegacyServiceAccount: "mysa",
	})

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if captured.Namespace != "default" || captured.ServiceAccount != "mysa" {
		t.Fatalf("captured identity = %+v, want namespace=default serviceaccount=mysa", *captured)
	}
}

// TestIdentityContext_RoundTrip은 WithIdentity/IdentityFromContext가 값을
// 정확히 왕복시키고, 아무 것도 실려있지 않은 컨텍스트에서는 ok=false를
// 반환하는지 확인한다.
func TestIdentityContext_RoundTrip(t *testing.T) {
	base := context.Background()
	if _, ok := authn.IdentityFromContext(base); ok {
		t.Fatal("IdentityFromContext(base) ok = true, want false")
	}

	want := authn.Identity{
		Namespace:      "ns",
		ServiceAccount: "sa",
		Subject:        "system:serviceaccount:ns:sa",
		Groups:         []string{"system:serviceaccounts", "system:serviceaccounts:ns"},
	}
	ctx := authn.WithIdentity(base, want)

	got, ok := authn.IdentityFromContext(ctx)
	if !ok {
		t.Fatal("IdentityFromContext(ctx) ok = false, want true")
	}
	if got.Namespace != want.Namespace || got.ServiceAccount != want.ServiceAccount || got.Subject != want.Subject {
		t.Fatalf("got = %+v, want %+v", got, want)
	}
	if len(got.Groups) != len(want.Groups) {
		t.Fatalf("got.Groups = %v, want %v", got.Groups, want.Groups)
	}
	for i := range want.Groups {
		if got.Groups[i] != want.Groups[i] {
			t.Fatalf("got.Groups = %v, want %v", got.Groups, want.Groups)
		}
	}
}
