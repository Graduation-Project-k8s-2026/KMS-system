package transit_test

import (
	"crypto/rsa"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	kmstransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

var extCfg = apitransit.ExternalConfig{SubjectNamespaces: []string{"kms-external"}, KeyNamespaces: []string{"kms-external"}, RPS: 1000, Burst: 1000, AuthFailMax: 100}

// extEnv: 외부 라우터. 요청자 신원은 실제 토큰 검증(authn)을 거친다 — 테스트 헤더 X-Test-NS를 받아 그 네임스페이스의
// ServiceAccount 토큰을 서명해 Authorization으로 바꿔 준다. verifier를 직접 넘기면(인증 실패 시험) 변환하지 않는다.
// (외부 라우터는 Verifier/Authorizer가 없으면 503으로 닫히므로 둘 다 필요하다.)
func extEnv(t *testing.T, authorizer *authz.Authorizer, cfg apitransit.ExternalConfig, verifier *authn.Verifier) (*httptest.Server, *keys.KeyManager, *audit.TransitLog, string) {
	t.Helper()
	b := barrier.NewBarrier(storage.NewMemoryStorage(), seal.NewDevSeal("p"))
	if err := b.Unseal(); err != nil {
		t.Fatal(err)
	}
	km := keys.NewKeyManager(b)
	dir := t.TempDir()
	alog, _ := audit.NewTransit(dir, 256, 20*time.Millisecond)
	var priv *rsa.PrivateKey
	autoSign := verifier == nil
	if autoSign {
		verifier, priv = newAuthTestVerifier(t)
	}
	router := apitransit.NewExternalRouter(apitransit.Deps{Barrier: b, Transit: kmstransit.NewTransitService(km), Authorizer: authorizer, Audit: alog, Verifier: verifier}, cfg)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ns := r.Header.Get("X-Test-NS"); ns != "" && autoSign && r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+signTestToken(t, priv, ns, "u"))
		}
		router.ServeHTTP(w, r)
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, km, alog, dir
}

func extPost(t *testing.T, srv *httptest.Server, path, ns string, hdr map[string]string) *http.Response {
	t.Helper()
	body := `{"plaintext":"AA=="}`
	if strings.Contains(path, "datakey") {
		body = `{}`
	}
	req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
	req.Header.Set("X-Test-NS", ns)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestExternal_OnlyFourRoutesAndHealthz(t *testing.T) {
	srv, km, _, _ := extEnv(t, newFakeAuthorizer(t, true), extCfg, nil)
	km.CreateKey("kms-external.k", 0)
	for _, op := range []string{"encrypt", "datakey"} {
		if r := extPost(t, srv, "/v1/"+op+"/kms-external.k", "kms-external", nil); r.StatusCode != 200 {
			t.Fatalf("%s = %d", op, r.StatusCode)
		}
	}
	if r, _ := http.Get(srv.URL + "/healthz"); r.StatusCode != 200 {
		t.Fatalf("healthz = %d", r.StatusCode)
	}
	for _, p := range []string{"/v1/sys/seal-profile", "/v1/sys/seal-status", "/v1/keys", "/v1/sys/init", "/metrics"} {
		resp := extPost(t, srv, p, "kms-external", nil)
		wantError(t, resp, 404, "not_found")
		r, _ := http.Get(srv.URL + p)
		if r.StatusCode != 404 {
			t.Fatalf("GET %s = %d, want 404", p, r.StatusCode)
		}
	}
	r, _ := http.Get(srv.URL + "/v1/encrypt/kms-external.k")
	if r.StatusCode != 405 {
		t.Fatalf("GET encrypt = %d", r.StatusCode)
	}
}

func TestExternal_SubjectAndKeyNamespaceGuards(t *testing.T) {
	srv, km, _, _ := extEnv(t, newFakeAuthorizer(t, true), extCfg, nil)
	for _, n := range []string{"kms-external.k", "team-a.k", "global"} {
		km.CreateKey(n, 0)
	}
	// 내부 SA(다른 ns)는 외부 키여도 403
	wantError(t, extPost(t, srv, "/v1/encrypt/kms-external.k", "kube-system", nil), 403, "forbidden")
	wantError(t, extPost(t, srv, "/v1/encrypt/kms-external.k", "team-a", nil), 403, "forbidden")
	// 외부 SA라도 외부 네임스페이스 키가 아니면 403 — 존재하는 키/없는 키/형식 오류 모두 같은 본문
	for _, k := range []string{"team-a.k", "global", "team-a.ghost", "kms-external.k.x", "ghost"} {
		resp := extPost(t, srv, "/v1/encrypt/"+k, "kms-external", nil)
		wantError(t, resp, 403, "forbidden")
	}
	// 정상
	if r := extPost(t, srv, "/v1/decrypt/kms-external.k", "kms-external", nil); r.StatusCode == 403 {
		t.Fatal("legit external subject/key was forbidden")
	}
}

func TestExternal_KeyGuardResponsesAreIdenticalForExistingAndMissing(t *testing.T) {
	srv, km, _, _ := extEnv(t, newFakeAuthorizer(t, true), extCfg, nil)
	km.CreateKey("team-a.real", 0)
	read := func(k string) string {
		resp := extPost(t, srv, "/v1/encrypt/"+k, "kms-external", nil)
		b, _ := io.ReadAll(resp.Body)
		return resp.Status + string(b)
	}
	if read("team-a.real") != read("team-a.ghost") {
		t.Fatal("responses distinguish existing from missing keys")
	}
}

func TestExternal_RateLimitByRemoteAddrIgnoresForwardedFor(t *testing.T) {
	cfg := extCfg
	cfg.RPS, cfg.Burst = 0.001, 2
	srv, km, _, _ := extEnv(t, newFakeAuthorizer(t, true), cfg, nil)
	km.CreateKey("kms-external.k", 0)
	before := testutil.ToFloat64(metrics.ExternalRejectedTotal.WithLabelValues("rate"))
	var codes []int
	for i := 0; i < 4; i++ { // 요청마다 다른 X-Forwarded-For를 보내도 한도는 연결 IP 기준
		resp := extPost(t, srv, "/v1/encrypt/kms-external.k", "kms-external", map[string]string{"X-Forwarded-For": "203.0.113." + string(rune('1'+i))})
		codes = append(codes, resp.StatusCode)
		if resp.StatusCode == 429 {
			if resp.Header.Get("Retry-After") == "" {
				t.Fatal("Retry-After missing")
			}
			wantError(t, resp, 429, "rate_limited")
		}
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 || codes[3] != 429 {
		t.Fatalf("codes = %v", codes)
	}
	if d := testutil.ToFloat64(metrics.ExternalRejectedTotal.WithLabelValues("rate")) - before; d != 2 {
		t.Fatalf("rate rejections metric delta = %v, want 2", d)
	}
}

func TestExternal_AuthFailuresBlockIP(t *testing.T) {
	verifier, _ := newAuthTestVerifier(t)
	cfg := extCfg
	cfg.AuthFailMax = 3
	srv, _, _, _ := extEnv(t, newFakeAuthorizer(t, true), cfg, verifier)
	before := testutil.ToFloat64(metrics.ExternalRejectedTotal.WithLabelValues("authfail"))
	var codes []int
	for i := 0; i < 6; i++ {
		resp := extPost(t, srv, "/v1/encrypt/kms-external.k", "", nil) // 토큰 없음 → 401
		codes = append(codes, resp.StatusCode)
	}
	// 401 ×4(한도 3 초과 시점에 차단) 이후 429
	if codes[0] != 401 || codes[3] != 401 || codes[4] != 429 || codes[5] != 429 {
		t.Fatalf("codes = %v", codes)
	}
	if d := testutil.ToFloat64(metrics.ExternalRejectedTotal.WithLabelValues("authfail")) - before; d != 2 {
		t.Fatalf("authfail rejections delta = %v", d)
	}
	// 차단 중에는 유효한 요청도 막힌다 (healthz 포함)
	if r, _ := http.Get(srv.URL + "/healthz"); r.StatusCode != 429 {
		t.Fatalf("healthz while blocked = %d", r.StatusCode)
	}
}

func TestExternal_AuditHasListenerAndClientIPNoSecrets(t *testing.T) {
	srv, km, alog, dir := extEnv(t, newFakeAuthorizer(t, true), extCfg, nil)
	km.CreateKey("kms-external.k", 0)
	extPost(t, srv, "/v1/encrypt/kms-external.k", "kms-external", map[string]string{"X-Forwarded-For": "198.51.100.7"}).Body.Close()
	extPost(t, srv, "/v1/encrypt/kms-external.k", "kube-system", nil).Body.Close() // 내부 SA의 외부 사용 시도도 기록
	alog.Close()
	evs, _ := audit.ReadTransitToday(dir)
	if len(evs) != 2 {
		t.Fatalf("events = %+v", evs)
	}
	for _, e := range evs {
		if e.Listener != "external" || e.ClientIP != "127.0.0.1" {
			t.Fatalf("event = %+v (X-Forwarded-For must not be used)", e)
		}
	}
	if evs[0].Status != 200 || evs[1].Status != 403 {
		t.Fatalf("statuses = %d %d", evs[0].Status, evs[1].Status)
	}
}

// §0 fail-closed: Verifier 또는 Authorizer가 없으면 외부 라우터는 모든 요청을 503으로 거부한다.
func TestExternal_NilVerifierOrAuthorizerRejectsEverythingWith503(t *testing.T) {
	b := barrier.NewBarrier(storage.NewMemoryStorage(), seal.NewDevSeal("p"))
	b.Unseal()
	km := keys.NewKeyManager(b)
	km.CreateKey("kms-external.k", 0)
	verifier, priv := newAuthTestVerifier(t)
	cases := map[string]apitransit.Deps{
		"authn off": {Barrier: b, Transit: kmstransit.NewTransitService(km), Authorizer: newFakeAuthorizer(t, true)},
		"authz off": {Barrier: b, Transit: kmstransit.NewTransitService(km), Verifier: verifier},
		"both off":  {Barrier: b, Transit: kmstransit.NewTransitService(km)},
	}
	for name, deps := range cases {
		srv := httptest.NewServer(apitransit.NewExternalRouter(deps, extCfg))
		for _, path := range []string{"/v1/encrypt/kms-external.k", "/v1/datakey/kms-external.k"} {
			req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(`{"plaintext":"AA=="}`))
			req.Header.Set("Authorization", "Bearer "+signTestToken(t, priv, "kms-external", "u")) // 유효한 토큰이어도
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			wantError(t, resp, 503, "unavailable")
		}
		r, _ := http.Get(srv.URL + "/healthz")
		if r.StatusCode != 503 {
			t.Fatalf("%s: healthz = %d, want 503", name, r.StatusCode)
		}
		srv.Close()
	}
}
