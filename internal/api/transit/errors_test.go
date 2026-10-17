package transit_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/security"

	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	kmstransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

var codeRE = regexp.MustCompile(`^[a-z][a-z_]*$`)

// wantError는 응답이 {"error":코드,"message":설명}의 일관된 JSON이고 상태·코드가 기대와 같은지 확인한다.
func wantError(t *testing.T, resp *http.Response, status int, code string) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d", resp.StatusCode, status)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if got, _ := body["error"].(string); got != code || !codeRE.MatchString(got) {
		t.Fatalf("error code = %v, want %q (body %v)", body["error"], code, body)
	}
	if m, _ := body["message"].(string); m == "" {
		t.Fatalf("message missing: %v", body)
	}
	return body
}

func TestErrorBodies_MainPaths(t *testing.T) {
	// 400: 본문/ base64 / 암호문 형식
	env := newTestEnv(t)
	if err := env.Barrier.Unseal(); err != nil {
		t.Fatal(err)
	}
	env.Keys.CreateKey("app", 0)

	req, _ := http.NewRequest("POST", env.Server.URL+"/v1/encrypt/app", strings.NewReader("{not json"))
	resp, _ := http.DefaultClient.Do(req)
	wantError(t, resp, 400, "bad_request")
	wantError(t, doJSON(t, "POST", env.Server.URL+"/v1/encrypt/app", map[string]string{"plaintext": "!!!"}), 400, "bad_request")
	wantError(t, doJSON(t, "POST", env.Server.URL+"/v1/decrypt/app", map[string]string{"ciphertext": "garbage"}), 400, "invalid_ciphertext")

	// 404: 존재하지 않는 키 (authz 꺼짐) — 키 이름은 응답에 없다
	body := wantError(t, doJSON(t, "POST", env.Server.URL+"/v1/encrypt/missing-key", map[string]string{"plaintext": "AA=="}), 404, "key_not_found")
	if strings.Contains(body["message"].(string), "missing-key") {
		t.Fatal("key name in 404 message")
	}

	// 403: 예약 키, 인가 거부 — 같은 모양
	rk := apitransit.NewRouter(apitransit.Deps{ReservedKey: "k8s-secrets", Barrier: env.Barrier, Transit: kmstransit.NewTransitService(env.Keys)})
	rec := httptest.NewRecorder()
	rk.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/encrypt/k8s-secrets", nil))
	wantError(t, rec.Result(), 403, "forbidden")
	denied := newTestEnvWithAuthzAndAuthn(t, nil, newFakeAuthorizer(t, false))
	if err := denied.Barrier.Unseal(); err != nil {
		t.Fatal(err)
	}
	// verifier가 nil이면 신원이 없어 인가 미들웨어가 403으로 닫는다.
	wantError(t, doJSON(t, "POST", denied.Server.URL+"/v1/encrypt/app", map[string]string{"plaintext": "AA=="}), 403, "forbidden")

	// 503: sealed
	sealed := newTestEnv(t)
	wantError(t, doJSON(t, "POST", sealed.Server.URL+"/v1/encrypt/app", map[string]string{"plaintext": "AA=="}), 503, "sealed")
}

func TestErrorBodies_401(t *testing.T) {
	verifier, _ := newAuthTestVerifier(t)
	env := newTestEnvWithVerifier(t, verifier)
	wantError(t, doJSON(t, "POST", env.Server.URL+"/v1/encrypt/app", map[string]string{"plaintext": "AA=="}), 401, "unauthorized")
}

func TestErrorBodies_413(t *testing.T) {
	env := newTestEnv(t)
	h := security.Limit(apitransit.NewRouter(apitransit.Deps{Barrier: env.Barrier, Transit: kmstransit.NewTransitService(env.Keys)}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	big := `{"plaintext":"` + strings.Repeat("A", 2<<20) + `"}`
	resp, err := http.Post(srv.URL+"/v1/encrypt/app", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	body := wantError(t, resp, 413, "payload_too_large")
	if body["limit_bytes"] != float64(2<<20) || body["hint"] != "use the datakey API or the kms CLI" {
		t.Fatalf("413 body = %v", body)
	}
	for _, v := range body {
		if s, ok := v.(string); ok && strings.Contains(s, "http") {
			t.Fatalf("413 body contains a URL: %q", s)
		}
	}
}

// 최소 복호화 버전 거부: 응답에는 키 이름·버전 숫자가 없고, 감사 기록에는 남는다.
func TestErrorBodies_MinVersionRejection_HidesDetailButAudits(t *testing.T) {
	srv, km, dir, log := auditEnv(t, newFakeAuthorizer(t, true))
	if _, err := km.CreateKey("secret-name-key", 0); err != nil {
		t.Fatal(err)
	}
	resp := doJSON(t, "POST", srv.URL+"/v1/encrypt/secret-name-key", map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("x"))})
	var enc struct{ Ciphertext string }
	decodeJSON(t, resp, &enc)
	km.RotateKey("secret-name-key")
	two := 2
	km.UpdateConfig("secret-name-key", &two, nil)

	resp = doJSON(t, "POST", srv.URL+"/v1/decrypt/secret-name-key", map[string]string{"ciphertext": enc.Ciphertext})
	body := wantError(t, resp, 400, "version_not_allowed")
	raw, _ := json.Marshal(body)
	for _, leak := range []string{"secret-name-key", "min_decryption_version", "version 1", "version 2", "v1", "2"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("response leaks %q: %s", leak, raw)
		}
	}
	log.Close()
	evs, _ := audit.ReadTransitToday(dir)
	var found bool
	for _, e := range evs {
		if e.Action == "decrypt" && e.Status == 400 && strings.Contains(e.Detail, "secret-name-key") && strings.Contains(e.Detail, "min_decryption_version") {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit lacks the detailed reason: %+v", evs)
	}
}
