package transit_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	kmstransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// testEnv는 Transit 라우터 하나와, 그 라우터가 감싼 barrier/keys를 함께
// 들고 있다. 키 생성/unseal 같은 관리 연산은 이제 이 라우터에 없으므로,
// 테스트가 이를 직접(HTTP를 거치지 않고) 호출해 준비 상태를 만든다 — 실제
// 배포에서는 admin.sock을 통해 이뤄지는 일이다.
type testEnv struct {
	Barrier *barrier.Barrier
	Keys    *keys.KeyManager
	Server  *httptest.Server
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	ts := kmstransit.NewTransitService(km)

	router := apitransit.NewRouter(apitransit.Deps{Barrier: b, Transit: ts, Seal: sealer})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &testEnv{Barrier: b, Keys: km, Server: srv}
}

func doJSON(t *testing.T, method, url string, body any) *http.Response {
	t.Helper()

	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	req, err := http.NewRequest(method, url, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func decodeJSON(t *testing.T, resp *http.Response, dest any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		t.Fatalf("decode response body failed: %v", err)
	}
}

// TestRouter_AdminRoutesNotRegistered는 키 관리/init/unseal/seal-status 같은
// 관리 라우트가 Transit 라우터에는 전혀 등록되지 않았음을 확인한다 — 이
// 라우터만 네트워크(TCP)로 열리므로, 여기 관리 라우트가 남아있으면 관리
// 평면이 실수로 네트워크에 노출되는 셈이다.
func TestRouter_AdminRoutesNotRegistered(t *testing.T) {
	env := newTestEnv(t)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/keys"},
		{http.MethodGet, "/v1/keys"},
		{http.MethodGet, "/v1/keys/app"},
		{http.MethodPost, "/v1/keys/app/rotate"},
		{http.MethodPost, "/v1/keys/app/config"},
		{http.MethodGet, "/v1/sys/seal-status"},
		{http.MethodPost, "/v1/sys/init"},
		{http.MethodPost, "/v1/sys/unseal"},
	}

	for _, tc := range cases {
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			resp := doJSON(t, tc.method, env.Server.URL+tc.path, map[string]any{})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want %d (admin route must not exist on transit router)", resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}

// TestRouter_StaticPagesNotRegistered는 웹 UI(/,/dashboard,/console,/portal)가
// Transit 라우터에도 등록되지 않았음을 확인한다 — 관리 API가 생기기 전까지
// 웹 UI는 비활성이어야 한다.
func TestRouter_StaticPagesNotRegistered(t *testing.T) {
	env := newTestEnv(t)

	for _, path := range []string{"/", "/dashboard", "/console", "/portal"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(env.Server.URL + path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s status = %d, want %d", path, resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}

// TestRouter_SealedGuard_BlocksEncrypt는 barrier가 sealed인 상태에서
// POST /v1/encrypt/{name}이 503으로 막히는지 확인한다.
func TestRouter_SealedGuard_BlocksEncrypt(t *testing.T) {
	env := newTestEnv(t) // Unseal 호출 안 함 -> sealed 상태 그대로

	resp := doJSON(t, http.MethodPost, env.Server.URL+"/v1/encrypt/app", map[string]any{"plaintext": "aGk="})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// TestRouter_EncryptDecryptRewrap_RoundTrip은 (unseal/키 생성/회전은 직접
// 호출로 준비해두고) 암호화 -> 복호화 -> 회전 후 rewrap -> 복호화까지
// Transit 라우터만으로 도는지 확인한다.
func TestRouter_EncryptDecryptRewrap_RoundTrip(t *testing.T) {
	env := newTestEnv(t)

	if err := env.Barrier.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if _, err := env.Keys.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("top secret"))

	encResp := doJSON(t, http.MethodPost, env.Server.URL+"/v1/encrypt/app", map[string]any{"plaintext": plaintext})
	defer encResp.Body.Close()
	if encResp.StatusCode != http.StatusOK {
		t.Fatalf("encrypt status = %d, want %d", encResp.StatusCode, http.StatusOK)
	}
	var encBody struct {
		Ciphertext string `json:"ciphertext"`
	}
	decodeJSON(t, encResp, &encBody)
	if !strings.HasPrefix(encBody.Ciphertext, "kms:v1:") {
		t.Fatalf("ciphertext = %q, want prefix %q", encBody.Ciphertext, "kms:v1:")
	}
	v1Ciphertext := encBody.Ciphertext

	decResp := doJSON(t, http.MethodPost, env.Server.URL+"/v1/decrypt/app", map[string]any{"ciphertext": v1Ciphertext})
	defer decResp.Body.Close()
	if decResp.StatusCode != http.StatusOK {
		t.Fatalf("decrypt status = %d, want %d", decResp.StatusCode, http.StatusOK)
	}
	var decBody struct {
		Plaintext string `json:"plaintext"`
	}
	decodeJSON(t, decResp, &decBody)
	if decBody.Plaintext != plaintext {
		t.Fatalf("decrypted plaintext = %q, want %q", decBody.Plaintext, plaintext)
	}

	if _, err := env.Keys.RotateKey("app"); err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	rewrapResp := doJSON(t, http.MethodPost, env.Server.URL+"/v1/rewrap/app", map[string]any{"ciphertext": v1Ciphertext})
	defer rewrapResp.Body.Close()
	if rewrapResp.StatusCode != http.StatusOK {
		t.Fatalf("rewrap status = %d, want %d", rewrapResp.StatusCode, http.StatusOK)
	}
	var rewrapBody struct {
		Ciphertext string `json:"ciphertext"`
	}
	decodeJSON(t, rewrapResp, &rewrapBody)
	if !strings.HasPrefix(rewrapBody.Ciphertext, "kms:v2:") {
		t.Fatalf("rewrap ciphertext = %q, want prefix %q", rewrapBody.Ciphertext, "kms:v2:")
	}

	decResp2 := doJSON(t, http.MethodPost, env.Server.URL+"/v1/decrypt/app", map[string]any{"ciphertext": rewrapBody.Ciphertext})
	defer decResp2.Body.Close()
	if decResp2.StatusCode != http.StatusOK {
		t.Fatalf("decrypt(rewrapped) status = %d, want %d", decResp2.StatusCode, http.StatusOK)
	}
}

// TestRouter_SealProfile_WorksWhileSealed는 GET /v1/sys/seal-profile이 unseal
// 여부와 무관하게(sealed 가드 밖에 있으므로) 200을 반환하는지 확인한다.
func TestRouter_SealProfile_WorksWhileSealed(t *testing.T) {
	env := newTestEnv(t) // sealed 상태 그대로

	resp, err := http.Get(env.Server.URL + "/v1/sys/seal-profile")
	if err != nil {
		t.Fatalf("GET seal-profile failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (sealed guard should not apply here)", resp.StatusCode, http.StatusOK)
	}
	var profile struct {
		Type string `json:"Type"`
	}
	decodeJSON(t, resp, &profile)
	if profile.Type != "dev" {
		t.Fatalf("profile.Type = %q, want %q", profile.Type, "dev")
	}
}

// TestRouter_SealBenchmark_WorksWhileSealed_ReturnsFourResults는
// GET /v1/sys/seal-benchmark도 sealed 상태에서 동작하며 dev/shamir/tpm/k8s
// 4개 결과를 반환하는지 확인한다.
func TestRouter_SealBenchmark_WorksWhileSealed_ReturnsFourResults(t *testing.T) {
	env := newTestEnv(t) // sealed 상태 그대로

	resp, err := http.Get(env.Server.URL + "/v1/sys/seal-benchmark")
	if err != nil {
		t.Fatalf("GET seal-benchmark failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (sealed guard should not apply here)", resp.StatusCode, http.StatusOK)
	}

	var results []struct {
		Type string `json:"type"`
	}
	decodeJSON(t, resp, &results)
	if len(results) != 4 {
		t.Fatalf("len(results) = %d, want 4", len(results))
	}
}
