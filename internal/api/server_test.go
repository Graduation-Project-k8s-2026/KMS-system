package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	ts := transit.NewTransitService(km)

	router := api.NewRouter(api.Deps{Barrier: b, Keys: km, Transit: ts})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
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

// TestAPI_FullFlow는 sealed -> unseal -> 키 생성/조회 -> 암복호화 -> 회전 ->
// min_decryption_version 정책 -> 없는 키 조회까지, README의 MVP 5개 기능이
// 실제 HTTP 요청/응답으로 이어지는지를 순서대로 검증한다.
func TestAPI_FullFlow(t *testing.T) {
	srv := newTestServer(t)

	t.Run("1_sealed_blocks_key_creation", func(t *testing.T) {
		resp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]any{"name": "app"})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
		}
	})

	t.Run("2_unseal", func(t *testing.T) {
		resp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/unseal", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unseal status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		statusResp, err := http.Get(srv.URL + "/v1/sys/seal-status")
		if err != nil {
			t.Fatalf("GET seal-status failed: %v", err)
		}
		var status struct {
			Sealed bool `json:"sealed"`
		}
		decodeJSON(t, statusResp, &status)
		if status.Sealed {
			t.Fatal("seal-status.sealed = true after unseal, want false")
		}
	})

	t.Run("3_create_list_get_key", func(t *testing.T) {
		createResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]any{"name": "app"})
		defer createResp.Body.Close()
		if createResp.StatusCode != http.StatusCreated {
			t.Fatalf("create status = %d, want %d", createResp.StatusCode, http.StatusCreated)
		}

		listResp, err := http.Get(srv.URL + "/v1/keys")
		if err != nil {
			t.Fatalf("GET /v1/keys failed: %v", err)
		}
		var list struct {
			Keys []string `json:"keys"`
		}
		decodeJSON(t, listResp, &list)
		if len(list.Keys) != 1 || list.Keys[0] != "app" {
			t.Fatalf(`keys = %v, want ["app"]`, list.Keys)
		}

		getResp, err := http.Get(srv.URL + "/v1/keys/app")
		if err != nil {
			t.Fatalf("GET /v1/keys/app failed: %v", err)
		}
		defer getResp.Body.Close()
		if getResp.StatusCode != http.StatusOK {
			t.Fatalf("get status = %d, want %d", getResp.StatusCode, http.StatusOK)
		}
	})

	var v1Ciphertext string

	t.Run("4_and_5_encrypt_then_decrypt_round_trip", func(t *testing.T) {
		plaintext := base64.StdEncoding.EncodeToString([]byte("top secret"))

		encResp := doJSON(t, http.MethodPost, srv.URL+"/v1/encrypt/app", map[string]any{"plaintext": plaintext})
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
		v1Ciphertext = encBody.Ciphertext

		decResp := doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/app", map[string]any{"ciphertext": v1Ciphertext})
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
	})

	t.Run("6_rotate_then_encrypt_v2_and_v1_still_decryptable", func(t *testing.T) {
		rotResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys/app/rotate", nil)
		defer rotResp.Body.Close()
		if rotResp.StatusCode != http.StatusOK {
			t.Fatalf("rotate status = %d, want %d", rotResp.StatusCode, http.StatusOK)
		}

		plaintext := base64.StdEncoding.EncodeToString([]byte("after rotation"))
		encResp := doJSON(t, http.MethodPost, srv.URL+"/v1/encrypt/app", map[string]any{"plaintext": plaintext})
		defer encResp.Body.Close()
		var encBody struct {
			Ciphertext string `json:"ciphertext"`
		}
		decodeJSON(t, encResp, &encBody)
		if !strings.HasPrefix(encBody.Ciphertext, "kms:v2:") {
			t.Fatalf("ciphertext = %q, want prefix %q", encBody.Ciphertext, "kms:v2:")
		}

		decResp := doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/app", map[string]any{"ciphertext": v1Ciphertext})
		defer decResp.Body.Close()
		if decResp.StatusCode != http.StatusOK {
			t.Fatalf("decrypt(v1) after rotation status = %d, want %d", decResp.StatusCode, http.StatusOK)
		}
	})

	t.Run("7_raising_min_decryption_version_blocks_v1_decrypt", func(t *testing.T) {
		cfgResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys/app/config", map[string]any{"min_decryption_version": 2})
		defer cfgResp.Body.Close()
		if cfgResp.StatusCode != http.StatusOK {
			t.Fatalf("config status = %d, want %d", cfgResp.StatusCode, http.StatusOK)
		}

		decResp := doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/app", map[string]any{"ciphertext": v1Ciphertext})
		defer decResp.Body.Close()
		if decResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("decrypt(v1) after raising min version status = %d, want %d", decResp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("8_missing_key_returns_404", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/keys/does-not-exist")
		if err != nil {
			t.Fatalf("GET failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})
}
