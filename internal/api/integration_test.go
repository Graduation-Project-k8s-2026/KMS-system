// 이 파일은 internal/api/admin과 internal/api/transit이 같은
// barrier/keys/transit 인스턴스를 공유할 때 두 라우터에 걸친 흐름(관리
// 평면에서 키를 만들고 회전시키면, 데이터 평면에서 그 키로 암복호화/rewrap이
// 정상 동작하는지)이 실제 배포 형태(서로 다른 리스너, 같은 프로세스 상태)와
// 동일하게 이어지는지 검증한다.
package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiadmin "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	kmstransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// twoPlaneServer는 admin.sock과 Transit TCP 리스너가 실제로는 서로 다른
// 프로세스 진입점이지만 같은 barrier/keys/transit 상태를 공유한다는 사실을
// httptest.Server 두 개로 재현한다.
type twoPlaneServer struct {
	Admin   *httptest.Server
	Transit *httptest.Server
}

func newTwoPlaneServer(t *testing.T, sealer seal.Seal, shamirParts, shamirThreshold int) *twoPlaneServer {
	t.Helper()

	store := storage.NewMemoryStorage()
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	ts := kmstransit.NewTransitService(km)

	adminRouter := apiadmin.NewRouter(apiadmin.Deps{
		Barrier:         b,
		Keys:            km,
		Seal:            sealer,
		ShamirParts:     shamirParts,
		ShamirThreshold: shamirThreshold,
	})
	transitRouter := apitransit.NewRouter(apitransit.Deps{Barrier: b, Transit: ts, Seal: sealer})

	adminSrv := httptest.NewServer(adminRouter)
	transitSrv := httptest.NewServer(transitRouter)
	t.Cleanup(adminSrv.Close)
	t.Cleanup(transitSrv.Close)

	return &twoPlaneServer{Admin: adminSrv, Transit: transitSrv}
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

// TestTwoPlane_FullFlow는 sealed -> (admin) unseal -> 키 생성/조회 ->
// (transit) 암복호화 -> (admin) 회전 -> (transit) rewrap -> (admin)
// min_decryption_version 정책 -> 없는 키 조회까지, README의 MVP 기능이
// 두 평면에 걸쳐 하나의 흐름으로 이어지는지 순서대로 검증한다.
func TestTwoPlane_FullFlow(t *testing.T) {
	srv := newTwoPlaneServer(t, seal.NewDevSeal("test-passphrase"), 0, 0)

	t.Run("1_sealed_blocks_key_creation", func(t *testing.T) {
		resp := doJSON(t, http.MethodPost, srv.Admin.URL+"/v1/keys", map[string]any{"name": "app"})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
		}
	})

	t.Run("2_unseal_via_admin", func(t *testing.T) {
		resp := doJSON(t, http.MethodPost, srv.Admin.URL+"/v1/sys/unseal", nil)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unseal status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		statusResp, err := http.Get(srv.Admin.URL + "/v1/sys/seal-status")
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

	t.Run("3_create_list_get_key_via_admin", func(t *testing.T) {
		createResp := doJSON(t, http.MethodPost, srv.Admin.URL+"/v1/keys", map[string]any{"name": "app"})
		defer createResp.Body.Close()
		if createResp.StatusCode != http.StatusCreated {
			t.Fatalf("create status = %d, want %d", createResp.StatusCode, http.StatusCreated)
		}

		listResp, err := http.Get(srv.Admin.URL + "/v1/keys")
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
	})

	var v1Ciphertext string

	t.Run("4_and_5_encrypt_then_decrypt_via_transit", func(t *testing.T) {
		plaintext := base64.StdEncoding.EncodeToString([]byte("top secret"))

		encResp := doJSON(t, http.MethodPost, srv.Transit.URL+"/v1/encrypt/app", map[string]any{"plaintext": plaintext})
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

		decResp := doJSON(t, http.MethodPost, srv.Transit.URL+"/v1/decrypt/app", map[string]any{"ciphertext": v1Ciphertext})
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

	t.Run("6_rotate_via_admin_then_rewrap_via_transit", func(t *testing.T) {
		rotResp := doJSON(t, http.MethodPost, srv.Admin.URL+"/v1/keys/app/rotate", nil)
		defer rotResp.Body.Close()
		if rotResp.StatusCode != http.StatusOK {
			t.Fatalf("rotate status = %d, want %d", rotResp.StatusCode, http.StatusOK)
		}

		rewrapResp := doJSON(t, http.MethodPost, srv.Transit.URL+"/v1/rewrap/app", map[string]any{"ciphertext": v1Ciphertext})
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

		decResp := doJSON(t, http.MethodPost, srv.Transit.URL+"/v1/decrypt/app", map[string]any{"ciphertext": rewrapBody.Ciphertext})
		defer decResp.Body.Close()
		if decResp.StatusCode != http.StatusOK {
			t.Fatalf("decrypt(rewrapped) status = %d, want %d", decResp.StatusCode, http.StatusOK)
		}
	})

	t.Run("7_raising_min_decryption_version_via_admin_blocks_v1_decrypt_via_transit", func(t *testing.T) {
		cfgResp := doJSON(t, http.MethodPost, srv.Admin.URL+"/v1/keys/app/config", map[string]any{"min_decryption_version": 2})
		defer cfgResp.Body.Close()
		if cfgResp.StatusCode != http.StatusOK {
			t.Fatalf("config status = %d, want %d", cfgResp.StatusCode, http.StatusOK)
		}

		decResp := doJSON(t, http.MethodPost, srv.Transit.URL+"/v1/decrypt/app", map[string]any{"ciphertext": v1Ciphertext})
		defer decResp.Body.Close()
		if decResp.StatusCode != http.StatusBadRequest {
			t.Fatalf("decrypt(v1) after raising min version status = %d, want %d", decResp.StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("8_missing_key_returns_404_via_admin", func(t *testing.T) {
		resp, err := http.Get(srv.Admin.URL + "/v1/keys/does-not-exist")
		if err != nil {
			t.Fatalf("GET failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
		}
	})
}
