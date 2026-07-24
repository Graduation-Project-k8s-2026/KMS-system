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
	return newTestServerWithSeal(t, seal.NewDevSeal("test-passphrase"), 0, 0)
}

// newTestServerWithSeal은 임의의 Seal 구현체(dev/shamir/tpm/k8s 무엇이든)로
// 서버를 조립한다. shamirParts/shamirThreshold는 shamir가 아닌 seal에는
// 아무 영향이 없다 — main.go가 실제로 하는 조립을 그대로 흉내낸 것이다.
func newTestServerWithSeal(t *testing.T, sealer seal.Seal, shamirParts, shamirThreshold int) *httptest.Server {
	t.Helper()

	store := storage.NewMemoryStorage()
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	ts := transit.NewTransitService(km)

	router := api.NewRouter(api.Deps{
		Barrier:         b,
		Keys:            km,
		Transit:         ts,
		Seal:            sealer,
		ShamirParts:     shamirParts,
		ShamirThreshold: shamirThreshold,
	})
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

// TestAPI_Rewrap은 별도의 새 서버/키로 unseal -> 키생성 -> encrypt(v1) -> rotate
// -> rewrap -> decrypt 흐름을 검증한다. TestAPI_FullFlow의 "app" 키는 이미
// min_decryption_version=2로 올려둬서 v1 rewrap이 막힌 상태이므로, 이 테스트는
// 독립된 키로 새로 시작한다.
func TestAPI_Rewrap(t *testing.T) {
	srv := newTestServer(t)

	unsealResp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/unseal", nil)
	unsealResp.Body.Close()

	createResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]any{"name": "rewrap-app"})
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want %d", createResp.StatusCode, http.StatusCreated)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("rewrap me via http"))
	encResp := doJSON(t, http.MethodPost, srv.URL+"/v1/encrypt/rewrap-app", map[string]any{"plaintext": plaintext})
	var encBody struct {
		Ciphertext string `json:"ciphertext"`
	}
	decodeJSON(t, encResp, &encBody)
	v1Ciphertext := encBody.Ciphertext
	if !strings.HasPrefix(v1Ciphertext, "kms:v1:") {
		t.Fatalf("ciphertext = %q, want prefix %q", v1Ciphertext, "kms:v1:")
	}

	rotResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys/rewrap-app/rotate", nil)
	rotResp.Body.Close()
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d", rotResp.StatusCode, http.StatusOK)
	}

	rewrapResp := doJSON(t, http.MethodPost, srv.URL+"/v1/rewrap/rewrap-app", map[string]any{"ciphertext": v1Ciphertext})
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

	decResp := doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/rewrap-app", map[string]any{"ciphertext": rewrapBody.Ciphertext})
	defer decResp.Body.Close()
	if decResp.StatusCode != http.StatusOK {
		t.Fatalf("decrypt(rewrapped) status = %d, want %d", decResp.StatusCode, http.StatusOK)
	}
	var decBody struct {
		Plaintext string `json:"plaintext"`
	}
	decodeJSON(t, decResp, &decBody)
	if decBody.Plaintext != plaintext {
		t.Fatalf("decrypted plaintext = %q, want %q", decBody.Plaintext, plaintext)
	}
}

// TestAPI_DevSeal_UnsealWithoutInit_ImmediatelyUnseals는 dev seal이 별도
// init 없이 unseal 한 번으로 즉시 열리는지 확인한다 — 패스프레이즈에서
// 결정론적으로 Root Key가 나오므로 "초기화"라는 별도 단계가 아예 없다.
func TestAPI_DevSeal_UnsealWithoutInit_ImmediatelyUnseals(t *testing.T) {
	srv := newTestServer(t)

	resp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/unseal", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unseal status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	var body struct {
		Sealed bool `json:"sealed"`
	}
	decodeJSON(t, resp, &body)
	if body.Sealed {
		t.Fatal("sealed = true after unseal (no init called), want false")
	}
}

// TestAPI_ShamirSeal_InitAndProgressiveUnseal은 shamir의 핵심 흐름 —
// init으로 조각을 발급받고, threshold에 도달할 때까지 조각을 하나씩
// 제출하면서 진행 상황이 올바르게 보고되는지, 마지막 조각에서 실제로
// unseal되는지, 그 뒤 KMS가 정상 동작하는지 — 를 검증한다.
func TestAPI_ShamirSeal_InitAndProgressiveUnseal(t *testing.T) {
	const parts, threshold = 5, 3
	srv := newTestServerWithSeal(t, seal.NewShamirSeal(threshold), parts, threshold)

	initResp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/init", map[string]any{})
	defer initResp.Body.Close()
	if initResp.StatusCode != http.StatusCreated {
		t.Fatalf("init status = %d, want %d", initResp.StatusCode, http.StatusCreated)
	}
	var initBody struct {
		Shares []string `json:"shares"`
		Sealed bool     `json:"sealed"`
	}
	decodeJSON(t, initResp, &initBody)
	if len(initBody.Shares) != parts {
		t.Fatalf("len(shares) = %d, want %d", len(initBody.Shares), parts)
	}
	if !initBody.Sealed {
		t.Fatal("init response sealed = false, want true (shamir still needs POST /v1/sys/unseal)")
	}

	submitShare := func(share string) (sealed bool, progress string) {
		resp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/unseal", map[string]any{"share": share})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unseal status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		var body struct {
			Sealed   bool   `json:"sealed"`
			Progress string `json:"progress"`
		}
		decodeJSON(t, resp, &body)
		return body.Sealed, body.Progress
	}

	if sealed, progress := submitShare(initBody.Shares[0]); !sealed || progress != "1/3" {
		t.Fatalf("after share 1: sealed=%v progress=%q, want sealed=true progress=%q", sealed, progress, "1/3")
	}
	if sealed, progress := submitShare(initBody.Shares[1]); !sealed || progress != "2/3" {
		t.Fatalf("after share 2: sealed=%v progress=%q, want sealed=true progress=%q", sealed, progress, "2/3")
	}

	statusResp, err := http.Get(srv.URL + "/v1/sys/seal-status")
	if err != nil {
		t.Fatalf("GET seal-status failed: %v", err)
	}
	var status struct {
		Sealed   bool   `json:"sealed"`
		SealType string `json:"seal_type"`
		Progress string `json:"progress"`
	}
	decodeJSON(t, statusResp, &status)
	if !status.Sealed || status.SealType != "shamir" || status.Progress != "2/3" {
		t.Fatalf("seal-status = %+v, want sealed=true seal_type=shamir progress=2/3", status)
	}

	if sealed, _ := submitShare(initBody.Shares[2]); sealed {
		t.Fatal("after share 3 (threshold reached): sealed = true, want false")
	}

	// unseal 후 KMS가 실제로 정상 동작하는지 (키 생성 + 암호화).
	createResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]any{"name": "app"})
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create key status = %d, want %d", createResp.StatusCode, http.StatusCreated)
	}

	plaintext := base64.StdEncoding.EncodeToString([]byte("shamir unsealed this"))
	encResp := doJSON(t, http.MethodPost, srv.URL+"/v1/encrypt/app", map[string]any{"plaintext": plaintext})
	defer encResp.Body.Close()
	if encResp.StatusCode != http.StatusOK {
		t.Fatalf("encrypt status = %d, want %d", encResp.StatusCode, http.StatusOK)
	}
}

// TestAPI_SealStatus_ReportsSealType은 seal_type이 조립한 seal 종류를 그대로
// 반영하는지 dev/shamir 각각에 대해 확인한다.
func TestAPI_SealStatus_ReportsSealType(t *testing.T) {
	t.Run("dev", func(t *testing.T) {
		srv := newTestServer(t)

		resp, err := http.Get(srv.URL + "/v1/sys/seal-status")
		if err != nil {
			t.Fatalf("GET failed: %v", err)
		}
		var status struct {
			SealType string `json:"seal_type"`
		}
		decodeJSON(t, resp, &status)
		if status.SealType != "dev" {
			t.Fatalf("seal_type = %q, want %q", status.SealType, "dev")
		}
	})

	t.Run("shamir", func(t *testing.T) {
		srv := newTestServerWithSeal(t, seal.NewShamirSeal(3), 5, 3)

		resp, err := http.Get(srv.URL + "/v1/sys/seal-status")
		if err != nil {
			t.Fatalf("GET failed: %v", err)
		}
		var status struct {
			SealType string `json:"seal_type"`
		}
		decodeJSON(t, resp, &status)
		if status.SealType != "shamir" {
			t.Fatalf("seal_type = %q, want %q", status.SealType, "shamir")
		}
	})
}

// TestAPI_Init_CalledTwice_Returns409는 "이미 unseal된 상태에서 init을 다시
// 호출하면 409"를 dev seal로 검증한다.
//
// dev/shamir 자체에는 "이미 초기화됨"을 나타내는 영속 상태가 없다 —
// InitShamir는 아무 것도 저장하지 않는 순수 함수라, sealed 상태에서 두 번
// 불러도 그 자체로는 막을 방법이 없다. 그래서 handleInit의 가드는 "barrier가
// 이미 unsealed인가"로 판단한다 — 이건 seal 종류와 무관하게 항상 적용되는
// 규칙이라 dev로 검증하는 게 가장 간단하고 확실하다. TPM/K8s는 이 가드에
// 더해 InitTPM/InitK8s 자체가 반환하는 "이미 존재" 에러로도 409가 되는데,
// 그건 internal/seal/tpm_test.go, k8s_test.go(TestTPMSeal_InitTwice_SecondRejected,
// TestK8sSeal_InitTwice_SecondRejected)에서 이미 검증하고 있다.
func TestAPI_Init_CalledTwice_Returns409(t *testing.T) {
	srv := newTestServer(t)

	resp1 := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/init", map[string]any{})
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("init (1st) status = %d, want %d", resp1.StatusCode, http.StatusOK)
	}

	resp2 := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/init", map[string]any{})
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("init (2nd) status = %d, want %d", resp2.StatusCode, http.StatusConflict)
	}
}
