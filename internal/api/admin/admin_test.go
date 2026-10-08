package admin_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apiadmin "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newTestServerWithSeal(t, seal.NewDevSeal("test-passphrase"), 0, 0)
}

// newTestServerWithSeal은 임의의 Seal 구현체(dev/shamir/tpm/k8s 무엇이든)로
// Admin 라우터만 조립한다 — main.go가 실제로 하는 조립을 그대로 흉내낸
// 것이다. 암복호화(Transit)는 관여하지 않는다.
func newTestServerWithSeal(t *testing.T, sealer seal.Seal, shamirParts, shamirThreshold int) *httptest.Server {
	t.Helper()

	store := storage.NewMemoryStorage()
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)

	router := apiadmin.NewRouter(apiadmin.Deps{
		Barrier:         b,
		Keys:            km,
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

// TestRouter_TransitRoutesNotRegistered는 암복호화/rewrap과
// seal-profile/seal-benchmark이 Admin 라우터에는 전혀 등록되지 않았음을
// 확인한다 — 이 라우터는 유닉스 소켓 전용이라 여기 데이터 평면 라우트가
// 남아있으면 안 된다(설계상 큰 문제는 아니지만, 두 평면의 경계가 코드
// 상에서도 명확해야 한다).
func TestRouter_TransitRoutesNotRegistered(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/v1/encrypt/app"},
		{http.MethodPost, "/v1/decrypt/app"},
		{http.MethodPost, "/v1/rewrap/app"},
		{http.MethodGet, "/v1/sys/seal-profile"},
		{http.MethodGet, "/v1/sys/seal-benchmark"},
	}

	for _, tc := range cases {
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			resp := doJSON(t, tc.method, srv.URL+tc.path, map[string]any{})
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want %d (transit route must not exist on admin router)", resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}

// TestRouter_StaticPagesNotRegistered는 웹 UI(/,/dashboard,/console,/portal)가
// Admin 라우터에도 등록되지 않았음을 확인한다. 브라우저는 유닉스 소켓에
// 접속할 수 없으므로 등록해도 쓸모가 없고, 관리 API(HTTPS -> admin.sock
// 중계)가 생기기 전까지는 의도적으로 비활성이다.
func TestRouter_StaticPagesNotRegistered(t *testing.T) {
	srv := newTestServer(t)

	for _, path := range []string{"/", "/dashboard", "/console", "/portal"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + path)
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

// TestRouter_SealedGuard_BlocksKeyCreation은 barrier가 sealed인 상태에서
// POST /v1/keys가 503으로 막히는지 확인한다.
func TestRouter_SealedGuard_BlocksKeyCreation(t *testing.T) {
	srv := newTestServer(t) // Unseal 호출 안 함 -> sealed 상태 그대로

	resp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]any{"name": "app"})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// TestRouter_KeyLifecycle_CreateListGetRotateConfig은 unseal 이후 키 생성 ->
// 목록 -> 조회 -> 회전 -> 정책 설정까지 관리 평면 흐름을 검증한다.
func TestRouter_KeyLifecycle_CreateListGetRotateConfig(t *testing.T) {
	srv := newTestServer(t)

	unsealResp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/unseal", nil)
	unsealResp.Body.Close()
	if unsealResp.StatusCode != http.StatusOK {
		t.Fatalf("unseal status = %d, want %d", unsealResp.StatusCode, http.StatusOK)
	}

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

	rotResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys/app/rotate", nil)
	defer rotResp.Body.Close()
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status = %d, want %d", rotResp.StatusCode, http.StatusOK)
	}

	cfgResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys/app/config", map[string]any{"min_decryption_version": 2})
	defer cfgResp.Body.Close()
	if cfgResp.StatusCode != http.StatusOK {
		t.Fatalf("config status = %d, want %d", cfgResp.StatusCode, http.StatusOK)
	}
}

// TestRouter_MissingKey_Returns404는 없는 키를 조회하면 404가 되는지 확인한다.
func TestRouter_MissingKey_Returns404(t *testing.T) {
	srv := newTestServer(t)

	unsealResp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/unseal", nil)
	unsealResp.Body.Close()

	resp, err := http.Get(srv.URL + "/v1/keys/does-not-exist")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

// TestRouter_DevSeal_UnsealWithoutInit_ImmediatelyUnseals는 dev seal이 별도
// init 없이 unseal 한 번으로 즉시 열리는지 확인한다 — 패스프레이즈에서
// 결정론적으로 Root Key가 나오므로 "초기화"라는 별도 단계가 아예 없다.
func TestRouter_DevSeal_UnsealWithoutInit_ImmediatelyUnseals(t *testing.T) {
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

// TestRouter_Init_CalledTwice_Returns409는 이미 unseal된 상태에서 init을 다시
// 호출하면 409가 되는지 확인한다.
func TestRouter_Init_CalledTwice_Returns409(t *testing.T) {
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

// TestRouter_ShamirSeal_InitAndProgressiveUnseal은 shamir의 핵심 흐름 —
// init으로 조각을 발급받고, threshold에 도달할 때까지 조각을 하나씩
// 제출하면서 진행 상황이 올바르게 보고되는지, 마지막 조각에서 실제로
// unseal되는지, 그 뒤 키 생성까지 정상 동작하는지 — 를 검증한다.
func TestRouter_ShamirSeal_InitAndProgressiveUnseal(t *testing.T) {
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

	createResp := doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]any{"name": "app"})
	defer createResp.Body.Close()
	if createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create key status = %d, want %d", createResp.StatusCode, http.StatusCreated)
	}
}

// TestRouter_SealStatus_ReportsSealType은 seal_type이 조립한 seal 종류를 그대로
// 반영하는지 dev/shamir 각각에 대해 확인한다.
func TestRouter_SealStatus_ReportsSealType(t *testing.T) {
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
