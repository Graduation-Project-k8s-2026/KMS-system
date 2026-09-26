package transit_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	kmstransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// newFakeAuthorizer는 지정된 allowed 값을 항상 돌려주는 SubjectAccessReview
// fake 클라이언트로 Authorizer를 만든다.
func newFakeAuthorizer(t *testing.T, allowed bool) *authz.Authorizer {
	t.Helper()
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create := action.(k8stesting.CreateAction)
		sar := create.GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		sar.Status = authorizationv1.SubjectAccessReviewStatus{Allowed: allowed}
		return true, sar, nil
	})
	return authz.NewAuthorizer(client.AuthorizationV1().SubjectAccessReviews(), authz.Config{})
}

// newTestEnvWithAuthzAndAuthn은 인증(verifier)과 인가(authorizer)를 모두
// 설정한 Transit 라우터로 testEnv를 만든다.
func newTestEnvWithAuthzAndAuthn(t *testing.T, verifier *authn.Verifier, authorizer *authz.Authorizer) *testEnv {
	t.Helper()

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	ts := kmstransit.NewTransitService(km)

	router := apitransit.NewRouter(apitransit.Deps{
		Barrier:    b,
		Transit:    ts,
		Seal:       sealer,
		Verifier:   verifier,
		Authorizer: authorizer,
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &testEnv{Barrier: b, Keys: km, Server: srv}
}

func newAuthorizedRequest(t *testing.T, method, url, token, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

// TestRouter_AuthzOn_DeniedBlocksEncrypt는 SAR이 거부를 응답하면
// POST /v1/encrypt/{name}이 403으로 막히는지 확인한다.
func TestRouter_AuthzOn_DeniedBlocksEncrypt(t *testing.T) {
	verifier, rsaKey := newAuthTestVerifier(t)
	authorizer := newFakeAuthorizer(t, false)
	env := newTestEnvWithAuthzAndAuthn(t, verifier, authorizer)

	if err := env.Barrier.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if _, err := env.Keys.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	token := signTestToken(t, rsaKey, "team-a", "app-workload")
	req := newAuthorizedRequest(t, http.MethodPost, env.Server.URL+"/v1/encrypt/app", token,
		`{"plaintext":"`+base64.StdEncoding.EncodeToString([]byte("hi"))+`"}`)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// TestRouter_AuthzOn_AllowedPermitsEncrypt는 SAR이 허용을 응답하면
// 요청이 통과해 실제 암호화까지 되는지 확인한다.
func TestRouter_AuthzOn_AllowedPermitsEncrypt(t *testing.T) {
	verifier, rsaKey := newAuthTestVerifier(t)
	authorizer := newFakeAuthorizer(t, true)
	env := newTestEnvWithAuthzAndAuthn(t, verifier, authorizer)

	if err := env.Barrier.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if _, err := env.Keys.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	token := signTestToken(t, rsaKey, "team-a", "app-workload")
	req := newAuthorizedRequest(t, http.MethodPost, env.Server.URL+"/v1/encrypt/app", token,
		`{"plaintext":"`+base64.StdEncoding.EncodeToString([]byte("hi"))+`"}`)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestRouter_AuthzOn_SealProfileAndBenchmarkExemptFromAuthz는 SAR이 항상
// 거부를 응답하는 상태에서도 seal-profile/seal-benchmark은 (인증만 통과하면)
// 여전히 200으로 응답하는지 확인한다 — 이 둘은 특정 키를 대상으로 하지
// 않는 진단 엔드포인트라 인가 대상에서 의도적으로 제외했다.
func TestRouter_AuthzOn_SealProfileAndBenchmarkExemptFromAuthz(t *testing.T) {
	verifier, rsaKey := newAuthTestVerifier(t)
	authorizer := newFakeAuthorizer(t, false) // 항상 거부
	env := newTestEnvWithAuthzAndAuthn(t, verifier, authorizer)

	token := signTestToken(t, rsaKey, "team-a", "app-workload")

	for _, path := range []string{"/v1/sys/seal-profile", "/v1/sys/seal-benchmark"} {
		t.Run(path, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, env.Server.URL+path, nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d, want %d (should be exempt from authz)", path, resp.StatusCode, http.StatusOK)
			}
		})
	}
}
