package transit_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	kmstransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// newTestEnvWithVerifier는 newTestEnv와 같지만, deps.Verifier를 지정할 수
// 있게 한다 — nil이면 KMS_AUTHN=off, 아니면 KMS_AUTHN=on 상태를 흉내낸다.
func newTestEnvWithVerifier(t *testing.T, verifier *authn.Verifier) *testEnv {
	t.Helper()

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	ts := kmstransit.NewTransitService(km)

	router := apitransit.NewRouter(apitransit.Deps{Barrier: b, Transit: ts, Seal: sealer, Verifier: verifier})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	return &testEnv{Barrier: b, Keys: km, Server: srv}
}

// TestRouter_AuthnOff_AllowsRequestsWithoutToken은 Verifier가 nil(즉
// KMS_AUTHN=off)이면 Authorization 헤더가 전혀 없어도 요청이 통과하는지
// 확인한다 — 로컬 개발/테스트가 토큰 없는 curl로 이뤄지는 현재 동작을
// 깨지 않기 위한 기본값이다.
func TestRouter_AuthnOff_AllowsRequestsWithoutToken(t *testing.T) {
	env := newTestEnvWithVerifier(t, nil)

	resp, err := http.Get(env.Server.URL + "/v1/sys/seal-profile")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d (KMS_AUTHN=off should not require a token)", resp.StatusCode, http.StatusOK)
	}
}

// TestRouter_AuthnOn_RejectsRequestsWithoutToken은 Verifier가 설정된 경우
// (KMS_AUTHN=on) 토큰 없는 요청이 401로 거부되는지 확인한다. sealed 가드
// 밖에 있는 seal-profile로 확인한다 — 인증이 sealed 가드와 무관하게
// 라우터 전체에 걸려있는지를 보는 것이다.
func TestRouter_AuthnOn_RejectsRequestsWithoutToken(t *testing.T) {
	verifier, _ := newAuthTestVerifier(t)
	env := newTestEnvWithVerifier(t, verifier)

	resp, err := http.Get(env.Server.URL + "/v1/sys/seal-profile")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (KMS_AUTHN=on should require a token)", resp.StatusCode, http.StatusUnauthorized)
	}
}

// TestRouter_AuthnOn_AcceptsValidToken은 유효한 토큰을 Authorization 헤더에
// 실으면 요청이 통과해 실제 암호화까지 되는지 확인한다.
func TestRouter_AuthnOn_AcceptsValidToken(t *testing.T) {
	verifier, rsaKey := newAuthTestVerifier(t)
	env := newTestEnvWithVerifier(t, verifier)

	if err := env.Barrier.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if _, err := env.Keys.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	token := signTestToken(t, rsaKey, "default", "app-workload")

	req, err := http.NewRequest(http.MethodPost, env.Server.URL+"/v1/encrypt/app",
		strings.NewReader(`{"plaintext":"`+base64.StdEncoding.EncodeToString([]byte("hi"))+`"}`))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// newAuthTestVerifier는 테스트용 RSA 키쌍을 만들고, 그 공개키만 로드한
// Verifier를 반환한다.
func newAuthTestVerifier(t *testing.T) (*authn.Verifier, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key failed: %v", err)
	}
	v := authn.NewVerifier([]crypto.PublicKey{key.Public()}, authn.Config{})
	return v, key
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, namespace, name string) string {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject: "system:serviceaccount:" + namespace + ":" + name,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing token failed: %v", err)
	}
	return signed
}
