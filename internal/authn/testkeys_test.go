package authn_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
)

// testKeys는 검증 대상 서명키 쌍(rsaKey)과, 서명자를 흉내내되 검증기에는
// 절대 로드하지 않는 "다른 키"(otherRSAKey) — 서명 불일치 테스트에 쓴다.
type testKeys struct {
	rsaKey      *rsa.PrivateKey
	otherRSAKey *rsa.PrivateKey
	ecKey       *ecdsa.PrivateKey
}

func newTestKeys(t *testing.T) *testKeys {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key failed: %v", err)
	}
	otherRSAKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating other RSA key failed: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key failed: %v", err)
	}

	return &testKeys{rsaKey: rsaKey, otherRSAKey: otherRSAKey, ecKey: ecKey}
}

// legacyClaims는 레거시(자동 마운트 시크릿) ServiceAccount 토큰의 클레임
// 형태를 흉내낸다 — exp/nbf/iat/aud가 없다.
type legacyClaims struct {
	Issuer               string `json:"iss,omitempty"`
	Subject              string `json:"sub,omitempty"`
	LegacyNamespace      string `json:"kubernetes.io/serviceaccount/namespace,omitempty"`
	LegacyServiceAccount string `json:"kubernetes.io/serviceaccount/service-account.name,omitempty"`
}

func (legacyClaims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (legacyClaims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (legacyClaims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (c legacyClaims) GetIssuer() (string, error)                 { return c.Issuer, nil }
func (c legacyClaims) GetSubject() (string, error)                { return c.Subject, nil }
func (legacyClaims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

// projectedClaims는 TokenRequest API 기반 projected 토큰의 클레임 형태를
// 흉내낸다 — kubernetes.io 아래 중첩된 namespace/serviceaccount.name과
// exp/nbf/iat/aud를 전부 갖는다.
type projectedClaims struct {
	jwt.RegisteredClaims
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

func signRSA(t *testing.T, key *rsa.PrivateKey, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing token failed: %v", err)
	}
	return signed
}

func signES(t *testing.T, key *ecdsa.PrivateKey, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing token failed: %v", err)
	}
	return signed
}

// signNone은 alg:none, 서명 없는 토큰을 만든다 — 반드시 거부되어야 한다.
func signNone(t *testing.T, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("signing none-alg token failed: %v", err)
	}
	return signed
}

func newVerifier(keys *testKeys, cfg authn.Config) *authn.Verifier {
	pubKeys := []crypto.PublicKey{keys.rsaKey.Public(), keys.ecKey.Public()}
	return authn.NewVerifier(pubKeys, cfg)
}
