package authn_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
)

// TestVerifier_LegacyToken_ValidSignature_ExtractsIdentity는 레거시 형태
// (exp/nbf/iat/aud 없음, 평평한 kubernetes.io/serviceaccount/* 클레임)
// 토큰이 통과하고, 신원이 정확히 뽑히는지 확인한다.
func TestVerifier_LegacyToken_ValidSignature_ExtractsIdentity(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	token := signRSA(t, keys.rsaKey, legacyClaims{
		Issuer:               "kubernetes/serviceaccount",
		Subject:              "system:serviceaccount:default:mysa",
		LegacyNamespace:      "default",
		LegacyServiceAccount: "mysa",
	})

	id, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if id.Namespace != "default" || id.ServiceAccount != "mysa" {
		t.Fatalf("identity = %+v, want namespace=default serviceaccount=mysa", id)
	}
	if id.Subject != "system:serviceaccount:default:mysa" {
		t.Fatalf("subject = %q, want %q", id.Subject, "system:serviceaccount:default:mysa")
	}
	wantGroups := []string{"system:serviceaccounts", "system:serviceaccounts:default"}
	if len(id.Groups) != 2 || id.Groups[0] != wantGroups[0] || id.Groups[1] != wantGroups[1] {
		t.Fatalf("groups = %v, want %v", id.Groups, wantGroups)
	}
}

// TestVerifier_ProjectedToken_ValidSignature_ExtractsIdentity는 projected
// 형태(kubernetes.io 아래 중첩된 namespace/serviceaccount.name, exp/nbf/iat/
// aud 전부 있음) 토큰이 ES256으로 서명돼도 통과하고 신원이 정확히 뽑히는지
// 확인한다.
func TestVerifier_ProjectedToken_ValidSignature_ExtractsIdentity(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	now := time.Now()
	claims := projectedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://kubernetes.default.svc.cluster.local",
			Subject:   "system:serviceaccount:kube-system:builder",
			Audience:  jwt.ClaimStrings{"https://kubernetes.default.svc"},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	claims.Kubernetes.Namespace = "kube-system"
	claims.Kubernetes.ServiceAccount.Name = "builder"

	token := signES(t, keys.ecKey, claims)

	id, err := v.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if id.Namespace != "kube-system" || id.ServiceAccount != "builder" {
		t.Fatalf("identity = %+v, want namespace=kube-system serviceaccount=builder", id)
	}
}

// TestVerifier_WrongSigningKey_Rejected는 검증기에 로드되지 않은 키로
// 서명된 토큰이 거부되는지 확인한다.
func TestVerifier_WrongSigningKey_Rejected(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	token := signRSA(t, keys.otherRSAKey, legacyClaims{
		Subject: "system:serviceaccount:default:mysa",
	})

	if _, err := v.Verify(token); err == nil {
		t.Fatal("Verify succeeded with a token signed by an untrusted key, want error")
	}
}

// TestVerifier_ExpiredToken_Rejected는 만료된 토큰이 거부되는지 확인한다.
func TestVerifier_ExpiredToken_Rejected(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	claims := projectedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "system:serviceaccount:default:mysa",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}
	claims.Kubernetes.Namespace = "default"
	claims.Kubernetes.ServiceAccount.Name = "mysa"
	token := signRSA(t, keys.rsaKey, claims)

	if _, err := v.Verify(token); err == nil {
		t.Fatal("Verify succeeded with an expired token, want error")
	}
}

// TestVerifier_FutureIssuedAt_Rejected는 iat가 미래인 토큰이 거부되는지
// 확인한다 — jwt/v5의 기본 검증기는 iat를 보지 않으므로, Verifier가 직접
// 확인해야 하는 경로다.
func TestVerifier_FutureIssuedAt_Rejected(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	claims := projectedClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "system:serviceaccount:default:mysa",
			IssuedAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
		},
	}
	claims.Kubernetes.Namespace = "default"
	claims.Kubernetes.ServiceAccount.Name = "mysa"
	token := signRSA(t, keys.rsaKey, claims)

	if _, err := v.Verify(token); err == nil {
		t.Fatal("Verify succeeded with a token issued in the future, want error")
	}
}

// TestVerifier_AlgNone_Rejected는 alg:none(서명 없음) 토큰이 거부되는지
// 확인한다 — 이게 통과하면 누구나 서명 없이 원하는 신원을 자칭할 수 있게
// 되는 치명적인 취약점이다.
func TestVerifier_AlgNone_Rejected(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	token := signNone(t, legacyClaims{
		Subject: "system:serviceaccount:default:mysa",
	})

	if _, err := v.Verify(token); err == nil {
		t.Fatal("Verify succeeded with an alg:none token, want error")
	}
}

// TestVerifier_MalformedToken_Rejected는 아예 JWT 형식이 아닌 문자열이
// 거부되는지 확인한다.
func TestVerifier_MalformedToken_Rejected(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	if _, err := v.Verify("not-a-jwt"); err == nil {
		t.Fatal("Verify succeeded with a malformed token, want error")
	}
}

// TestVerifier_Issuer_MismatchRejected_MatchAccepted는 KMS_SA_ISSUER가
// 설정된 경우 iss 클레임이 일치해야만 통과하는지 확인한다.
func TestVerifier_Issuer_MismatchRejected_MatchAccepted(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{Issuer: "https://kubernetes.default.svc.cluster.local"})

	t.Run("mismatch", func(t *testing.T) {
		token := signRSA(t, keys.rsaKey, legacyClaims{
			Issuer:  "some-other-issuer",
			Subject: "system:serviceaccount:default:mysa",
		})
		if _, err := v.Verify(token); err == nil {
			t.Fatal("Verify succeeded despite issuer mismatch, want error")
		}
	})

	t.Run("match", func(t *testing.T) {
		token := signRSA(t, keys.rsaKey, legacyClaims{
			Issuer:               "https://kubernetes.default.svc.cluster.local",
			Subject:              "system:serviceaccount:default:mysa",
			LegacyNamespace:      "default",
			LegacyServiceAccount: "mysa",
		})
		if _, err := v.Verify(token); err != nil {
			t.Fatalf("Verify failed despite matching issuer: %v", err)
		}
	})
}

// TestVerifier_Audience_MismatchRejected_MatchAccepted는 KMS_SA_AUDIENCE가
// 설정된 경우 aud 클레임이 일치해야만 통과하는지 확인한다.
func TestVerifier_Audience_MismatchRejected_MatchAccepted(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{Audience: "https://kms.internal"})

	t.Run("mismatch", func(t *testing.T) {
		claims := projectedClaims{RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "system:serviceaccount:default:mysa",
			Audience: jwt.ClaimStrings{"https://kubernetes.default.svc"},
		}}
		claims.Kubernetes.Namespace = "default"
		claims.Kubernetes.ServiceAccount.Name = "mysa"
		token := signRSA(t, keys.rsaKey, claims)
		if _, err := v.Verify(token); err == nil {
			t.Fatal("Verify succeeded despite audience mismatch, want error")
		}
	})

	t.Run("match", func(t *testing.T) {
		claims := projectedClaims{RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "system:serviceaccount:default:mysa",
			Audience: jwt.ClaimStrings{"https://kms.internal"},
		}}
		claims.Kubernetes.Namespace = "default"
		claims.Kubernetes.ServiceAccount.Name = "mysa"
		token := signRSA(t, keys.rsaKey, claims)
		if _, err := v.Verify(token); err != nil {
			t.Fatalf("Verify failed despite matching audience: %v", err)
		}
	})
}

// TestVerifier_UnrecognizableSubject_Rejected는 sub/kubernetes.io/legacy
// 클레임 어디에서도 namespace+이름을 뽑을 수 없을 때 명확히 실패하는지
// 확인한다(신원 없이 통과하는 사고를 막는다).
func TestVerifier_UnrecognizableSubject_Rejected(t *testing.T) {
	keys := newTestKeys(t)
	v := newVerifier(keys, authn.Config{})

	token := signRSA(t, keys.rsaKey, legacyClaims{Subject: "not-a-serviceaccount-subject"})

	_, err := v.Verify(token)
	if err == nil {
		t.Fatal("Verify succeeded with an unrecognizable subject, want error")
	}
	if !errors.Is(err, authn.ErrUnauthenticated) {
		t.Fatalf("error = %v, want wrapped %v", err, authn.ErrUnauthenticated)
	}
}
