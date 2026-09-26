package authn

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// saClaims는 쿠버네티스 ServiceAccount 토큰의 두 형태를 모두 담을 수 있는
// 클레임 구조다.
//
//   - 레거시 토큰(자동 마운트 시크릿, K8s 1.21 이전 기본값)은 평평한
//     "kubernetes.io/serviceaccount/namespace",
//     "kubernetes.io/serviceaccount/service-account.name" 클레임을 쓰고,
//     exp/nbf/iat/aud가 없다(만료 개념 자체가 없음).
//   - Projected 토큰(TokenRequest API, K8s 1.22+ 기본값)은
//     "kubernetes.io" 클레임 아래 중첩된 namespace/serviceaccount.name을
//     쓰고, exp/nbf/iat/aud를 전부 갖는다.
//
// 둘 다 sub 클레임은 공통으로 "system:serviceaccount:<namespace>:<name>"
// 형태이므로, 이게 없거나 파싱이 안 될 때만 위 클레임들로 보완한다.
type saClaims struct {
	jwt.RegisteredClaims

	LegacyNamespace      string `json:"kubernetes.io/serviceaccount/namespace,omitempty"`
	LegacyServiceAccount string `json:"kubernetes.io/serviceaccount/service-account.name,omitempty"`

	Kubernetes *projectedClaim `json:"kubernetes.io,omitempty"`
}

type projectedClaim struct {
	Namespace      string `json:"namespace"`
	ServiceAccount struct {
		Name string `json:"name"`
	} `json:"serviceaccount"`
}

// identityFromClaims는 검증이 끝난 클레임에서 Identity를 뽑아낸다. 우선
// projected 토큰의 중첩 클레임을, 없으면 레거시 토큰의 평평한 클레임을,
// 그마저 없으면 sub 클레임을 파싱해 namespace/이름을 얻는다 — sub는 두
// 형태 모두에 공통으로 존재하는 필드라 최후의 보완책으로 쓸 수 있다.
func identityFromClaims(c *saClaims) (Identity, error) {
	var namespace, name string

	switch {
	case c.Kubernetes != nil && c.Kubernetes.Namespace != "" && c.Kubernetes.ServiceAccount.Name != "":
		namespace = c.Kubernetes.Namespace
		name = c.Kubernetes.ServiceAccount.Name
	case c.LegacyNamespace != "" && c.LegacyServiceAccount != "":
		namespace = c.LegacyNamespace
		name = c.LegacyServiceAccount
	default:
		ns, n, err := parseSubject(c.Subject)
		if err != nil {
			return Identity{}, fmt.Errorf("%w: %v", ErrUnauthenticated, err)
		}
		namespace, name = ns, n
	}

	subject := c.Subject
	if subject == "" {
		subject = fmt.Sprintf("system:serviceaccount:%s:%s", namespace, name)
	}

	return Identity{
		Namespace:      namespace,
		ServiceAccount: name,
		Subject:        subject,
		Groups: []string{
			"system:serviceaccounts",
			"system:serviceaccounts:" + namespace,
		},
	}, nil
}

// parseSubject는 "system:serviceaccount:<namespace>:<name>" 형태의 sub
// 클레임에서 namespace/이름을 뽑는다.
func parseSubject(sub string) (namespace, name string, err error) {
	parts := strings.Split(sub, ":")
	if len(parts) != 4 || parts[0] != "system" || parts[1] != "serviceaccount" || parts[2] == "" || parts[3] == "" {
		return "", "", fmt.Errorf("cannot extract identity: unrecognized subject %q", sub)
	}
	return parts[2], parts[3], nil
}
