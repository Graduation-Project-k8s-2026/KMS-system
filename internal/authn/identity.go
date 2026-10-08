// Package authn은 Transit API(:8200) 호출자의 신원을 확인한다 — "누구인지"
// 만 검증하고 "무엇을 할 수 있는지"(인가)는 다루지 않는다. 인가는 2단계
// 작업(SubjectAccessReview)에서 다룬다.
//
// 검증 방식은 apiserver의 TokenReview를 호출하는 대신, ServiceAccount 토큰
// (kube-apiserver가 서명한 JWT)의 서명을 로컬에서 직접 검증한다 — KMS가
// static pod로 배포될 예정이라 ServiceAccount 토큰이 자동 마운트되지
// 않고(admission controller를 거치지 않으므로), apiserver 호출에 필요한
// 자격 증명을 KMS가 스스로 마련해야 한다. 게다가 암복호화는 요청마다
// 일어나는 핫패스라 매 요청 apiserver 왕복은 지연 측면에서도 부적합하다.
// 대신 컨트롤 플레인 노드에 존재하는 서명 공개키(예: /etc/kubernetes/pki/
// sa.pub)로 서명만 로컬 검증한다.
//
// 한계: 토큰 폐기(revocation) 여부는 이 방식으로 확인할 수 없다 — 서명이
// 유효하고 exp가 지나지 않았다면, apiserver가 그 사이 해당 토큰을
// 무효화했더라도 로컬 검증은 통과시킨다. README의 인증 절에 명시한다.
package authn

import "context"

// Identity는 검증에 성공한 ServiceAccount 토큰에서 뽑아낸 요청자 신원이다.
type Identity struct {
	// Namespace: 토큰을 발급받은 ServiceAccount의 네임스페이스.
	Namespace string
	// ServiceAccount: ServiceAccount 이름(네임스페이스 내에서만 고유).
	ServiceAccount string
	// Subject: "system:serviceaccount:<namespace>:<name>" 형태의 전체
	// 주체 문자열. 2단계 SubjectAccessReview에서 그대로 쓴다.
	Subject string
	// Groups: apiserver의 ServiceAccount 인증기가 부여하는 것과 동일한
	// 표준 그룹("system:serviceaccounts", "system:serviceaccounts:<ns>")을
	// 이쪽에서 합성한 값이다 — 토큰 자체에는 이 그룹들이 클레임으로 들어있지
	// 않다(TokenReview 응답에서만 볼 수 있는, apiserver가 계산해주는 값).
	// 2단계 SAR에서 사용한다.
	Groups []string
}

type contextKey struct{}

// WithIdentity는 검증된 신원을 컨텍스트에 싣는다.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// IdentityFromContext는 WithIdentity로 실어둔 신원을 꺼낸다. 인증 미들웨어를
// 통과한 요청의 컨텍스트에만 존재한다.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}
