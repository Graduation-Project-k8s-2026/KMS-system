// Package authz는 Transit API 호출자가 "이 키에 이 동작을 해도 되는가"를
// 판단한다 — internal/authn(1단계)이 이미 확인한 "누구인지"를 전제로 한다.
//
// 자체 정책 저장소를 두지 않고 쿠버네티스 RBAC에 위임한다: kube-apiserver의
// SubjectAccessReview(SAR)에 "이 주체가 이 작업을 해도 되는가"를 묻는다.
// 정책 저장/편집 API·관리 UI·백업을 따로 만들 필요가 없고, 관리자는
// 익숙한 kubectl로 Role/RoleBinding을 다루면 된다.
//
// 네임스페이스 의미 (C+B 키 소유 모델, ADR-009): 키 이름이 <ns>.<name>이면 그 키는
// <ns> 소유이고, SAR의 namespace는 <ns>다 — 그 네임스페이스의 Role/RoleBinding만
// 효력이 있다(다른 네임스페이스의 SA도 소유 팀이 RoleBinding subjects에 넣으면 쓸 수
// 있다). 점이 없는 키는 클러스터 전역 키로, SAR을 namespace 없이 보내 ClusterRole/
// ClusterRoleBinding으로만 허용된다. 요청자 SA의 네임스페이스는 판단에 쓰지 않는다.
package authz

import "github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"

// APIGroup/Resource는 SAR 질의에 쓰는 가상 리소스 식별자다. 실제
// 쿠버네티스에 존재하는 리소스가 아니다 — SAR은 존재하지 않는 리소스에도
// 질의를 허용하므로 이 방식이 성립한다. 이름이 추후 바뀔 수 있다고 알려져
// 있으므로, 코드 전체에서 이 두 상수만 참조하게 해 한 곳만 고치면 되게
// 한다.
const (
	APIGroup = "kms.local"
	Resource = "keys"
)

// JudgedNamespace는 키 이름에서 SAR에 보낼 네임스페이스를 구한다. 점 없는 전역 키는 ""를
// 반환한다(클러스터 범위 판단). 이름 형식이 틀리면 에러.
func JudgedNamespace(keyName string) (string, error) {
	ns, _, err := keys.ParseName(keyName)
	return ns, err
}
