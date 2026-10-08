// Package authz는 Transit API 호출자가 "이 키에 이 동작을 해도 되는가"를
// 판단한다 — internal/authn(1단계)이 이미 확인한 "누구인지"를 전제로 한다.
//
// 자체 정책 저장소를 두지 않고 쿠버네티스 RBAC에 위임한다: kube-apiserver의
// SubjectAccessReview(SAR)에 "이 주체가 이 작업을 해도 되는가"를 묻는다.
// 정책 저장/편집 API·관리 UI·백업을 따로 만들 필요가 없고, 관리자는
// 익숙한 kubectl로 Role/RoleBinding을 다루면 된다.
//
// 네임스페이스 스코프에 대한 주의: 키 저장소 자체에는 네임스페이스 개념이
// 없다 — 키는 클러스터 전역으로 하나의 목록이다. 네임스페이스는 접근 권한
// 판단에만 쓰인다. 즉 "team-a의 demo 키"가 따로 존재하는 게 아니라, "demo
// 키에 대한 team-a 소속 요청자의 권한"을 SAR에 묻는 것이다.
package authz

// APIGroup/Resource는 SAR 질의에 쓰는 가상 리소스 식별자다. 실제
// 쿠버네티스에 존재하는 리소스가 아니다 — SAR은 존재하지 않는 리소스에도
// 질의를 허용하므로 이 방식이 성립한다. 이름이 추후 바뀔 수 있다고 알려져
// 있으므로, 코드 전체에서 이 두 상수만 참조하게 해 한 곳만 고치면 되게
// 한다.
const (
	APIGroup = "kms.local"
	Resource = "keys"
)
