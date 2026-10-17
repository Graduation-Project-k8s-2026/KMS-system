// Package keys: 키 생성/조회/회전/버전 관리.
package keys

import "time"

// KeyVersion은 KeyRing 안의 한 버전 — 실제 KEK material을 담고 있다.
//
// KeyMaterial은 여기 그대로 디스크에 쓰이지 않는다. KeyRing 전체가
// barrier.PutJSON을 통해 저장되고, barrier가 이 JSON 전체를 Root Key로 암호화한
// 뒤에야 storage로 내려가기 때문이다 — 그래서 "KeyMaterial이 평문 그대로 파일에
// 남는다"는 걱정 없이 이 구조체에 그대로 넣어둘 수 있다.
type KeyVersion struct {
	Version     int
	KeyMaterial []byte // 이 버전의 KEK (crypto.KeyLen=32 바이트)
	CreatedAt   time.Time
}

// KeyRing은 하나의 키 이름 아래 존재하는 모든 버전의 묶음이다. barrier 아래
// (즉 Root Key로 암호화된 채로) 저장되는 내부 표현이며, KeyMaterial을 포함하므로
// 절대 API 응답으로 그대로 내보내면 안 된다.
type KeyRing struct {
	Name                 string
	Type                 string // 지금은 "aes256-gcm" 하나뿐
	CreatedAt            time.Time
	LatestVersion        int
	MinDecryptionVersion int
	AutoRotatePeriodSec  int // 0이면 자동 회전 안 함
	LastRotatedAt        time.Time
	Versions             []KeyVersion

	// State: 키 수명 상태 ("active"|"disabled"|"pending_deletion"). 이 필드가 없는 기존(옛 형식) 키는
	// 빈 문자열로 읽히며 active로 취급한다 — 그래서 저장 형식을 바꿔도 운영 중인 키를 그대로 읽는다.
	State string `json:",omitempty"`
	// DeletionDate: pending_deletion일 때만 값이 있다. 이 시각이 지나면 백그라운드 작업이 키 자료를 삭제한다.
	DeletionDate *time.Time `json:",omitempty"`
}

// 키 상태 값.
const (
	StateActive          = "active"
	StateDisabled        = "disabled"
	StatePendingDeletion = "pending_deletion"
)

// state는 빈 값(옛 형식)을 active로 정규화한다.
func (r *KeyRing) state() string {
	if r.State == "" {
		return StateActive
	}
	return r.State
}

// KeyRingMeta는 외부(조회 API 응답 등)로 노출하는 표현이다. KeyRing과 필드가
// 거의 같지만 KeyMaterial이 통째로 빠져 있다 — KEK 원문이 조회 API를 통해
// 실수로라도 새어나갈 방법을 타입 수준에서 차단하는 것이 목적이다. "material을
// 지우는 로직을 매번 잘 짜는지"에 의존하지 않고, 애초에 그 필드가 존재하지 않는
// 타입을 반환하게 만들어 사고를 원천 차단한다.
type KeyRingMeta struct {
	Name                 string
	Type                 string
	CreatedAt            time.Time
	LatestVersion        int
	MinDecryptionVersion int
	AutoRotatePeriodSec  int
	LastRotatedAt        time.Time
	Versions             []KeyVersionMeta
	State                string     `json:"state"`
	DeletionDate         *time.Time `json:"deletion_date,omitempty"`
}

// KeyVersionMeta는 KeyVersion의 외부 노출용 표현 — KeyMaterial 제외.
type KeyVersionMeta struct {
	Version   int
	CreatedAt time.Time
}
