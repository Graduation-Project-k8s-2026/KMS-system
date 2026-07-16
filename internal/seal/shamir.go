// shamir.go: Shamir Secret Sharing 기반 Seal 구현체.
//
// DevSeal과 비교해 이 방식이 해결하는 문제: DevSeal은 Root Key가 패스프레이즈
// "하나"에서 결정적으로 유도된다 — 그 패스프레이즈를 아는 사람 한 명이면
// 누구든 Root Key 전체를 즉시 얻는다(단일 장애점/단일 신뢰점). ShamirSeal은
// Root Key를 처음부터 완전히 무작위로 생성하고 어디에도 통째로 저장하지
// 않는다. 대신 Shamir Secret Sharing으로 parts개의 "조각"으로 쪼개 서로 다른
// 운영자들에게 나눠주고, 오직 그중 threshold개 이상이 실제로(같은 시점에)
// 모여야만 Unseal이 가능하다 — 운영자 한 명(혹은 threshold 미만의 공모자들)이
// 아무리 애써도 Root Key를 복원할 수 없다는 게 수학적으로 보장된다. 이것이
// "단일 장애점 제거"가 실제로 의미하는 바다.
//
// 그 대가로 잃는 것: DevSeal은 패스프레이즈만 있으면 사람 개입 없이 자동으로
// Unseal할 수 있어서 서버 재시작 시 KMS_AUTO_UNSEAL 같은 자동화가 가능하다.
// ShamirSeal은 그럴 수 없다 — 서버가 재시작될 때마다 threshold명의 운영자가
// 각자 자기 조각을 실제로 제출해야만 봉인이 풀린다. 보안(단일 장애점 제거)과
// 운영 편의성(자동 복구) 사이의 트레이드오프이며, 실무 KMS/Vault가 흔히
// Shamir를 기본값으로 쓰는 이유이기도 하다.
package seal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"sync"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/shamir"
)

var (
	// ErrNotEnoughShares: 조각이 threshold만큼 모이지 않은 상태에서 Unseal을
	// 호출했을 때 반환.
	ErrNotEnoughShares = errors.New("seal: not enough shares submitted to unseal")

	// ErrDuplicateShare: 이미 제출된 것과 완전히 같은 조각을 다시 제출했을 때
	// 반환.
	//
	// 이걸 막아야 하는 이유는 Shamir의 보안 가정 자체와 직결된다:
	// "threshold명이 각자 서로 다른 조각을 실제로 갖고 모여야 한다"가
	// 안전성의 전제인데, 같은 조각을 두 번(혹은 여러 번) 제출하는 걸 허용하면
	// 조각을 하나만 손에 넣은 사람이 그걸 반복 제출해서 "threshold개가 모인
	// 것처럼" 위장할 수 있다. 즉 이 검증이 없으면 threshold가 사실상 1로
	// 무너진다.
	ErrDuplicateShare = errors.New("seal: this share has already been submitted")

	// ErrThresholdAlreadyMet: 이미 threshold만큼 조각이 모인 뒤에 조각을 더
	// 제출하려 했을 때 반환. Unseal을 부르거나 Reset한 뒤 다시 시작해야 한다.
	ErrThresholdAlreadyMet = errors.New("seal: threshold already met; call Unseal or Reset")

	// ErrInvalidShareLength: 제출된 조각의 길이가 예상(crypto.KeyLen+1바이트)과
	// 다를 때 반환.
	ErrInvalidShareLength = errors.New("seal: share has an unexpected length")
)

// shamirShareLen: ShamirSeal이 다루는 조각의 길이. Root Key가 항상
// crypto.KeyLen(32)바이트이고, shamir.Split이 조각마다 x좌표 1바이트를 더
// 붙이므로(shamir.ShareOverhead) 조각은 항상 이 길이여야 한다.
const shamirShareLen = kmscrypto.KeyLen + shamir.ShareOverhead

// ShamirSeal은 Shamir Secret Sharing으로 Root Key를 보호하는 Seal 구현체다.
// 조각이 여러 차례에 걸쳐(운영자마다 한 번씩) 제출되므로, DevSeal과 달리
// 내부에 "지금까지 모인 조각"이라는 상태를 갖는다.
type ShamirSeal struct {
	threshold int

	mu     sync.Mutex
	shares [][]byte // 지금까지 제출된 조각들 (제출 순서, 중복 없음)
}

// NewShamirSeal은 threshold개의 조각이 모여야 Unseal 가능한 ShamirSeal을 만든다.
func NewShamirSeal(threshold int) *ShamirSeal {
	return &ShamirSeal{threshold: threshold}
}

// SubmitShare는 조각 하나를 접수해 누적하고, 현재까지 모인 개수를 반환한다.
func (s *ShamirSeal) SubmitShare(share []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(share) != shamirShareLen {
		return len(s.shares), ErrInvalidShareLength
	}
	if len(s.shares) >= s.threshold {
		return len(s.shares), ErrThresholdAlreadyMet
	}
	for _, existing := range s.shares {
		if bytes.Equal(existing, share) {
			return len(s.shares), ErrDuplicateShare
		}
	}

	stored := make([]byte, len(share))
	copy(stored, share)
	s.shares = append(s.shares, stored)

	return len(s.shares), nil
}

// IsConfigured는 조각이 threshold만큼 모였는지 반환한다 — 이 값이 true면
// Unseal이 성공할 것으로 기대할 수 있다.
func (s *ShamirSeal) IsConfigured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.shares) >= s.threshold
}

// Unseal은 모인 조각으로 shamir.Combine을 실행해 Root Key를 복원한다. 조각이
// 부족하면 에러를 반환한다. 복원에 성공하면 조각 자체는 더 이상 필요 없으므로,
// 수집해둔 조각들을 메모리에서 0으로 덮어 지운다 — 조각도 Root Key 못지않은
// 비밀이라, 다 쓴 뒤에는 남겨두지 않는다.
func (s *ShamirSeal) Unseal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.shares) < s.threshold {
		return nil, ErrNotEnoughShares
	}

	rootKey, err := shamir.Combine(s.shares)
	if err != nil {
		return nil, err
	}

	s.clearSharesLocked()

	return rootKey, nil
}

// Type은 이 seal 구현의 이름 "shamir"를 반환한다.
func (s *ShamirSeal) Type() string {
	return "shamir"
}

// Reset은 지금까지 모은 조각을 전부 버리고 처음 상태로 되돌린다 — Unseal이
// 실패했거나 잘못된 조각이 섞여 들어간 것 같을 때, 처음부터 다시 모으기
// 위해 쓴다.
func (s *ShamirSeal) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clearSharesLocked()
}

// clearSharesLocked는 수집된 조각들을 0으로 덮어쓰고 비운다. 호출자가 이미
// s.mu를 잠근 상태여야 한다.
func (s *ShamirSeal) clearSharesLocked() {
	for _, share := range s.shares {
		zeroBytes(share)
	}
	s.shares = nil
}

// zeroBytes는 슬라이스의 모든 바이트를 0으로 덮어쓴다.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// InitShamir는 최초 1회 실행하는 초기화 함수다. crypto/rand로 완전히 새로운
// Root Key(32바이트)를 만들고, 그걸 shamir.Split으로 parts개 조각으로 나눈다.
//
// DevSeal은 패스프레이즈에서 매번 같은 Root Key를 "유도"하므로 별도의 init이
// 필요 없다(패스프레이즈만 있으면 언제든 같은 키가 나온다). 반면 ShamirSeal은
// Root Key를 무작위로 생성하고 그 값을 어디에도(디스크, 설정 파일, 어느 한
// 사람의 기억) 저장하지 않는다 — 오직 이 함수가 반환하는 조각 M개가 나중에
// 다시 모여야만 Unseal로 복원된다. Root Key 자체가 이 함수 호출이 끝나는
// 순간 "어디에도 온전한 형태로는 존재하지 않는" 상태가 되는 것, 이게 바로
// "단일 장애점 제거"가 실제로 의미하는 바다.
//
// 반환된 rootKey는 호출자가 barrier를 초기화하는 데 한 번 쓰고, shares는
// 운영자들에게 각각 한 번씩 보여준 뒤(그리고 호출자 쪽에서도) 즉시 버려야
// 한다 — 이 함수는 그 이후의 배포/폐기까지 책임지지 않는다.
func InitShamir(parts, threshold int) (rootKey []byte, shares [][]byte, err error) {
	rootKey = make([]byte, kmscrypto.KeyLen)
	if _, err := rand.Read(rootKey); err != nil {
		return nil, nil, err
	}

	shares, err = shamir.Split(rootKey, parts, threshold)
	if err != nil {
		zeroBytes(rootKey)
		return nil, nil, err
	}

	return rootKey, shares, nil
}
