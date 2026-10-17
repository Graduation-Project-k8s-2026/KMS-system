package seal

import (
	"errors"
	"fmt"
	"sync"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

// TPMBackend: Switch가 TPM 쪽에서 필요로 하는 동작. 실제 구현은 *TPMSeal이고,
// 테스트는 CGO 없이 돌 수 있게 sealtest의 가짜 구현을 끼운다. 인터페이스로 둔
// 이유는 Seal을 barrier에서 분리한 것과 같다 — 호출하는 쪽(barrier/admin)은
// "TPM이 어떤 장치인지" 몰라도 된다.
type TPMBackend interface {
	Seal
	SealExisting(root []byte) error
	RemoveBlob() error
}

var _ TPMBackend = (*TPMSeal)(nil)

// ErrTPMUnavailable: TPM 장치를 열 수 없어 TPM 동작을 할 수 없을 때.
var ErrTPMUnavailable = errors.New("seal: TPM unavailable")

// Switch는 Shamir와 TPM 두 방식을 한 서버 안에서 오가게 해 주는 Seal이다.
//
// 왜 필요한가: barrier는 Seal 인스턴스를 하나만 들고 있다. 그런데 봉인 방식
// 이전(Shamir ↔ TPM)은 서버가 떠 있는 채로 일어나고, TPM 모드에서도 복구용
// Shamir 조각을 받을 수 있어야 한다. 그래서 두 구현체를 안에 두고 "지금 기록상
// 방식"(mode)에 따라 Unseal 경로를 고른다.
//
// 해제 경로:
//  1. 복구 조각이 threshold만큼 모여 있으면 → Shamir로 해제 (TPM 모드의 복구 경로)
//  2. mode가 tpm이면 → TPM 장치로 해제 (자동 해제 경로)
//  3. 그 외 → 조각 부족 에러 (봉인 유지)
//
// 어느 경로든 결과 루트 키는 barrier.validateRoot를 통과해야만 쓰인다. TPM이
// 실패했다고 조용히 다른 방식으로 바꾸거나 초기화하지 않는다(fail-closed) —
// 조각 입력은 운영자가 명시적으로 하는 것이다.
type Switch struct {
	mu     sync.Mutex
	mode   string // "shamir" | "tpm" — init 기록의 seal 값과 같아야 한다
	shamir *ShamirSeal
	tpm    TPMBackend
	open   func() (TPMBackend, error) // 장치를 (다시) 여는 함수. 장치가 없을 수 있어 지연 호출한다.
	store  storage.StorageBackend     // blob 삭제는 장치 없이도 되어야 하므로 store를 직접 안다
}

// NewSwitch: mode는 init 기록의 값. tpm은 이미 열려 있으면 넘기고 없으면 nil
// (open으로 나중에 시도). open이 nil이면 TPM을 쓸 수 없다.
func NewSwitch(mode string, shamir *ShamirSeal, tpm TPMBackend, open func() (TPMBackend, error), store storage.StorageBackend) *Switch {
	return &Switch{mode: mode, shamir: shamir, tpm: tpm, open: open, store: store}
}

// Mode: 현재 봉인 방식("shamir"|"tpm").
func (s *Switch) Mode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode
}

// SetMode: 이전이 성공(기록 저장 완료)한 뒤에만 호출한다.
func (s *Switch) SetMode(m string) {
	s.mu.Lock()
	s.mode = m
	s.mu.Unlock()
}

// Shamir: 복구/주 조각을 받는 ShamirSeal.
func (s *Switch) Shamir() *ShamirSeal { return s.shamir }

// TPM: 열려 있는 TPM을 돌려주고, 없으면 장치를 열어 본다. 실패는 ErrTPMUnavailable로
// 감싸므로 호출자는 errors.Is로 "장치 문제"를 구분할 수 있다.
func (s *Switch) TPM() (TPMBackend, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tpm != nil {
		return s.tpm, nil
	}
	if s.open == nil {
		return nil, fmt.Errorf("%w: no TPM device configured", ErrTPMUnavailable)
	}
	t, err := s.open()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTPMUnavailable, err)
	}
	s.tpm = t
	return t, nil
}

// RemoveTPMBlob: 저장된 blob을 지운다. 장치가 없어도 동작해야 한다 — TPM이 고장
// 났을 때 Shamir로 되돌리는 것이 바로 이 기능의 주된 용도이기 때문이다.
func (s *Switch) RemoveTPMBlob() error {
	return s.store.Delete(tpmBlobStorageKey)
}

// Unseal: 위 "해제 경로" 참고.
func (s *Switch) Unseal() ([]byte, error) {
	if s.shamir.IsConfigured() {
		return s.shamir.Unseal()
	}
	if s.Mode() == "tpm" {
		t, err := s.TPM()
		if err != nil {
			return nil, err
		}
		return t.Unseal()
	}
	return s.shamir.Unseal() // ErrNotEnoughShares
}

// Type: 기록상 방식. barrier는 이 값으로 validateRoot 여부와 기록 일치를 확인한다.
func (s *Switch) Type() string { return s.Mode() }

func (s *Switch) IsConfigured() bool {
	if s.shamir.IsConfigured() {
		return true
	}
	if s.Mode() != "tpm" {
		return false
	}
	t, err := s.TPM()
	return err == nil && t.IsConfigured()
}

// Profile: 현재 방식의 특성. seal-profile API(Transit)가 Switch에서도 동작하게 한다.
func (s *Switch) Profile() SealProfile {
	if s.Mode() == "tpm" {
		p := tpmProfile()
		p.Notes = "TPM 자동 해제 + 같은 루트 키의 Shamir 복구 조각(장치 고장 시 조각으로 해제)"
		return p
	}
	return s.shamir.Profile()
}
