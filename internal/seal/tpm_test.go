package seal

import (
	"bytes"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/google/go-tpm-tools/simulator"
)

// 컴파일 타임에 "*TPMSeal이 Seal 인터페이스를 만족하는가"를 확인한다.
// var _ Seal = (*ShamirSeal)(nil)의 설명은 shamir_test.go 참고 — 원리는 동일하다.
var _ Seal = (*TPMSeal)(nil)

func newTestSimulator(t *testing.T) *simulator.Simulator {
	t.Helper()

	sim, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get failed: %v", err)
	}
	t.Cleanup(func() { sim.Close() })
	return sim
}

func TestTPMSeal_InitThenUnseal_RoundTrip(t *testing.T) {
	sim := newTestSimulator(t)
	s := NewTPMSeal(sim, storage.NewMemoryStorage())

	rootKey, err := s.InitTPM()
	if err != nil {
		t.Fatalf("InitTPM failed: %v", err)
	}

	got, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if !bytes.Equal(got, rootKey) {
		t.Fatalf("Unseal = %x, want %x", got, rootKey)
	}
}

func TestTPMSeal_RootKeyIs32Bytes(t *testing.T) {
	sim := newTestSimulator(t)
	s := NewTPMSeal(sim, storage.NewMemoryStorage())

	rootKey, err := s.InitTPM()
	if err != nil {
		t.Fatalf("InitTPM failed: %v", err)
	}
	if len(rootKey) != 32 {
		t.Fatalf("len(rootKey) = %d, want 32", len(rootKey))
	}
}

func TestTPMSeal_BlobDoesNotContainPlaintextRootKey(t *testing.T) {
	sim := newTestSimulator(t)
	store := storage.NewMemoryStorage()
	s := NewTPMSeal(sim, store)

	rootKey, err := s.InitTPM()
	if err != nil {
		t.Fatalf("InitTPM failed: %v", err)
	}

	raw, err := store.Get(tpmBlobStorageKey)
	if err != nil {
		t.Fatalf("store.Get failed: %v", err)
	}
	if raw == nil {
		t.Fatal("store.Get returned nil; expected a stored sealed blob")
	}
	if bytes.Contains(raw, rootKey) {
		t.Fatal("stored blob contains the plaintext root key; expected it to be TPM-sealed")
	}
}

func TestTPMSeal_Unconfigured_IsConfiguredFalse_UnsealErrors(t *testing.T) {
	sim := newTestSimulator(t)
	s := NewTPMSeal(sim, storage.NewMemoryStorage())

	if s.IsConfigured() {
		t.Fatal("IsConfigured() = true before InitTPM")
	}
	if _, err := s.Unseal(); err != ErrTPMNotInitialized {
		t.Fatalf("Unseal err = %v, want ErrTPMNotInitialized", err)
	}
}

func TestTPMSeal_IsConfiguredTrueAfterInit(t *testing.T) {
	sim := newTestSimulator(t)
	s := NewTPMSeal(sim, storage.NewMemoryStorage())

	if _, err := s.InitTPM(); err != nil {
		t.Fatalf("InitTPM failed: %v", err)
	}
	if !s.IsConfigured() {
		t.Fatal("IsConfigured() = false after InitTPM")
	}
}

func TestTPMSeal_InitTwice_SecondRejected(t *testing.T) {
	sim := newTestSimulator(t)
	s := NewTPMSeal(sim, storage.NewMemoryStorage())

	if _, err := s.InitTPM(); err != nil {
		t.Fatalf("InitTPM (1st) failed: %v", err)
	}
	if _, err := s.InitTPM(); err != ErrTPMAlreadyInitialized {
		t.Fatalf("InitTPM (2nd) err = %v, want ErrTPMAlreadyInitialized", err)
	}
}

func TestTPMSeal_Type(t *testing.T) {
	sim := newTestSimulator(t)
	s := NewTPMSeal(sim, storage.NewMemoryStorage())

	if s.Type() != "tpm" {
		t.Fatalf("Type() = %q, want %q", s.Type(), "tpm")
	}
}

func TestTPMSeal_WithPCRs_RoundTrip(t *testing.T) {
	sim := newTestSimulator(t)
	s := NewTPMSeal(sim, storage.NewMemoryStorage(), WithPCRs([]int{7}))

	rootKey, err := s.InitTPM()
	if err != nil {
		t.Fatalf("InitTPM (with PCRs) failed: %v", err)
	}

	got, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal (with PCRs) failed: %v", err)
	}
	if !bytes.Equal(got, rootKey) {
		t.Fatalf("Unseal (with PCRs) = %x, want %x", got, rootKey)
	}
}

// TestTPMSeal_DifferentTPMCannotUnsealOthersBlob은 TPM의 핵심 보안 속성 —
// "그 TPM이 아니면 sealed blob을 절대 열 수 없다" — 을 검증하려던 테스트다.
//
// 직접 실험해본 결과: 같은 프로세스 안에서 simulator.Get()을 두 번 호출해
// "서로 다른 TPM 두 개"를 만들고, 하나(sim1)로 봉인한 blob을 다른 하나
// (sim2)로 열려고 시도하면 — 실패 응답이 오는 게 아니라 그 호출 자체가
// 응답 없이 멈췄다(2분 타임아웃으로도 끝나지 않음). go-tpm-tools의
// 시뮬레이터는 Microsoft의 TPM 2.0 레퍼런스 구현(ms-tpm-20-ref)을 cgo로
// 그대로 빌드해 쓰는데, 이 C 구현은 프로세스 전역(정적) 상태를 갖는 것으로
// 보인다 — 즉 "두 개의 시뮬레이터 인스턴스"가 실제로는 완전히 독립된 두
// TPM이 아니라 같은 전역 상태를 공유하는 셈이라서, 한쪽에서 세션을 잡은
// 채로 다른 쪽을 건드리면 내부적으로 교착 상태에 빠지는 것으로 추정된다.
//
// 이건 TPMSeal 구현의 버그가 아니라 소프트웨어 시뮬레이터 자체의 한계다.
// "다른 TPM으로는 못 연다"는 속성은 TPM 사양과 SRK가 TPM마다 고유하다는
// 사실에서 이론적으로 보장되지만, 그걸 같은 프로세스 안의 시뮬레이터
// 인스턴스 두 개로 안전하게 재현하는 방법은 이 라이브러리 수준에서 찾지
// 못했다. 실제로 검증하려면 물리적으로 분리된 TPM 두 개(또는 최소한
// 프로세스가 분리된 시뮬레이터 두 개)가 필요하다.
func TestTPMSeal_DifferentTPMCannotUnsealOthersBlob(t *testing.T) {
	t.Skip("go-tpm-tools 시뮬레이터는 프로세스 전역 C 상태를 공유하는 것으로 " +
		"보여, 같은 프로세스에서 두 번째 simulator.Get() 인스턴스로 첫 번째의 " +
		"sealed blob을 열려고 하면 응답 없이 멈춘다(직접 재현, 2분 타임아웃). " +
		"테스트 스위트 전체를 위험에 빠뜨리지 않기 위해 스킵한다 — 자세한 내용은 " +
		"이 함수 위 주석 참고.")
}
