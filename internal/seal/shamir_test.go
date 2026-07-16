package seal

import (
	"bytes"
	"testing"
)

// 컴파일 타임에 "*ShamirSeal이 Seal 인터페이스를 만족하는가"를 확인하는
// 관용구다. 오른쪽의 (*ShamirSeal)(nil)은 *ShamirSeal 타입의 nil 포인터
// 값을 만드는 표현이고, 그걸 Seal 타입 변수에 대입할 수 있는지를 컴파일러가
// 검사한다. 왼쪽의 "_"는 "이 값 자체를 실제로 쓰지는 않고, 대입이 되는지만
// 확인하고 싶다"는 뜻이다. 만약 ShamirSeal이 Seal의 메서드(Unseal/Type/
// IsConfigured) 중 하나라도 빠뜨리면, 이 한 줄이 그 자리에서 바로 컴파일
// 에러를 내서 — 테스트를 실제로 실행해보지 않고도 — 문제를 알 수 있다.
var _ Seal = (*ShamirSeal)(nil)

func TestShamirSeal_FullFlow_UnsealRecoversOriginalRootKey(t *testing.T) {
	rootKey, shares, err := InitShamir(5, 3)
	if err != nil {
		t.Fatalf("InitShamir failed: %v", err)
	}

	s := NewShamirSeal(3)
	for i := 0; i < 3; i++ {
		if _, err := s.SubmitShare(shares[i]); err != nil {
			t.Fatalf("SubmitShare(%d) failed: %v", i, err)
		}
	}

	got, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if !bytes.Equal(got, rootKey) {
		t.Fatalf("Unseal = %x, want %x", got, rootKey)
	}
}

func TestShamirSeal_NotEnoughShares_IsConfiguredFalse_UnsealErrors(t *testing.T) {
	_, shares, err := InitShamir(5, 3)
	if err != nil {
		t.Fatalf("InitShamir failed: %v", err)
	}

	s := NewShamirSeal(3)
	if _, err := s.SubmitShare(shares[0]); err != nil {
		t.Fatalf("SubmitShare failed: %v", err)
	}

	if s.IsConfigured() {
		t.Fatal("IsConfigured() = true with only 1 of 3 required shares")
	}
	if _, err := s.Unseal(); err != ErrNotEnoughShares {
		t.Fatalf("Unseal err = %v, want ErrNotEnoughShares", err)
	}
}

func TestShamirSeal_RejectsDuplicateShare(t *testing.T) {
	_, shares, err := InitShamir(5, 3)
	if err != nil {
		t.Fatalf("InitShamir failed: %v", err)
	}

	s := NewShamirSeal(3)
	if _, err := s.SubmitShare(shares[0]); err != nil {
		t.Fatalf("SubmitShare (1st) failed: %v", err)
	}
	if _, err := s.SubmitShare(shares[0]); err != ErrDuplicateShare {
		t.Fatalf("SubmitShare (duplicate) err = %v, want ErrDuplicateShare", err)
	}
}

func TestShamirSeal_RejectsSubmissionAfterThresholdMet(t *testing.T) {
	_, shares, err := InitShamir(5, 3)
	if err != nil {
		t.Fatalf("InitShamir failed: %v", err)
	}

	s := NewShamirSeal(3)
	for i := 0; i < 3; i++ {
		if _, err := s.SubmitShare(shares[i]); err != nil {
			t.Fatalf("SubmitShare(%d) failed: %v", i, err)
		}
	}

	if _, err := s.SubmitShare(shares[3]); err != ErrThresholdAlreadyMet {
		t.Fatalf("SubmitShare (4th, after threshold) err = %v, want ErrThresholdAlreadyMet", err)
	}
}

func TestShamirSeal_ResetAllowsStartingOver(t *testing.T) {
	_, shares, err := InitShamir(5, 3)
	if err != nil {
		t.Fatalf("InitShamir failed: %v", err)
	}

	s := NewShamirSeal(3)
	if _, err := s.SubmitShare(shares[0]); err != nil {
		t.Fatalf("SubmitShare failed: %v", err)
	}

	s.Reset()

	if s.IsConfigured() {
		t.Fatal("IsConfigured() = true right after Reset")
	}
	if len(s.shares) != 0 {
		t.Fatalf("len(s.shares) after Reset = %d, want 0", len(s.shares))
	}

	for i := 0; i < 3; i++ {
		if _, err := s.SubmitShare(shares[i]); err != nil {
			t.Fatalf("SubmitShare(%d) after Reset failed: %v", i, err)
		}
	}
	if !s.IsConfigured() {
		t.Fatal("IsConfigured() = false after resubmitting threshold shares post-Reset")
	}
}

func TestShamirSeal_Unseal_ClearsCollectedShares(t *testing.T) {
	_, shares, err := InitShamir(5, 3)
	if err != nil {
		t.Fatalf("InitShamir failed: %v", err)
	}

	s := NewShamirSeal(3)
	for i := 0; i < 3; i++ {
		if _, err := s.SubmitShare(shares[i]); err != nil {
			t.Fatalf("SubmitShare(%d) failed: %v", i, err)
		}
	}

	// Unseal 전에 내부에 쌓인 조각들의 백업 슬라이스를 그대로 참조해둔다 —
	// clearSharesLocked는 이 백업 배열의 내용 자체를 0으로 덮어쓰므로, Unseal이
	// 끝난 뒤에도 이 참조를 통해 실제로 지워졌는지 확인할 수 있다(단순히
	// s.shares가 nil이 됐는지만 보는 것보다 더 확실한 검증이다).
	collected := s.shares

	if _, err := s.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}

	if s.shares != nil {
		t.Fatalf("s.shares after Unseal = %v, want nil", s.shares)
	}
	for i, share := range collected {
		for _, b := range share {
			if b != 0 {
				t.Fatalf("share %d still has non-zero bytes after Unseal: %x", i, share)
			}
		}
	}
}

func TestShamirSeal_RootKeyIs32Bytes(t *testing.T) {
	rootKey, _, err := InitShamir(5, 3)
	if err != nil {
		t.Fatalf("InitShamir failed: %v", err)
	}
	if len(rootKey) != 32 {
		t.Fatalf("len(rootKey) = %d, want 32", len(rootKey))
	}
}

func TestShamirSeal_Type(t *testing.T) {
	s := NewShamirSeal(3)
	if s.Type() != "shamir" {
		t.Fatalf("Type() = %q, want %q", s.Type(), "shamir")
	}
}
