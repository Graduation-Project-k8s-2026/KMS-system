package shamir_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/shamir"
	vaultshamir "github.com/hashicorp/vault/shamir"
)

func testSecret() []byte {
	return []byte("this is a 32-byte root key!!!!!")
}

func TestSplitCombine_AnyThresholdSubsetRecoversSecret(t *testing.T) {
	secret := testSecret()

	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	subsets := [][][]byte{
		{shares[0], shares[1], shares[2]},
		{shares[1], shares[2], shares[3]},
		{shares[2], shares[3], shares[4]},
		{shares[0], shares[2], shares[4]},
	}

	for i, subset := range subsets {
		got, err := shamir.Combine(subset)
		if err != nil {
			t.Fatalf("Combine (subset %d) failed: %v", i, err)
		}
		if !bytes.Equal(got, secret) {
			t.Fatalf("Combine (subset %d) = %q, want %q", i, got, secret)
		}
	}
}

func TestCombine_BelowThreshold_DoesNotRecoverSecret(t *testing.T) {
	secret := testSecret()

	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// threshold(3) 미만인 2개만 넘긴다. Combine은 threshold를 모르므로 에러를
	// 내지 않을 수도 있다 — 대신 "에러 없이 원본과 같은 값이 나오는" 경우만
	// 확실히 없어야 한다 (Shamir의 안전성 정의 자체가 그렇다).
	got, err := shamir.Combine(shares[:2])
	if err == nil && bytes.Equal(got, secret) {
		t.Fatal("Combine with fewer than threshold shares recovered the original secret; expected failure or a different value")
	}
}

func TestSplit_ProducesDifferentSharesEachTime(t *testing.T) {
	secret := testSecret()

	shares1, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split (1st) failed: %v", err)
	}
	shares2, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("Split (2nd) failed: %v", err)
	}

	if bytes.Equal(shares1[0], shares2[0]) {
		t.Fatal("two Split calls on the same secret produced identical shares (random coefficient reuse?)")
	}
}

func TestSplit_RejectsInvalidParameters(t *testing.T) {
	secret := testSecret()

	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
		wantErr   error
	}{
		{"empty secret", nil, 5, 3, shamir.ErrEmptySecret},
		{"parts too few", secret, 1, 1, shamir.ErrInvalidParts},
		{"parts too many", secret, 256, 3, shamir.ErrInvalidParts},
		{"threshold too small", secret, 5, 1, shamir.ErrInvalidThreshold},
		{"threshold exceeds parts", secret, 5, 6, shamir.ErrInvalidThreshold},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := shamir.Split(tt.secret, tt.parts, tt.threshold)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Split(...) err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestCombine_RejectsMismatchedShareLengths(t *testing.T) {
	shares := [][]byte{
		{1, 2, 3, 0x01},
		{1, 2, 0x02}, // 길이가 다름
	}

	if _, err := shamir.Combine(shares); !errors.Is(err, shamir.ErrShareLengthMismatch) {
		t.Fatalf("Combine err = %v, want ErrShareLengthMismatch", err)
	}
}

func TestCombine_RejectsDuplicateXCoordinate(t *testing.T) {
	shares := [][]byte{
		{1, 2, 3, 0x01},
		{4, 5, 6, 0x01}, // x좌표(마지막 바이트)가 첫 번째 조각과 동일
	}

	if _, err := shamir.Combine(shares); !errors.Is(err, shamir.ErrDuplicateShareX) {
		t.Fatalf("Combine err = %v, want ErrDuplicateShareX", err)
	}
}

// ---- 교차검증 ----
//
// Shamir는 다항식 계수를 매번 무작위로 새로 생성하므로, "우리 구현과 vault
// 구현이 같은 조각을 만드는지"는 애초에 비교할 수 없는 질문이다(같은 비밀을
// 넣어도 매번 다른 조각이 나오는 게 정상이다). 대신 "상호운용되는지"로
// 정확성을 검증한다: 한쪽이 만든 조각을 다른 쪽이 정확히 복원해낼 수 있다면,
// 두 구현이 같은 유한체(GF(256), 기약다항식 0x1B)와 같은 조각 포맷
// ({y1..yN, x})을 쓰고 있다는 증거가 된다 — 우리가 문서만 보고 베낀 게
// 아니라 실제로 맞게 구현했다는 걸 라이브러리 자체가 검증해주는 셈이다.
//
// vault 패키지는 이 테스트 파일에서만 쓰인다(go.mod에는 남지만 실제 서버
// 바이너리에는 포함되지 않는다) — cmd/server나 internal/seal 등 어디에서도
// import하지 않기 때문이다.

func TestCrossValidation_OurSplit_VaultCombine(t *testing.T) {
	secret := testSecret()

	shares, err := shamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("our Split failed: %v", err)
	}

	got, err := vaultshamir.Combine(shares[:3])
	if err != nil {
		t.Fatalf("vault Combine(our shares) failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("vault Combine(our shares) = %q, want %q", got, secret)
	}
}

func TestCrossValidation_VaultSplit_OurCombine(t *testing.T) {
	secret := testSecret()

	shares, err := vaultshamir.Split(secret, 5, 3)
	if err != nil {
		t.Fatalf("vault Split failed: %v", err)
	}

	got, err := shamir.Combine(shares[:3])
	if err != nil {
		t.Fatalf("our Combine(vault shares) failed: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("our Combine(vault shares) = %q, want %q", got, secret)
	}
}
