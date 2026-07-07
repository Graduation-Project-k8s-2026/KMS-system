package transit

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeDecodeCiphertext_RoundTrip(t *testing.T) {
	envelope := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	encoded := EncodeCiphertext(3, envelope)

	version, decoded, err := DecodeCiphertext(encoded)
	if err != nil {
		t.Fatalf("DecodeCiphertext failed: %v", err)
	}
	if version != 3 {
		t.Fatalf("version = %d, want 3", version)
	}
	if !bytes.Equal(decoded, envelope) {
		t.Fatalf("decoded envelope = %v, want %v", decoded, envelope)
	}
}

func TestEncodeCiphertext_HasExpectedPrefix(t *testing.T) {
	encoded := EncodeCiphertext(1, []byte("data"))
	if !strings.HasPrefix(encoded, "kms:v1:") {
		t.Fatalf("EncodeCiphertext = %q, want prefix %q", encoded, "kms:v1:")
	}
}

func TestDecodeCiphertext_RejectsInvalidFormats(t *testing.T) {
	invalid := []string{
		"",
		"not-kms-format",
		"kms:v1",                   // 콜론 개수 부족 (파트 2개)
		"vault:v1:aGVsbG8=",        // 접두사 불일치
		"kms:1:aGVsbG8=",           // 버전에 "v" 접두사 없음
		"kms:v0:aGVsbG8=",          // 버전이 1 미만
		"kms:vabc:aGVsbG8=",        // 버전이 숫자가 아님
		"kms:v1:!!!not-base64!!!!", // base64 디코딩 실패
	}

	for _, s := range invalid {
		if _, _, err := DecodeCiphertext(s); err == nil {
			t.Errorf("DecodeCiphertext(%q) succeeded; want error", s)
		}
	}
}
