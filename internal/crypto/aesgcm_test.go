package crypto

import (
	"bytes"
	"testing"
)

// 테스트용 32바이트 더미 키. 실제로는 무작위 생성/키 관리 계층에서 나온다.
func testKey() []byte {
	key := make([]byte, KeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	return key
}

// 암호화 → 복호화 왕복 시 원문이 그대로 복원되는지 확인.
func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := testKey()
	plaintext := []byte("hello, KMS")
	aad := []byte("key-version:1")

	ciphertext, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	got, err := Decrypt(key, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

// 같은 평문을 두 번 암호화해도 매번 새 nonce를 쓰므로 암호문이 달라야 한다.
// (nonce가 같은 채로 재사용되면 GCM의 기밀성이 깨지는 심각한 취약점이 된다.)
func TestEncrypt_NonceIsRandomEachTime(t *testing.T) {
	key := testKey()
	plaintext := []byte("same plaintext")
	aad := []byte("same-aad")

	ct1, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt (1st) failed: %v", err)
	}
	ct2, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt (2nd) failed: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertext (nonce reuse?)")
	}
	// 앞 NonceLen 바이트(=nonce)도 서로 달라야 한다.
	if bytes.Equal(ct1[:NonceLen], ct2[:NonceLen]) {
		t.Fatal("nonces were identical across two Encrypt calls")
	}
}

// aad가 암호화 때와 다르면 복호화가 인증 실패로 거부되어야 한다.
func TestDecrypt_FailsOnAADMismatch(t *testing.T) {
	key := testKey()
	plaintext := []byte("integrity matters")

	ciphertext, err := Encrypt(key, plaintext, []byte("aad-A"))
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if _, err := Decrypt(key, ciphertext, []byte("aad-B")); err == nil {
		t.Fatal("Decrypt succeeded despite mismatched AAD; expected authentication failure")
	}
}

// 키 길이가 32바이트가 아니면 Encrypt/Decrypt 둘 다 에러를 반환해야 한다.
func TestInvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16) // AES-128 길이 — 이 패키지는 AES-256(32바이트)만 허용
	plaintext := []byte("data")
	aad := []byte("aad")

	if _, err := Encrypt(shortKey, plaintext, aad); err != ErrInvalidKeyLen {
		t.Fatalf("Encrypt: got err=%v, want ErrInvalidKeyLen", err)
	}

	// Decrypt도 동일하게 검증하는지 확인 (임의의 바이트열로 충분 — 키 검증이 먼저 실행돼야 함).
	fakeCiphertext := make([]byte, NonceLen+TagLen)
	if _, err := Decrypt(shortKey, fakeCiphertext, aad); err != ErrInvalidKeyLen {
		t.Fatalf("Decrypt: got err=%v, want ErrInvalidKeyLen", err)
	}
}
