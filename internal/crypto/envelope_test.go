package crypto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Seal → Open 왕복 시 원문이 그대로 복원되는지 확인.
func TestSealOpen_RoundTrip(t *testing.T) {
	kek := testKey()
	plaintext := []byte("top secret data")
	aad := []byte("key-id:abc")

	envelope, err := Seal(kek, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	got, err := Open(kek, envelope, aad)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip mismatch: got %q, want %q", got, plaintext)
	}
}

// 같은 평문을 두 번 Seal해도 매번 새 DEK(+nonce)를 쓰므로 envelope가 달라야 한다.
func TestSeal_DEKIsRandomEachTime(t *testing.T) {
	kek := testKey()
	plaintext := []byte("same plaintext")
	aad := []byte("same-aad")

	env1, err := Seal(kek, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal (1st) failed: %v", err)
	}
	env2, err := Seal(kek, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal (2nd) failed: %v", err)
	}

	if bytes.Equal(env1, env2) {
		t.Fatal("two Seal calls on the same plaintext produced identical envelopes (DEK/nonce reuse?)")
	}
}

// aad가 Seal 때와 다르면 Open이 (DEK 언래핑 단계에서) 인증 실패로 거부되어야 한다.
func TestOpen_FailsOnAADMismatch(t *testing.T) {
	kek := testKey()
	plaintext := []byte("integrity matters")

	envelope, err := Seal(kek, plaintext, []byte("aad-A"))
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if _, err := Open(kek, envelope, []byte("aad-B")); err == nil {
		t.Fatal("Open succeeded despite mismatched AAD; expected failure")
	}
}

// Seal에 쓴 KEK와 다른 KEK로 Open하면 DEK 언래핑이 실패해야 한다.
func TestOpen_FailsWithDifferentKEK(t *testing.T) {
	kek := testKey()
	otherKEK := make([]byte, KeyLen)
	for i := range otherKEK {
		otherKEK[i] = byte(255 - i)
	}
	plaintext := []byte("wrap me")
	aad := []byte("aad")

	envelope, err := Seal(kek, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	if _, err := Open(otherKEK, envelope, aad); err == nil {
		t.Fatal("Open succeeded with the wrong KEK; expected failure")
	}
}

// 길이 헤더(앞 4바이트)를 조작하면 실제 데이터와 무관하게 즉시 에러가 나야 한다.
func TestOpen_FailsOnCorruptedLengthField(t *testing.T) {
	kek := testKey()
	envelope, err := Seal(kek, []byte("data"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	binary.BigEndian.PutUint32(envelope[:4], 9999)

	if _, err := Open(kek, envelope, []byte("aad")); err == nil {
		t.Fatal("Open succeeded despite a corrupted length field; expected failure")
	}
}

// envelope가 길이 헤더조차 담지 못할 만큼 짧으면 에러가 나야 한다.
func TestOpen_FailsOnTooShortEnvelope(t *testing.T) {
	kek := testKey()

	if _, err := Open(kek, []byte{1, 2, 3}, []byte("aad")); err == nil {
		t.Fatal("Open succeeded on a too-short envelope; expected failure")
	}
}
