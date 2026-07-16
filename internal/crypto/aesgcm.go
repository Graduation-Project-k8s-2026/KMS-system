// aesgcm.go — AES-256-GCM 원시 암복호화.
//
// 이 파일은 "키 하나로 데이터를 암호화/복호화"하는 가장 기본적인 연산만 담당한다.
// KEK/DEK 같은 봉투암호화 개념은 모르고, 그냥 "32바이트 키 + 평문 → 암호문",
// "32바이트 키 + 암호문 → 평문"만 할 줄 아는 가장 밑바닥 계층이다.
// envelope.go가 이 파일의 Encrypt/Decrypt를 두 번씩 갖다 써서 봉투암호화를 구현한다.

// Package crypto: AES-GCM 및 봉투 암호화(envelope encryption) 로직.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// AES-256-GCM에서 사용하는 파라미터.
const (
	KeyLen   = 32 // AES-256 키 길이 (바이트)
	NonceLen = 12 // GCM 표준 nonce(IV) 길이 (바이트)
	TagLen   = 16 // GCM 인증 태그 길이 (바이트)
)

// 예외 처리
var (
	// ErrInvalidKeyLen: 키 길이가 KeyLen(32바이트)이 아닐 때 반환.
	ErrInvalidKeyLen = errors.New("crypto: key must be 32 bytes (AES-256)")
	// ErrCiphertextTooShort: 복호화 대상이 nonce조차 담지 못할 만큼 짧을 때 반환.
	ErrCiphertextTooShort = errors.New("crypto: ciphertext too short to contain nonce")
)

// Encrypt 함수: key로 plaintext를 AES-256-GCM으로 암호화
// aad(additional authenticated data)는 암호화되지는 않지만 인증(무결성 검증) 대상에 포함된다 —
//
// 반환값은 매 호출마다 새로 생성한 nonce를 암호문 앞에 이어붙인 형태다: Decrypt 시 별도로 nonce를 전달/보관하지 않아도 된다.
//
//	nonce(12B) || ciphertext+tag
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, ErrInvalidKeyLen
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithTagSize(block, TagLen)
	if err != nil {
		return nil, err
	}

	// nonce는 반드시 매 암호화마다 새로 생성해야 한다 (재사용 시 GCM의 기밀성이 깨짐).
	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal(dst, nonce, plaintext, aad): dst 뒤에 암호문+태그를 이어붙여 반환한다.
	// dst로 nonce 슬라이스를 넘기면 결과가 자연스럽게 nonce||ciphertext+tag가 된다.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)
	return ciphertext, nil
}

// Decrypt는 Encrypt가 만든 nonce||ciphertext+tag 형태의 데이터를 key와 aad로 복호화한다.
// aad는 암호화 때 사용한 것과 정확히 일치해야 하며, 하나라도 다르면(키/암호문/aad 변조 포함)
// 인증 실패로 에러를 반환한다 — 평문 일부라도 반환하지 않는다.
func Decrypt(key, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, ErrInvalidKeyLen
	}
	if len(ciphertext) < NonceLen {
		return nil, ErrCiphertextTooShort
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithTagSize(block, TagLen)
	if err != nil {
		return nil, err
	}

	nonce, sealed := ciphertext[:NonceLen], ciphertext[NonceLen:]
	return gcm.Open(nil, nonce, sealed, aad)
}
