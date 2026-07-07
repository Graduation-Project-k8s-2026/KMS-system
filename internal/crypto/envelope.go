package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// wrappedDEKLen: Encrypt(kek, dek, aad)가 만드는 결과의 길이.
// dek는 항상 KeyLen(32)바이트이므로 nonce(12) + 암호문(32) + 태그(16) = 60바이트로 고정된다.
const wrappedDEKLen = NonceLen + KeyLen + TagLen

var (
	// ErrEnvelopeTooShort: envelope가 길이 헤더(4바이트)조차 담지 못하거나,
	// 헤더가 말하는 만큼의 래핑된 DEK를 담지 못할 때 반환.
	ErrEnvelopeTooShort = errors.New("crypto: envelope too short")
	// ErrInvalidWrappedDEKLen: 길이 헤더 값이 래핑된 DEK의 고정 길이(60바이트)와 다를 때 반환.
	// Seal이 만드는 envelope는 항상 이 값을 가지므로, 다르면 조작/손상으로 간주한다.
	ErrInvalidWrappedDEKLen = errors.New("crypto: invalid wrapped DEK length field")
)

// Seal은 봉투 암호화(envelope encryption)로 plaintext를 암호화한다.
//
//  1. DEK(Data Encryption Key)를 요청마다 새로 무작위 생성한다.
//  2. plaintext를 DEK로 암호화한다 (aad 없음 — 데이터 자체와는 무관).
//  3. DEK를 KEK(Key Encryption Key)로 한 번 더 암호화("래핑")한다. 여기에 aad를 붙여서,
//     예컨대 "이 DEK가 어떤 키 버전에 속하는지" 같은 메타데이터가 위조되지 않았음을 보장한다.
//  4. [래핑된 DEK 길이(4바이트, big-endian)][래핑된 DEK][암호화된 데이터] 형태로 이어붙여 반환한다.
//
// DEK는 사용이 끝나면 메모리에서 0으로 덮어 지운다 — 평문 데이터를 풀 수 있는 키를
// 필요 이상으로 메모리에 남겨두지 않기 위함이다.
func Seal(kek, plaintext, aad []byte) ([]byte, error) {
	dek := make([]byte, KeyLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	defer zeroBytes(dek)

	encryptedData, err := Encrypt(dek, plaintext, nil)
	if err != nil {
		return nil, err
	}

	wrappedDEK, err := Encrypt(kek, dek, aad)
	if err != nil {
		return nil, err
	}

	envelope := make([]byte, 4, 4+len(wrappedDEK)+len(encryptedData))
	binary.BigEndian.PutUint32(envelope, uint32(len(wrappedDEK)))
	envelope = append(envelope, wrappedDEK...)
	envelope = append(envelope, encryptedData...)
	return envelope, nil
}

// Open은 Seal이 만든 envelope를 복호화해 plaintext를 복원한다.
//
//  1. 앞 4바이트에서 래핑된 DEK의 길이를 읽는다.
//  2. 그 길이가 고정값(60바이트)과 다르면 즉시 에러를 반환한다 (손상/조작 감지).
//  3. 래핑된 DEK를 KEK와 aad로 언래핑한다 — aad는 Seal 때와 정확히 일치해야 한다.
//  4. 복원한 DEK로 나머지 데이터를 복호화해 plaintext를 얻는다.
//
// DEK는 Seal과 마찬가지로 사용 후 메모리에서 지운다.
func Open(kek, envelope, aad []byte) ([]byte, error) {
	if len(envelope) < 4 {
		return nil, ErrEnvelopeTooShort
	}

	wrappedLen := binary.BigEndian.Uint32(envelope[:4])
	if wrappedLen != wrappedDEKLen {
		return nil, ErrInvalidWrappedDEKLen
	}
	if len(envelope) < 4+int(wrappedLen) {
		return nil, ErrEnvelopeTooShort
	}

	wrappedDEK := envelope[4 : 4+wrappedLen]
	encryptedData := envelope[4+wrappedLen:]

	dek, err := Decrypt(kek, wrappedDEK, aad)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)

	return Decrypt(dek, encryptedData, nil)
}

// zeroBytes는 슬라이스의 모든 바이트를 0으로 덮어써서, 더 이상 필요 없는 키 material이
// 메모리에 평문 형태로 남아있는 시간을 최소화한다.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
