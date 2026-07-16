package transit

import (
	"fmt"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
)

// TransitService는 keys.KeyManager(KEK 공급)와 crypto.Seal/Open(봉투 암호화)를
// 엮어, "데이터를 저장하지 않고 암복호화 연산만 제공"하는 transit형 KMS의 핵심
// 표면을 구현한다.
type TransitService struct {
	keys *keys.KeyManager
}

// NewTransitService는 주어진 KeyManager로 TransitService를 만든다.
func NewTransitService(km *keys.KeyManager) *TransitService {
	return &TransitService{keys: km}
}

// aad는 keyName과 version을 하나로 묶어 crypto.Seal/Open의 추가 인증 데이터로
// 쓴다. 이렇게 묶으면 "이 암호문은 정확히 이 키의 이 버전으로만 열려야 한다"는
// 사실이 암호문 자체에 새겨진다 — 예를 들어 키 "A"의 v1으로 만든 envelope를
// 키 "B"에, 또는 같은 키의 다른 버전에 억지로 끼워 넣어 복호화하려는 시도는
// (KEK가 다르거나 KEK가 우연히 같더라도) aad가 "A:v1"과 일치하지 않아 인증
// 실패로 거부된다.
func aad(name string, version int) []byte {
	return []byte(fmt.Sprintf("%s:v%d", name, version))
}

// Encrypt는 name 키의 최신 버전 KEK로 plaintext를 봉투 암호화해, 사용자에게
// 노출할 문자열 포맷("kms:v{n}:...")으로 인코딩해 반환한다.
func (s *TransitService) Encrypt(name string, plaintext []byte) (string, error) {
	version, kek, err := s.keys.GetEncryptionKEK(name)
	if err != nil {
		return "", err
	}
	defer zeroBytes(kek)

	envelope, err := kmscrypto.Seal(kek, plaintext, aad(name, version))
	if err != nil {
		return "", err
	}

	return EncodeCiphertext(version, envelope), nil
}

// Decrypt는 ciphertext에서 버전을 읽어 그 버전의 KEK를 확보하고, 봉투를 열어
// 원문을 복원한다. keys.GetDecryptionKEK가 min_decryption_version 정책을
// 강제하므로, 그 아래 버전은 여기까지 오기 전에 거부된다.
func (s *TransitService) Decrypt(name string, ciphertext string) ([]byte, error) {
	version, envelope, err := DecodeCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}

	kek, err := s.keys.GetDecryptionKEK(name, version)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(kek)

	return kmscrypto.Open(kek, envelope, aad(name, version))
}

// Rewrap은 평문을 밖으로 노출하지 않고, ciphertext를 최신 버전 KEK로 다시
// 암호화한다. 키 회전 후 옛 버전으로 암호화된 데이터를 최신 버전으로 "갈아입힐"
// 때 쓴다 — 호출자는 새 암호문("kms:v{최신}:...")만 받을 뿐, 그 사이 평문이
// 어디에도 반환되지 않는다.
//
// 구현은 기존 Decrypt로 원문을 복원한 뒤 곧바로 Encrypt로 다시 감싸는 형태다.
// 복원한 평문은 이 함수 밖으로 절대 반환하지 않고, 재암호화에 쓴 즉시 defer로
// 메모리에서 0으로 덮어 지운다.
//
// min_decryption_version 아래로 이미 떨어진 버전의 암호문은 내부 Decrypt
// 단계에서부터 거부되므로 rewrap도 함께 불가능해진다 — 즉 "min_version을
// 올리기 전에 옛 버전들의 rewrap을 끝내야 한다"는 순서가 이 구현만으로
// 자연히 강제된다 (별도 검증 로직이 필요 없다).
func (s *TransitService) Rewrap(name string, ciphertext string) (string, error) {
	plaintext, err := s.Decrypt(name, ciphertext)
	if err != nil {
		return "", err
	}
	defer zeroBytes(plaintext)

	return s.Encrypt(name, plaintext)
}

// zeroBytes는 슬라이스의 모든 바이트를 0으로 덮어써서, 더 이상 필요 없는 KEK가
// 메모리에 평문으로 남는 시간을 최소화한다.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
