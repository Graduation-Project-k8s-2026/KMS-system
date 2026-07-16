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

// zeroBytes는 슬라이스의 모든 바이트를 0으로 덮어써서, 더 이상 필요 없는 KEK가
// 메모리에 평문으로 남는 시간을 최소화한다.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
