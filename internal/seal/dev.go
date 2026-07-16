package seal

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
)

// KMS_MASTER_KEY: DevSeal이 패스프레이즈를 읽어오는 환경변수 이름.
const envMasterKey = "KMS_MASTER_KEY"

// ErrPassphraseNotConfigured: 패스프레이즈가 없는 상태에서 Unseal을 호출했을 때 반환.
var ErrPassphraseNotConfigured = errors.New("seal: passphrase not configured (set " + envMasterKey + " or pass it to NewDevSeal)")

// DevSeal은 개발/학습 전용 Seal 구현체다.
//
// ⚠️ 실무(운영 환경)에서는 절대 쓰면 안 된다. 이유:
//   - 패스프레이즈 → 키 변환에 SHA-256을 한 번만 적용한다. 이건 진짜 키 유도
//     함수(KDF)가 아니다 — Argon2/PBKDF2/scrypt처럼 반복 연산으로 무차별 대입을
//     느리게 만드는 장치가 전혀 없어서, 패스프레이즈가 유출되면 즉시 뚫린다.
//   - 패스프레이즈를 평문 환경변수(KMS_MASTER_KEY)로 주고받는다. 환경변수는
//     프로세스 목록, 크래시 덤프, 로그 등으로 새기 쉽다.
//   - "봉인 해제"에 필요한 게 비밀 하나뿐이다. Shamir 방식처럼 여러 조각을
//     여러 사람이 나눠 갖고 그중 일부만 모여야 열리는 구조(운영자 한 명이
//     Root Key를 통째로 손에 넣지 못하게 하는 안전장치)가 없다.
//
// 즉 DevSeal은 "매번 Shamir/K8s Secret을 설정하지 않고도 로컬에서 KMS를
// 켜고 끌 수 있게 해주는" 개발 편의용 구현일 뿐, 보안 설계가 전혀 없다.
type DevSeal struct {
	passphrase string
}

// NewDevSeal은 DevSeal을 만든다.
//
// passphrase를 직접 넘기면 그 값을 쓴다 (테스트에서 환경변수를 건드리지 않고
// 원하는 패스프레이즈를 주입할 수 있도록). 빈 문자열을 넘기면 환경변수
// KMS_MASTER_KEY 값을 대신 읽는다.
func NewDevSeal(passphrase string) *DevSeal {
	if passphrase == "" {
		passphrase = os.Getenv(envMasterKey)
	}
	return &DevSeal{passphrase: passphrase}
}

// Type은 이 seal 구현의 이름 "dev"를 반환한다.
func (s *DevSeal) Type() string {
	return "dev"
}

// IsConfigured는 패스프레이즈가 비어있지 않으면 true를 반환한다.
func (s *DevSeal) IsConfigured() bool {
	return s.passphrase != ""
}

// Unseal은 패스프레이즈를 SHA-256으로 해싱해 32바이트 Root Key를 도출한다.
// 같은 패스프레이즈는 항상 같은 Root Key를 만든다(결정적) — 그래야 서버를
// 재시작해도 이전에 암호화한 데이터를 계속 복호화할 수 있다.
func (s *DevSeal) Unseal() ([]byte, error) {
	if !s.IsConfigured() {
		return nil, ErrPassphraseNotConfigured
	}

	sum := sha256.Sum256([]byte(s.passphrase))
	rootKey := sum[:]

	// SHA-256 출력은 항상 32바이트이므로 이 검사는 사실상 항상 통과한다.
	// 그래도 "Root Key 길이는 crypto.KeyLen과 반드시 일치해야 한다"는 불변조건을
	// 코드로 명시해, 나중에 두 상수 중 하나가 바뀌어도 조용히 깨지지 않게 한다.
	if len(rootKey) != kmscrypto.KeyLen {
		return nil, fmt.Errorf("seal: derived root key length %d does not match crypto.KeyLen %d", len(rootKey), kmscrypto.KeyLen)
	}

	return rootKey, nil
}
