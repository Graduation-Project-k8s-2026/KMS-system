package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
)

// keysPrefix: KeyRing을 barrier에 저장할 때 쓰는 key 접두사.
const keysPrefix = "keys/"

// keyNameRE: 허용하는 키 이름 형식.
var keyNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// KeyNotFoundError: 존재하지 않는 키를 조회/조작하려 했을 때 반환한다.
type KeyNotFoundError struct {
	Name string
}

func (e *KeyNotFoundError) Error() string {
	return fmt.Sprintf("keys: key %q not found", e.Name)
}

// Is는 errors.Is(err, &KeyNotFoundError{})가 필드 값과 무관하게 "타입이
// KeyNotFoundError인가"만으로 판별되게 해준다.
func (e *KeyNotFoundError) Is(target error) bool {
	_, ok := target.(*KeyNotFoundError)
	return ok
}

// KeyPolicyError: 이름 형식 위반, 중복 생성, min_decryption_version 위반,
// 설정값 범위 위반 등 "요청이 정책에 맞지 않는" 모든 경우에 반환한다.
type KeyPolicyError struct {
	Msg string
}

func (e *KeyPolicyError) Error() string {
	return "keys: " + e.Msg
}

// Is는 errors.Is(err, &KeyPolicyError{})가 메시지 내용과 무관하게 "타입이
// KeyPolicyError인가"만으로 판별되게 해준다.
func (e *KeyPolicyError) Is(target error) bool {
	_, ok := target.(*KeyPolicyError)
	return ok
}

// KeyManager는 KMS의 핵심 도메인 로직 — 키(KeyRing)의 생성/조회/회전/버전 정책을
// 담당한다. 모든 데이터는 barrier.Barrier를 통해서만 오가므로, KEK material은
// Root Key로 암호화된 채로만 storage에 존재한다.
type KeyManager struct {
	barrier *barrier.Barrier
}

// NewKeyManager는 주어진 Barrier로 KeyManager를 만든다.
func NewKeyManager(b *barrier.Barrier) *KeyManager {
	return &KeyManager{barrier: b}
}

// storageKey는 키 이름을 barrier에 저장할 실제 key 문자열로 바꾼다.
func storageKey(name string) string {
	return keysPrefix + name
}

// validateKeyName은 이름이 허용된 형식(영문/숫자/`_`/`-`, 1~64자)인지 검증한다.
func validateKeyName(name string) error {
	if !keyNameRE.MatchString(name) {
		return &KeyPolicyError{Msg: fmt.Sprintf("invalid key name %q: must match %s", name, keyNameRE.String())}
	}
	return nil
}

// loadRing은 barrier에서 KeyRing을 읽어온다. 존재하지 않으면 barrier.ErrNotFound를
// 도메인 에러인 KeyNotFoundError로 바꿔서 반환한다 — 이 계층 위쪽(transit, api 등)은
// barrier의 존재를 몰라도 되게, keys 패키지 고유의 에러 타입만 신경 쓰면 된다.
func (m *KeyManager) loadRing(name string) (*KeyRing, error) {
	var ring KeyRing
	err := m.barrier.GetJSON(storageKey(name), &ring)
	if errors.Is(err, barrier.ErrNotFound) {
		return nil, &KeyNotFoundError{Name: name}
	}
	if err != nil {
		return nil, err
	}
	return &ring, nil
}

// toMeta는 내부 표현(KeyRing, material 포함)을 외부 노출용(KeyRingMeta, material
// 제외)으로 변환한다.
func toMeta(ring *KeyRing) KeyRingMeta {
	versions := make([]KeyVersionMeta, len(ring.Versions))
	for i, v := range ring.Versions {
		versions[i] = KeyVersionMeta{Version: v.Version, CreatedAt: v.CreatedAt}
	}
	return KeyRingMeta{
		Name:                 ring.Name,
		Type:                 ring.Type,
		CreatedAt:            ring.CreatedAt,
		LatestVersion:        ring.LatestVersion,
		MinDecryptionVersion: ring.MinDecryptionVersion,
		AutoRotatePeriodSec:  ring.AutoRotatePeriodSec,
		LastRotatedAt:        ring.LastRotatedAt,
		Versions:             versions,
	}
}

// newVersion은 crypto/rand로 새 32바이트 KEK를 생성해 KeyVersion으로 감싼다.
func newVersion(version int, now time.Time) (KeyVersion, error) {
	material := make([]byte, kmscrypto.KeyLen)
	if _, err := rand.Read(material); err != nil {
		return KeyVersion{}, err
	}
	return KeyVersion{Version: version, KeyMaterial: material, CreatedAt: now}, nil
}

// CreateKey는 새 KeyRing을 버전 1 하나로 만든다. 이미 같은 이름이 있으면
// KeyPolicyError를 반환한다.
func (m *KeyManager) CreateKey(name string, autoRotatePeriodSec int) (KeyRingMeta, error) {
	if err := validateKeyName(name); err != nil {
		return KeyRingMeta{}, err
	}
	if autoRotatePeriodSec < 0 {
		return KeyRingMeta{}, &KeyPolicyError{Msg: "autoRotatePeriodSec must be >= 0"}
	}

	if _, err := m.loadRing(name); err == nil {
		return KeyRingMeta{}, &KeyPolicyError{Msg: fmt.Sprintf("key %q already exists", name)}
	} else if !errors.Is(err, &KeyNotFoundError{}) {
		return KeyRingMeta{}, err
	}

	now := time.Now()
	v1, err := newVersion(1, now)
	if err != nil {
		return KeyRingMeta{}, err
	}

	ring := &KeyRing{
		Name:                 name,
		Type:                 "aes256-gcm",
		CreatedAt:            now,
		LatestVersion:        1,
		MinDecryptionVersion: 1,
		AutoRotatePeriodSec:  autoRotatePeriodSec,
		LastRotatedAt:        now,
		Versions:             []KeyVersion{v1},
	}

	if err := m.barrier.PutJSON(storageKey(name), ring); err != nil {
		return KeyRingMeta{}, err
	}
	return toMeta(ring), nil
}

// GetKeyMeta는 키의 외부 노출용 메타데이터를 반환한다.
func (m *KeyManager) GetKeyMeta(name string) (KeyRingMeta, error) {
	ring, err := m.loadRing(name)
	if err != nil {
		return KeyRingMeta{}, err
	}
	return toMeta(ring), nil
}

// ListKeys는 저장된 모든 키 이름을 반환한다.
func (m *KeyManager) ListKeys() ([]string, error) {
	return m.barrier.List(keysPrefix)
}

// RotateKey는 새 버전을 추가하고 LatestVersion을 올린다. 기존 버전은 그대로
// 남아있다 — min_decryption_version이 그 이상으로 올라가기 전까지는 여전히
// 복호화에 쓸 수 있어야 하기 때문이다.
func (m *KeyManager) RotateKey(name string) (KeyRingMeta, error) {
	ring, err := m.loadRing(name)
	if err != nil {
		return KeyRingMeta{}, err
	}

	now := time.Now()
	newVer, err := newVersion(ring.LatestVersion+1, now)
	if err != nil {
		return KeyRingMeta{}, err
	}

	ring.Versions = append(ring.Versions, newVer)
	ring.LatestVersion = newVer.Version
	ring.LastRotatedAt = now

	if err := m.barrier.PutJSON(storageKey(name), ring); err != nil {
		return KeyRingMeta{}, err
	}
	return toMeta(ring), nil
}

// UpdateConfig는 minDecryptionVersion/autoRotatePeriodSec을 부분적으로 갱신한다.
// 각 값은 포인터로 받아 nil이면 "변경 안 함"으로 처리한다.
func (m *KeyManager) UpdateConfig(name string, minDecryptionVersion *int, autoRotatePeriodSec *int) (KeyRingMeta, error) {
	ring, err := m.loadRing(name)
	if err != nil {
		return KeyRingMeta{}, err
	}

	if minDecryptionVersion != nil {
		v := *minDecryptionVersion
		if v < 1 || v > ring.LatestVersion {
			return KeyRingMeta{}, &KeyPolicyError{
				Msg: fmt.Sprintf("minDecryptionVersion %d out of range [1, %d]", v, ring.LatestVersion),
			}
		}
		ring.MinDecryptionVersion = v
	}

	if autoRotatePeriodSec != nil {
		v := *autoRotatePeriodSec
		if v < 0 {
			return KeyRingMeta{}, &KeyPolicyError{Msg: "autoRotatePeriodSec must be >= 0"}
		}
		ring.AutoRotatePeriodSec = v
	}

	if err := m.barrier.PutJSON(storageKey(name), ring); err != nil {
		return KeyRingMeta{}, err
	}
	return toMeta(ring), nil
}

// GetEncryptionKEK는 암호화에 쓸 최신 버전의 KEK를 반환한다. transit 층이
// "새로 암호화할 때는 항상 최신 키를 쓴다"는 정책을 구현하는 데 쓴다.
func (m *KeyManager) GetEncryptionKEK(name string) (version int, kek []byte, err error) {
	ring, err := m.loadRing(name)
	if err != nil {
		return 0, nil, err
	}

	for _, v := range ring.Versions {
		if v.Version == ring.LatestVersion {
			return v.Version, v.KeyMaterial, nil
		}
	}
	// LatestVersion에 해당하는 버전이 Versions에 없는 상태는 데이터 불일치를
	// 뜻한다 — 정상적으로는 절대 발생하지 않아야 한다.
	return 0, nil, fmt.Errorf("keys: key %q is missing its latest version %d", name, ring.LatestVersion)
}

// GetDecryptionKEK는 특정 버전의 KEK를 반환한다. 이 메서드가 바로
// min_decryption_version 정책이 실제로 강제되는 지점이다 — 지정한 version이
// MinDecryptionVersion보다 낮으면 그 버전의 material이 실제로 존재하든 말든
// KeyPolicyError로 거부한다.
func (m *KeyManager) GetDecryptionKEK(name string, version int) ([]byte, error) {
	ring, err := m.loadRing(name)
	if err != nil {
		return nil, err
	}

	if version < ring.MinDecryptionVersion {
		return nil, &KeyPolicyError{
			Msg: fmt.Sprintf("version %d is below min_decryption_version %d for key %q", version, ring.MinDecryptionVersion, name),
		}
	}

	for _, v := range ring.Versions {
		if v.Version == version {
			return v.KeyMaterial, nil
		}
	}
	return nil, &KeyPolicyError{Msg: fmt.Sprintf("version %d does not exist for key %q", version, name)}
}

// FindKeysDueForRotation은 자동 회전이 설정되어 있고(AutoRotatePeriodSec > 0),
// 마지막 회전으로부터 그 주기 이상 지난 키 이름들을 반환한다. nowMs를 인자로
// 받는 이유는 스케줄러가 실제 시각을 넘기게 하면서도, 테스트에서는 임의의
// 시각을 주입해 "회전이 필요한 시점"을 결정적으로 검증할 수 있게 하기 위함이다.
func (m *KeyManager) FindKeysDueForRotation(nowMs int64) ([]string, error) {
	names, err := m.ListKeys()
	if err != nil {
		return nil, err
	}

	var due []string
	for _, name := range names {
		ring, err := m.loadRing(name)
		if err != nil {
			return nil, err
		}
		if ring.AutoRotatePeriodSec <= 0 {
			continue
		}
		elapsedMs := nowMs - ring.LastRotatedAt.UnixMilli()
		if elapsedMs >= int64(ring.AutoRotatePeriodSec)*1000 {
			due = append(due, name)
		}
	}
	return due, nil
}
