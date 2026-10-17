package keys

import (
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
)

// keysPrefix: KeyRing을 barrier에 저장할 때 쓰는 key 접두사.
const keysPrefix = "keys/"

var ErrBackend = errors.New("key backend unavailable")
var ErrAlreadyExists = errors.New("key already exists")

// ErrKeyNotActive: disabled 또는 pending_deletion 상태의 키로 암복호화/회전을 시도했을 때.
var ErrKeyNotActive = errors.New("key is not active")

// keyNameRE: 허용하는 키 이름 형식 (점 없는 전역 키).
var keyNameRE = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// dns1123LabelRE: 네임스페이스 소유 키의 <ns> 부분. 쿠버네티스 네임스페이스 이름 규칙(DNS-1123 label).
var dns1123LabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// ParseName은 키 이름을 소유 네임스페이스와 나머지로 나눈다 (C+B 키 소유 모델, ADR-009).
//   - "payment"           -> ns "",       base "payment"  (클러스터 전역 키)
//   - "team-a.payment"    -> ns "team-a", base "payment"  (team-a 소유 키)
//
// 점은 최대 1개, <ns>는 DNS-1123 label, base는 기존 키 이름 규칙(영문/숫자/_/-)이다.
// 전체 길이는 기존과 같은 64자 이하(점 포함)다. 형식이 틀리면 KeyPolicyError.
func ParseName(name string) (ns, base string, err error) {
	if len(name) > 64 {
		return "", "", &KeyPolicyError{Msg: "invalid key name: too long", Code: "invalid_key_name", Public: "invalid key name"}
	}
	if i := strings.IndexByte(name, '.'); i >= 0 {
		ns, base = name[:i], name[i+1:]
		if !dns1123LabelRE.MatchString(ns) || !keyNameRE.MatchString(base) {
			return "", "", &KeyPolicyError{Msg: "invalid key name: want <namespace>.<name> with a DNS-1123 namespace and at most one dot", Code: "invalid_key_name", Public: "invalid key name"}
		}
		return ns, base, nil
	}
	if !keyNameRE.MatchString(name) {
		return "", "", &KeyPolicyError{Msg: fmt.Sprintf("invalid key name %q: must match %s", name, keyNameRE.String()), Code: "invalid_key_name", Public: "invalid key name"}
	}
	return "", name, nil
}

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
	Msg string // 상세 설명 (키 이름·버전 숫자 포함 가능). 서버 로그/감사용 — API 응답에는 쓰지 않는다.
	// Code: 기계용 오류 코드 (비어 있으면 "invalid_request").
	Code string
	// Public: 응답에 그대로 보여도 안전한 설명 (키 이름·버전 숫자를 넣지 않는다). 비어 있으면 일반 문구를 쓴다.
	Public string
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
	barrier   *barrier.Barrier
	locks     sync.Map
	protected sync.Map
	clock     func() time.Time // 테스트에서 시각을 주입한다 (nil이면 time.Now)
}

// NewKeyManager는 주어진 Barrier로 KeyManager를 만든다.
func NewKeyManager(b *barrier.Barrier) *KeyManager {
	return &KeyManager{barrier: b}
}

// Protect는 키를 보호 키로 표시한다: 최소 복호화 버전을 올릴 수 없고, 비활성화·삭제 예약이 거부되며,
// 상태와 무관하게 항상 사용 가능하다. KMS v2 경로의 키(kmsv2.New가 자동 등록)와 KMS_PROTECTED_KEYS가 대상이다.
func (m *KeyManager) Protect(name string) { m.protected.Store(name, true) }

func (m *KeyManager) isProtected(name string) bool { _, ok := m.protected.Load(name); return ok }

// SetClock은 테스트용으로 현재 시각 공급자를 바꾼다.
func (m *KeyManager) SetClock(f func() time.Time) { m.clock = f }

func (m *KeyManager) now() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now()
}

// requireUsable: 사용(암복호화·회전)할 수 있는 상태인지. 보호 키는 상태와 무관하게 통과한다 —
// 보호 키는 애초에 비활성화될 수 없고, 혹시 저장소가 외부에서 바뀌었더라도 KMS v2 경로(클러스터 Secret
// 읽기/쓰기)가 막히는 일은 없어야 하기 때문이다.
func (m *KeyManager) requireUsable(name string, ring *KeyRing) error {
	if ring.state() == StateActive || m.isProtected(name) {
		return nil
	}
	return ErrKeyNotActive
}
func (m *KeyManager) lock(name string) func() {
	v, _ := m.locks.LoadOrStore(name, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// storageKey는 키 이름을 barrier에 저장할 실제 key 문자열로 바꾼다.
func storageKey(name string) string {
	return keysPrefix + name
}

// validateKeyName은 이름이 허용된 형식(영문/숫자/`_`/`-`, 1~64자)인지 검증한다.
func validateKeyName(name string) error {
	_, _, err := ParseName(name)
	return err
}

// loadRing은 barrier에서 KeyRing을 읽어온다. 존재하지 않으면 barrier.ErrNotFound를
// 도메인 에러인 KeyNotFoundError로 바꿔서 반환한다 — 이 계층 위쪽(transit, api 등)은
// barrier의 존재를 몰라도 되게, keys 패키지 고유의 에러 타입만 신경 쓰면 된다.
func (m *KeyManager) loadRing(name string) (*KeyRing, error) {
	if err := validateKeyName(name); err != nil {
		return nil, err
	}
	var ring KeyRing
	err := m.barrier.GetJSON(storageKey(name), &ring)
	if errors.Is(err, barrier.ErrNotFound) {
		return nil, &KeyNotFoundError{Name: name}
	}
	if err != nil {
		if errors.Is(err, barrier.ErrSealed) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrBackend, err)
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
		State:                ring.state(),
		DeletionDate:         ring.DeletionDate,
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
	defer m.lock(name)()
	if err := validateKeyName(name); err != nil {
		return KeyRingMeta{}, err
	}
	if autoRotatePeriodSec < 0 {
		return KeyRingMeta{}, &KeyPolicyError{Msg: "autoRotatePeriodSec must be >= 0", Code: "invalid_request", Public: "autoRotatePeriodSec must be >= 0"}
	}

	if _, err := m.loadRing(name); err == nil {
		return KeyRingMeta{}, fmt.Errorf("%w: %w", ErrAlreadyExists, &KeyPolicyError{Msg: fmt.Sprintf("key %q already exists", name)})
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
		State:                StateActive,
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
	defer m.lock(name)()
	ring, err := m.loadRing(name)
	if err != nil {
		return KeyRingMeta{}, err
	}
	if err := m.requireUsable(name, ring); err != nil {
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
	defer m.lock(name)()
	ring, err := m.loadRing(name)
	if err != nil {
		return KeyRingMeta{}, err
	}

	if ring.state() == StatePendingDeletion {
		return KeyRingMeta{}, ErrKeyNotActive
	}
	if _, protected := m.protected.Load(name); protected && minDecryptionVersion != nil && *minDecryptionVersion != 1 {
		return KeyRingMeta{}, &KeyPolicyError{Msg: "protected key versions must be retained", Code: "key_protected", Public: "protected key versions must be retained"}
	}
	if minDecryptionVersion != nil {
		v := *minDecryptionVersion
		if v < 1 || v > ring.LatestVersion {
			m := fmt.Sprintf("minDecryptionVersion %d out of range [1, %d]", v, ring.LatestVersion)
			return KeyRingMeta{}, &KeyPolicyError{Msg: m, Code: "invalid_request", Public: m} // 관리 평면 응답: 설정 범위는 보여도 된다
		}
		ring.MinDecryptionVersion = v
	}

	if autoRotatePeriodSec != nil {
		v := *autoRotatePeriodSec
		if v < 0 {
			return KeyRingMeta{}, &KeyPolicyError{Msg: "autoRotatePeriodSec must be >= 0", Code: "invalid_request", Public: "autoRotatePeriodSec must be >= 0"}
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
	if err := m.requireUsable(name, ring); err != nil {
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
	if err := m.requireUsable(name, ring); err != nil {
		return nil, err
	}

	if version < ring.MinDecryptionVersion {
		return nil, &KeyPolicyError{
			Msg:    fmt.Sprintf("version %d is below min_decryption_version %d for key %q", version, ring.MinDecryptionVersion, name),
			Code:   "version_not_allowed",
			Public: "the key version that protects this ciphertext is no longer allowed for decryption",
		}
	}

	for _, v := range ring.Versions {
		if v.Version == version {
			return v.KeyMaterial, nil
		}
	}
	return nil, &KeyPolicyError{Msg: fmt.Sprintf("version %d does not exist for key %q", version, name), Code: "version_not_found",
		Public: "the key version that protects this ciphertext does not exist"}
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
		if ring.AutoRotatePeriodSec <= 0 || ring.state() != StateActive {
			continue // 자동 회전은 active 키만
		}
		elapsedMs := nowMs - ring.LastRotatedAt.UnixMilli()
		if elapsedMs >= int64(ring.AutoRotatePeriodSec)*1000 {
			due = append(due, name)
		}
	}
	return due, nil
}
