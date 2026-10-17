package barrier

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"time"
)

var ErrInitialized = errors.New("barrier: already initialized or legacy data exists; refusing init")
var ErrRootVerification = errors.New("barrier: initialization record or root verification invalid")

const initPath = "initialization.json"

// 봉인 방식 값. 이 init 기록의 seal 값이 "지금 이 저장소의 루트 키를 어떻게
// 보호하는가"에 대한 유일한 진실의 원천이다(환경변수가 아니다 — ADR-010).
const (
	SealShamir = "shamir"
	SealTPM    = "tpm"
)

// 기록 형식 버전.
//   - v1: seal 필드 없음. 항상 shamir로 해석한다(운영 저장소가 v1).
//   - v2: seal 필드 있음("shamir"|"tpm"). aad에 seal이 포함되어 디스크에서 값을
//     바꿔치기하면 검증 암호문 복호화가 실패한다.
const (
	initFormatV1 = 1
	initFormatV2 = 2
)

const verificationPlain = "kms-root-valid-v1"

type Initialization struct {
	FormatVersion int    `json:"format_version"`
	StoreID       string `json:"store_id"`
	Parts         int    `json:"parts"`
	Threshold     int    `json:"threshold"`
	Seal          string `json:"seal,omitempty"`
	Verification  []byte `json:"verification"`
}

// aad: v1은 기존 문자열을 한 글자도 바꾸지 않는다(이미 만들어진 검증 암호문이
// 계속 풀려야 하므로). v2부터 seal을 덧붙인다.
func (m Initialization) aad() []byte {
	if m.FormatVersion == initFormatV1 {
		return []byte(fmt.Sprintf("kms-init:%d:%s:%d:%d", m.FormatVersion, m.StoreID, m.Parts, m.Threshold))
	}
	return []byte(fmt.Sprintf("kms-init:%d:%s:%d:%d:%s", m.FormatVersion, m.StoreID, m.Parts, m.Threshold, m.Seal))
}

// SealMode: 이 기록이 가리키는 봉인 방식. v1은 필드가 없으므로 shamir.
func (m Initialization) SealMode() string {
	if m.FormatVersion == initFormatV1 {
		return SealShamir
	}
	return m.Seal
}

// wellFormed: 구조 검증. v1은 seal 필드가 비어 있어야 하고, v2는 알려진 값이어야
// 한다. 알 수 없는 형식은 "읽을 수 있는 만큼만 믿기"가 아니라 거부한다(fail-closed).
func (m Initialization) wellFormed() bool {
	if len(m.StoreID) != 32 || m.Threshold < 2 || m.Parts < m.Threshold {
		return false
	}
	switch m.FormatVersion {
	case initFormatV1:
		return m.Seal == ""
	case initFormatV2:
		return m.Seal == SealShamir || m.Seal == SealTPM
	}
	return false
}

// newVerification: 메모리의 루트 키로 검증 암호문을 (다시) 만든다.
func (m *Initialization) newVerification(root []byte) error {
	v, err := kmscrypto.Encrypt(root, []byte(verificationPlain), m.aad())
	if err != nil {
		return err
	}
	m.Verification = v
	return nil
}

// verify: 이 루트 키가 기록의 검증 암호문을 푸는지 확인한다.
func (m Initialization) verify(root []byte) error {
	plain, err := kmscrypto.Decrypt(root, m.Verification, m.aad())
	if err != nil || string(plain) != verificationPlain {
		return ErrRootVerification
	}
	return nil
}

// loadInit: 기록을 읽어 구조까지 검증한다. 기록이 없으면 (nil, nil).
func (b *Barrier) loadInit() (*Initialization, error) {
	raw, err := b.store.Get(initPath)
	if err != nil || raw == nil {
		return nil, err
	}
	var m Initialization
	if json.Unmarshal(raw, &m) != nil || !m.wellFormed() {
		return nil, ErrRootVerification
	}
	return &m, nil
}

// putInit: 기록을 storage의 원자적 Put으로 저장한다(임시 파일 → rename).
func (b *Barrier) putInit(m *Initialization) error {
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return b.store.Put(initPath, raw)
}

// SealMode는 init 기록의 봉인 방식을 반환한다. 기록이 없으면 "" (미초기화).
// 부팅 시 어떤 Seal로 시작할지 정하는 데 쓴다.
func (b *Barrier) SealMode() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	m, err := b.loadInit()
	if err != nil || m == nil {
		return "", err
	}
	return m.SealMode(), nil
}
func (b *Barrier) Initialize(parts, threshold int) ([][]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw, err := b.store.Get(initPath)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		return nil, ErrInitialized
	}
	names, err := b.store.List("keys/")
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		return nil, ErrInitialized
	}
	root, shares, err := seal.InitShamir(parts, threshold)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(root)
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return nil, err
	}
	m := &Initialization{FormatVersion: initFormatV2, StoreID: hex.EncodeToString(id), Parts: parts, Threshold: threshold, Seal: SealShamir}
	if err = m.newVerification(root); err != nil {
		return nil, err
	}
	if err = b.putInit(m); err != nil {
		for _, s := range shares {
			zeroBytes(s)
		}
		return nil, err
	}
	return shares, nil
}

// validateRoot: 복원된 루트 키가 이 저장소의 것인지, 그리고 지금 쓰는 Seal 방식이
// 기록과 일치하는지 확인한다. 둘 중 하나라도 어긋나면 해제하지 않는다.
func (b *Barrier) validateRoot(root []byte) error {
	m, err := b.loadInit()
	if err != nil {
		return err
	}
	if m == nil {
		return ErrRootVerification
	}
	if t := b.sealer.Type(); (t == SealShamir || t == SealTPM) && t != m.SealMode() {
		return fmt.Errorf("%w: server seal mode %q does not match recorded %q", ErrRootVerification, t, m.SealMode())
	}
	return m.verify(root)
}

// CheckInitialization: 기록이 있다면 v1/v2 모두 읽을 수 있어야 하고 조각 설정이
// 같아야 한다. 기록이 없으면(미초기화) 통과.
func (b *Barrier) CheckInitialization(parts, threshold int) error {
	m, err := b.loadInit()
	if err != nil || m == nil {
		return err
	}
	if m.Parts != parts || m.Threshold != threshold {
		return ErrRootVerification
	}
	return nil
}
func (b *Barrier) LastUnseal() time.Time { b.mu.Lock(); defer b.mu.Unlock(); return b.lastUnseal }

func (b *Barrier) InitializationStatus() (initialized, migration bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	raw, err := b.store.Get(initPath)
	if err != nil {
		return false, false, err
	}
	if raw != nil {
		return true, false, nil
	}
	names, err := b.store.List("keys/")
	return false, len(names) > 0, err
}

// rewriteInitLocked: 메모리의 루트 키로 검증 암호문을 새로 만들어 기록을 v2로
// 저장한다(봉인 방식 변경 또는 v1→v2 갱신). aad가 format_version과 seal을
// 포함하므로 기존 암호문을 그대로 옮길 수는 없다 — 반드시 루트 키가 필요하다.
// 루트 키 자체는 새로 만들지 않고 받은 것을 그대로 쓴다(루트 키 불변).
// 쓰기 전에 현재 기록이 이 루트 키로 검증되는지 먼저 확인해, 엉뚱한 기록을
// 덮어쓰지 않는다. 호출자가 b.mu를 잡고 있어야 한다.
func (b *Barrier) rewriteInitLocked(cur *Initialization, sealMode string) (*Initialization, error) {
	if b.rootKey == nil {
		return nil, ErrSealed
	}
	if err := cur.verify(b.rootKey); err != nil {
		return nil, err
	}
	next := &Initialization{FormatVersion: initFormatV2, StoreID: cur.StoreID, Parts: cur.Parts, Threshold: cur.Threshold, Seal: sealMode}
	if err := next.newVerification(b.rootKey); err != nil {
		return nil, err
	}
	if err := b.putInit(next); err != nil {
		return nil, err
	}
	return next, nil
}
