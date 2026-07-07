// Package barrier: seal(Root Key 공급)과 storage(암호화된 바이트 저장)를 잇는
// 접착제 계층. 평문은 이 계층 위쪽에만 존재하고, storage 아래로는 항상 암호문만
// 내려간다는 원칙을 실제로 강제한다.
package barrier

import (
	"encoding/json"
	"errors"
	"sync"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

var (
	// ErrSealed: barrier가 잠긴(sealed) 상태에서 데이터 접근을 시도했을 때 반환.
	ErrSealed = errors.New("barrier: sealed (call Unseal first)")

	// ErrNotFound: GetJSON에서 key에 해당하는 데이터가 없을 때 반환.
	//
	// storage.StorageBackend.Get은 "없음"을 (nil, nil)로 표현하지만, barrier의
	// GetJSON은 error 하나만 반환하는 시그니처를 쓴다 — 그래서 "있다/없다"를
	// 별도의 bool로 표현할 자리가 없다. Go 표준 라이브러리도 같은 상황에서
	// database/sql.ErrNoRows처럼 이름 붙인 sentinel 에러를 쓰는 게 관례이므로
	// (errors.Is로 판별), 여기서도 같은 패턴을 따른다.
	ErrNotFound = errors.New("barrier: key not found")
)

// Barrier는 seal과 storage를 연결한다.
type Barrier struct {
	store  storage.StorageBackend
	sealer seal.Seal

	// mu는 rootKey를 여러 goroutine(HTTP 요청)이 동시에 읽고 쓸 때의 경합을 막는다.
	mu      sync.Mutex
	rootKey []byte // nil이면 sealed 상태
}

// NewBarrier는 주어진 storage/seal 구현체로 Barrier를 만든다. 처음엔 항상
// sealed 상태다 — Unseal을 호출해야 데이터에 접근할 수 있다.
func NewBarrier(store storage.StorageBackend, sealer seal.Seal) *Barrier {
	return &Barrier{store: store, sealer: sealer}
}

// Unseal은 seal로부터 Root Key를 받아와 메모리에 올린다. 이후 데이터 접근이
// 가능해진다.
func (b *Barrier) Unseal() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	rootKey, err := b.sealer.Unseal()
	if err != nil {
		return err
	}
	b.rootKey = rootKey
	return nil
}

// Seal은 메모리에 올려둔 Root Key를 0으로 덮어 지우고, barrier를 다시 잠긴
// 상태로 되돌린다.
func (b *Barrier) Seal() {
	b.mu.Lock()
	defer b.mu.Unlock()

	zeroBytes(b.rootKey)
	b.rootKey = nil
}

// IsSealed는 현재 barrier가 잠긴 상태인지 반환한다.
func (b *Barrier) IsSealed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.rootKey == nil
}

// SealType은 이 barrier가 어떤 seal 구현을 쓰고 있는지 반환한다 (예: "dev").
// 상태 조회 API(GET /v1/sys/seal-status)에서 노출할 정보일 뿐, Root Key 자체와는
// 무관하므로 잠금 여부와 상관없이 항상 안전하게 반환할 수 있다.
func (b *Barrier) SealType() string {
	return b.sealer.Type()
}

// PutJSON은 value를 JSON으로 직렬화해 Root Key로 암호화한 뒤 storage에 저장한다.
//
// aad(추가 인증 데이터)로 key 문자열 자체를 바인딩한다. 이렇게 하면 "이 암호문은
// 바로 이 key 아래 저장된 것"이라는 사실까지 인증 대상에 포함되어, 누군가
// storage를 직접 조작해 key A의 암호문을 key B 자리에 복사해 넣더라도
// (ciphertext substitution / confused-deputy 공격) B로 읽을 때 aad가 일치하지
// 않아 복호화가 실패한다 — 암호문을 원래 key가 아닌 다른 key로 "재사용"할 수
// 없게 막는 것이다.
func (b *Barrier) PutJSON(key string, value any) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rootKey == nil {
		return ErrSealed
	}

	plaintext, err := json.Marshal(value)
	if err != nil {
		return err
	}

	ciphertext, err := kmscrypto.Encrypt(b.rootKey, plaintext, []byte(key))
	if err != nil {
		return err
	}

	return b.store.Put(key, ciphertext)
}

// GetJSON은 storage에서 key의 암호문을 꺼내 Root Key로 복호화하고, JSON을
// dest에 역직렬화한다. key가 없으면 ErrNotFound를 반환한다.
func (b *Barrier) GetJSON(key string, dest any) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rootKey == nil {
		return ErrSealed
	}

	ciphertext, err := b.store.Get(key)
	if err != nil {
		return err
	}
	if ciphertext == nil {
		return ErrNotFound
	}

	plaintext, err := kmscrypto.Decrypt(b.rootKey, ciphertext, []byte(key))
	if err != nil {
		return err
	}

	return json.Unmarshal(plaintext, dest)
}

// List는 storage.List로 위임한다. sealed 상태면 거부한다 — barrier가 잠긴
// 동안은 키 이름 목록조차 노출하지 않기 위해서다.
func (b *Barrier) List(prefix string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rootKey == nil {
		return nil, ErrSealed
	}
	return b.store.List(prefix)
}

// Delete는 storage.Delete로 위임한다. sealed 상태면 거부한다.
func (b *Barrier) Delete(key string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.rootKey == nil {
		return ErrSealed
	}
	return b.store.Delete(key)
}

// zeroBytes는 슬라이스의 모든 바이트를 0으로 덮어써서, 더 이상 필요 없는 키
// material이 메모리에 평문으로 남는 시간을 최소화한다.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
