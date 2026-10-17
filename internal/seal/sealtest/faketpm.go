// Package sealtest: 테스트 전용 가짜 TPM. CGO가 필요한 실제 시뮬레이터 없이
// "TPM으로 봉인한 루트 키는 같은 장치에서만 열린다"는 동작을 흉내 내서 admin/
// barrier 테스트가 일반 go test에서 돌 수 있게 한다. 서버 바이너리(cmd/server)는
// 이 패키지를 import하지 않는다. 실제 TPMSeal 경로는 tpm_lab 태그 테스트가 검증한다.
package sealtest

import (
	"crypto/rand"
	"errors"
	"sync"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

const blobKey = "seal/tpm/rootkey" // seal.tpmBlobStorageKey와 같은 값

// Device: 가짜 TPM 칩 하나. 칩마다 고유한 내부 키를 갖는다(SRK 역할).
type Device struct {
	mu     sync.Mutex
	key    []byte
	broken bool
}

func NewDevice() *Device {
	k := make([]byte, kmscrypto.KeyLen)
	rand.Read(k)
	return &Device{key: k}
}

// SetBroken(true): 장치가 없거나 고장 난 상황(Unseal 실패)을 흉내 낸다.
func (d *Device) SetBroken(v bool) { d.mu.Lock(); d.broken = v; d.mu.Unlock() }

func (d *Device) isBroken() bool { d.mu.Lock(); defer d.mu.Unlock(); return d.broken }

// Open: seal.Switch의 open 함수로 쓴다. 고장 상태면 실패.
func (d *Device) Open(store storage.StorageBackend) (seal.TPMBackend, error) {
	if d.isBroken() {
		return nil, errors.New("fake TPM device not found")
	}
	return &FakeTPM{dev: d, store: store}, nil
}

// FakeTPM: seal.TPMBackend의 가짜 구현.
type FakeTPM struct {
	dev   *Device
	store storage.StorageBackend
}

func (f *FakeTPM) Type() string { return "tpm" }

func (f *FakeTPM) IsConfigured() bool {
	d, err := f.store.Get(blobKey)
	return err == nil && d != nil
}

func (f *FakeTPM) SealExisting(root []byte) error {
	if f.dev.isBroken() {
		return errors.New("fake TPM broken")
	}
	if d, err := f.store.Get(blobKey); err != nil {
		return err
	} else if d != nil {
		return seal.ErrTPMAlreadyInitialized
	}
	blob, err := kmscrypto.Encrypt(f.dev.key, root, []byte(blobKey))
	if err != nil {
		return err
	}
	return f.store.Put(blobKey, blob)
}

func (f *FakeTPM) Unseal() ([]byte, error) {
	if f.dev.isBroken() {
		return nil, errors.New("fake TPM broken")
	}
	d, err := f.store.Get(blobKey)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, seal.ErrTPMNotInitialized
	}
	return kmscrypto.Decrypt(f.dev.key, d, []byte(blobKey))
}

func (f *FakeTPM) RemoveBlob() error { return f.store.Delete(blobKey) }
