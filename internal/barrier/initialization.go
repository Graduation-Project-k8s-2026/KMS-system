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

type Initialization struct {
	FormatVersion int    `json:"format_version"`
	StoreID       string `json:"store_id"`
	Parts         int    `json:"parts"`
	Threshold     int    `json:"threshold"`
	Verification  []byte `json:"verification"`
}

func (m Initialization) aad() []byte {
	return []byte(fmt.Sprintf("kms-init:%d:%s:%d:%d", m.FormatVersion, m.StoreID, m.Parts, m.Threshold))
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
	m := Initialization{FormatVersion: 1, StoreID: hex.EncodeToString(id), Parts: parts, Threshold: threshold}
	m.Verification, err = kmscrypto.Encrypt(root, []byte("kms-root-valid-v1"), m.aad())
	if err != nil {
		return nil, err
	}
	raw, err = json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if err = b.store.Put(initPath, raw); err != nil {
		for _, s := range shares {
			zeroBytes(s)
		}
		return nil, err
	}
	return shares, nil
}
func (b *Barrier) validateRoot(root []byte) error {
	raw, err := b.store.Get(initPath)
	if err != nil {
		return err
	}
	if raw == nil {
		return ErrRootVerification
	}
	var m Initialization
	if json.Unmarshal(raw, &m) != nil || m.FormatVersion != 1 || len(m.StoreID) != 32 || m.Threshold < 2 || m.Parts < m.Threshold {
		return ErrRootVerification
	}
	plain, err := kmscrypto.Decrypt(root, m.Verification, m.aad())
	if err != nil || string(plain) != "kms-root-valid-v1" {
		return ErrRootVerification
	}
	return nil
}
func (b *Barrier) CheckInitialization(parts, threshold int) error {
	raw, err := b.store.Get(initPath)
	if err != nil || raw == nil {
		return err
	}
	var m Initialization
	if json.Unmarshal(raw, &m) != nil || m.FormatVersion != 1 || m.Parts != parts || m.Threshold != threshold {
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
