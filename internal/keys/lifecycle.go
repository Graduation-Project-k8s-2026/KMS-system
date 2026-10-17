package keys

import (
	"errors"
	"fmt"
	"time"
)

// 키 수명 주기: active ⇄ disabled → pending_deletion → (유예 만료) 삭제.
//
//	disable          active → disabled            (이미 disabled면 그대로 성공)
//	enable           disabled → active            (이미 active면 그대로 성공)
//	schedule-deletion active|disabled → pending_deletion (유예 7~30일, 기본 30)
//	cancel-deletion  pending_deletion → disabled  (AWS와 같다: 취소해도 바로 쓰이지 않고, 다시 쓰려면 enable)
//
// 왜 바로 삭제하지 않나: 키를 지우면 그 키로 암호화한 모든 데이터를 영구히 복호화할 수 없다. 그래서
// "사용 중지(오류가 나는지 지켜보기) → 삭제 예약(유예) → 삭제"의 단계를 둬서, 잘못 지정했을 때 되돌릴
// 시간을 준다. 상세는 docs/decisions.md의 키 삭제 ADR.

const (
	MinPendingDays     = 7
	MaxPendingDays     = 30
	DefaultPendingDays = 30
)

var (
	// ErrKeyProtected: 보호 키(KMS v2 키, KMS_PROTECTED_KEYS)를 비활성화/삭제 예약하려 했을 때.
	ErrKeyProtected = errors.New("key is protected")
	// ErrInvalidState: 현재 상태에서 허용되지 않는 전이.
	ErrInvalidState = errors.New("invalid key state transition")
)

func (m *KeyManager) mutateState(name string, fn func(ring *KeyRing) error) (KeyRingMeta, error) {
	defer m.lock(name)()
	ring, err := m.loadRing(name)
	if err != nil {
		return KeyRingMeta{}, err
	}
	if err := fn(ring); err != nil {
		return KeyRingMeta{}, err
	}
	if err := m.barrier.PutJSON(storageKey(name), ring); err != nil {
		return KeyRingMeta{}, err
	}
	return toMeta(ring), nil
}

// DisableKey는 active 키를 사용 중지한다. 보호 키는 거부한다.
func (m *KeyManager) DisableKey(name string) (KeyRingMeta, error) {
	return m.mutateState(name, func(r *KeyRing) error {
		if m.isProtected(name) {
			return ErrKeyProtected
		}
		switch r.state() {
		case StateActive:
			r.State = StateDisabled
		case StateDisabled:
		default:
			return fmt.Errorf("%w: key is pending deletion; cancel the deletion first", ErrInvalidState)
		}
		return nil
	})
}

// EnableKey는 disabled 키를 다시 active로 만든다.
func (m *KeyManager) EnableKey(name string) (KeyRingMeta, error) {
	return m.mutateState(name, func(r *KeyRing) error {
		switch r.state() {
		case StateDisabled:
			r.State = StateActive
		case StateActive:
		default:
			return fmt.Errorf("%w: key is pending deletion; cancel the deletion first", ErrInvalidState)
		}
		return nil
	})
}

// ScheduleDeletion은 키를 pending_deletion으로 바꾸고 now+pendingDays일을 삭제 시각으로 기록한다.
// pendingDays가 0이면 기본 30일. 범위 밖(7~30 외)이면 KeyPolicyError. 보호 키는 거부한다.
func (m *KeyManager) ScheduleDeletion(name string, pendingDays int) (KeyRingMeta, error) {
	if pendingDays == 0 {
		pendingDays = DefaultPendingDays
	}
	if pendingDays < MinPendingDays || pendingDays > MaxPendingDays {
		msg := fmt.Sprintf("pending_days must be between %d and %d", MinPendingDays, MaxPendingDays)
		return KeyRingMeta{}, &KeyPolicyError{Msg: msg, Code: "invalid_request", Public: msg}
	}
	return m.mutateState(name, func(r *KeyRing) error {
		if m.isProtected(name) {
			return ErrKeyProtected
		}
		if r.state() == StatePendingDeletion {
			return fmt.Errorf("%w: deletion is already scheduled", ErrInvalidState)
		}
		date := m.now().UTC().Add(time.Duration(pendingDays) * 24 * time.Hour)
		r.State, r.DeletionDate = StatePendingDeletion, &date
		return nil
	})
}

// CancelDeletion은 삭제 예약을 취소한다. 결과 상태는 disabled다 (다시 쓰려면 EnableKey).
func (m *KeyManager) CancelDeletion(name string) (KeyRingMeta, error) {
	return m.mutateState(name, func(r *KeyRing) error {
		if r.state() != StatePendingDeletion {
			return fmt.Errorf("%w: no deletion is scheduled", ErrInvalidState)
		}
		r.State, r.DeletionDate = StateDisabled, nil
		return nil
	})
}

// PurgeExpired는 삭제 유예가 지난 키의 자료를 삭제한다 (되돌릴 수 없음). 봉인 상태이면 barrier가
// ErrSealed를 돌려주므로 아무것도 지우지 않는다 — 삭제는 해제 상태에서만 진행된다.
// 지우기 전에 beforeDelete(name)을 호출하고 에러가 나면 그 키는 건너뛴다 (감사 기록이 안 남으면 삭제하지
// 않는다). 삭제는 storage의 원자적 Delete 한 번이다. 삭제한 키 이름들을 돌려준다.
// 보호 키는 (예약될 수 없지만) 방어적으로 건너뛴다.
func (m *KeyManager) PurgeExpired(beforeDelete func(name string) error, afterDelete func(name string)) ([]string, error) {
	names, err := m.ListKeys()
	if err != nil {
		return nil, err
	}
	var purged []string
	for _, name := range names {
		// ListKeys는 "keys/<name>" 접두사를 포함한 저장 경로를 줄 수 있어 이름으로 정규화한다.
		name = trimKeysPrefix(name)
		ok, err := m.purgeOne(name, beforeDelete)
		if err != nil {
			return purged, err
		}
		if ok {
			purged = append(purged, name)
			if afterDelete != nil {
				afterDelete(name)
			}
		}
	}
	return purged, nil
}

func (m *KeyManager) purgeOne(name string, beforeDelete func(string) error) (bool, error) {
	defer m.lock(name)()
	ring, err := m.loadRing(name)
	if err != nil {
		var nf *KeyNotFoundError
		if errors.As(err, &nf) {
			return false, nil
		}
		return false, err
	}
	if ring.state() != StatePendingDeletion || ring.DeletionDate == nil || m.isProtected(name) || m.now().Before(*ring.DeletionDate) {
		return false, nil
	}
	if beforeDelete != nil {
		if err := beforeDelete(name); err != nil {
			return false, nil // 감사 기록 실패: 이번엔 지우지 않고 다음 주기에 다시 시도
		}
	}
	if err := m.barrier.Delete(storageKey(name)); err != nil {
		return false, err
	}
	m.locks.Delete(name)
	return true, nil
}

func trimKeysPrefix(s string) string {
	if len(s) > len(keysPrefix) && s[:len(keysPrefix)] == keysPrefix {
		return s[len(keysPrefix):]
	}
	return s
}
