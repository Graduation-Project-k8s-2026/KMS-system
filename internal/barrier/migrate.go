package barrier

import (
	"errors"
	"fmt"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/shamir"
)

var (
	// ErrInvalidSealTarget: target이 "shamir"|"tpm"이 아닐 때.
	ErrInvalidSealTarget = errors.New("barrier: seal target must be \"shamir\" or \"tpm\"")
	// ErrSealAlreadyTarget: 이미 tpm인데 tpm으로 이전을 요청했을 때(조각 재발급은 shamir만 허용).
	ErrSealAlreadyTarget = errors.New("barrier: seal is already the requested target")
	// ErrSealModeMismatch: 서버가 쓰는 방식과 init 기록이 다를 때. 어느 쪽이 맞는지 서버가
	// 판단하지 않고 멈춘다(fail-closed).
	ErrSealModeMismatch = errors.New("barrier: running seal mode does not match the initialization record")
)

// MigrateSeal은 봉인 방식을 target으로 이전하고 새 Shamir 조각을 반환한다.
//
// 불변 규칙: 루트 키는 새로 만들지 않는다. 메모리에 올라와 있는 같은 루트 키를 (a) TPM에
// 다시 봉인하거나, (b) 새 조각으로 다시 나눌 뿐이다. 운영 클러스터의 Secret은 이 루트
// 키로만 읽히기 때문이다. 그래서 봉인 해제 상태에서만 가능하다(sealed면 ErrSealed).
//
// 순서와 되돌림(실패해도 "기록과 실제가 어긋난" 상태를 남기지 않는 것이 목표):
//   - shamir→tpm: TPM에 봉인 → 같은 장치로 다시 풀어 같은 키인지 확인 → 기록 저장.
//     기록 저장이 실패하면 방금 만든 blob을 지운다.
//   - tpm→shamir: 기록을 shamir로 저장 → blob 삭제. blob 삭제가 실패하면 기록을 tpm으로
//     되돌린다(blob이 아직 있으니 TPM 모드가 계속 유효하다).
//   - shamir→shamir: 같은 루트 키를 다시 나눈 조각 재발급. 이전 조각도 계속 유효하다.
//
// 반환한 조각은 호출자가 한 번 보여주고 버려야 한다. 서버는 저장하지 않는다.
func (b *Barrier) MigrateSeal(sw *seal.Switch, target string, parts, threshold int) (shares [][]byte, err error) {
	if target != SealShamir && target != SealTPM {
		return nil, ErrInvalidSealTarget
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rootKey == nil {
		return nil, ErrSealed
	}

	cur, err := b.loadInit()
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, ErrRootVerification
	}
	if err := cur.verify(b.rootKey); err != nil {
		return nil, err
	}
	if cur.Parts != parts || cur.Threshold != threshold {
		return nil, fmt.Errorf("%w: share parameters differ from the record", ErrRootVerification)
	}
	from := cur.SealMode()
	if sw.Mode() != from {
		return nil, ErrSealModeMismatch
	}
	if from == SealTPM && target == SealTPM {
		return nil, ErrSealAlreadyTarget
	}

	// 어떤 실패에서도 조각을 메모리에 남기지 않는다.
	defer func() {
		if err != nil {
			for _, s := range shares {
				zeroBytes(s)
			}
			shares = nil
		}
	}()

	if shares, err = shamir.Split(b.rootKey, parts, threshold); err != nil {
		return nil, err
	}

	switch {
	case from == SealShamir && target == SealTPM:
		tpm, err := sw.TPM()
		if err != nil {
			return shares, err
		}
		if err := tpm.SealExisting(b.rootKey); err != nil {
			return shares, err // ErrTPMAlreadyInitialized도 그대로 올린다: 남은 blob을 덮어쓰지 않는다
		}
		// 저장된 blob이 실제로 같은 루트 키를 돌려주는지 확인한다. 이전 뒤 재부팅에서
		// 처음 알게 되는 것보다 지금 알게 되는 편이 훨씬 싸다.
		back, uerr := tpm.Unseal()
		same := uerr == nil && string(back) == string(b.rootKey)
		zeroBytes(back)
		if !same {
			return shares, errors.Join(errors.New("barrier: TPM round-trip check failed; migration aborted"), tpm.RemoveBlob())
		}
		if _, err := b.rewriteInitLocked(cur, SealTPM); err != nil {
			if rerr := tpm.RemoveBlob(); rerr != nil {
				err = errors.Join(err, fmt.Errorf("rollback failed, TPM blob remains: %w", rerr))
			}
			return shares, err
		}
		sw.SetMode(SealTPM)

	case from == SealTPM && target == SealShamir:
		next, err := b.rewriteInitLocked(cur, SealShamir)
		if err != nil {
			return shares, err
		}
		if err := sw.RemoveTPMBlob(); err != nil {
			// 기록을 원래대로 되돌린다: blob이 남아 있으므로 TPM 모드가 여전히 유효하다.
			if _, rerr := b.rewriteInitLocked(next, SealTPM); rerr != nil {
				err = errors.Join(err, fmt.Errorf("record rollback failed: %w", rerr))
			}
			return shares, err
		}
		sw.SetMode(SealShamir)

	default: // shamir → shamir
		if _, err := b.rewriteInitLocked(cur, SealShamir); err != nil {
			return shares, err
		}
	}
	return shares, nil
}
