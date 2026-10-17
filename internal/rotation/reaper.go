package rotation

import (
	"log"
	"sync"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
)

// Reaper는 주기적으로 깨어나 삭제 유예가 끝난 키(pending_deletion)의 자료를 지운다. 판단과 삭제는
// keys.PurgeExpired가 하고, 이 타입은 "언제 확인할지"와 시작/정지만 맡는다 (RotationScheduler와 같은 구조).
// 봉인되면 Stop으로 멈추고 해제되면 Start한다 — 삭제는 봉인 해제 상태에서만 진행된다.
type Reaper struct {
	km       *keys.KeyManager
	interval time.Duration
	before   func(name string) error // 삭제 직전 호출(관리 감사 기록). 에러면 그 키는 이번엔 삭제하지 않는다.
	after    func(name string)       // 삭제 직후 호출(관리 감사 기록)

	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewReaper: interval<=0이면 10분.
func NewReaper(km *keys.KeyManager, interval time.Duration, before func(string) error, after func(string)) *Reaper {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	return &Reaper{km: km, interval: interval, before: before, after: after}
}

// Tick은 한 번 점검한다 (테스트에서 직접 호출).
func (r *Reaper) Tick() ([]string, error) { return r.km.PurgeExpired(r.before, r.after) }

func (r *Reaper) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return
	}
	r.running = true
	r.stopCh, r.doneCh = make(chan struct{}), make(chan struct{})
	stopCh, doneCh := r.stopCh, r.doneCh
	go func() {
		defer close(doneCh)
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			if names, err := r.Tick(); err != nil {
				log.Printf("key reaper: %v", err)
			} else if len(names) > 0 {
				log.Printf("key reaper: purged %d key(s) past their deletion date", len(names))
			}
			select {
			case <-stopCh:
				return
			case <-t.C:
			}
		}
	}()
}

func (r *Reaper) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	r.running = false
	close(r.stopCh)
	done := r.doneCh
	r.mu.Unlock()
	<-done
}
