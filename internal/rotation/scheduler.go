// Package rotation: 주기적으로 깨어나 회전할 때가 된 키를 찾아 회전시키는
// 스케줄러. "회전이 필요한지 판단"하는 로직은 keys.KeyManager에 있으므로,
// 이 패키지는 "언제 확인할지"와 "회전 실행"만 담당한다.
package rotation

import (
	"log"
	"sync"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
)

// defaultTickInterval: 점검 주기 기본값.
const defaultTickInterval = 10 * time.Second

// Option은 NewRotationScheduler의 선택적 설정을 표현한다.
//
// Go에는 생성자 오버로딩(같은 이름에 파라미터 개수가 다른 함수 여러 개)이
// 없다. 그래서 "필수 인자 + 가변 개수의 옵션 함수"로 선택적 설정을 표현하는
// functional options 패턴이 관례로 쓰인다. 각 With*** 함수는 "RotationScheduler를
// 받아 필드 하나를 채우는 함수"를 반환하고, 생성자가 그 함수들을 순서대로
// 실행해 기본값 위에 옵션을 하나씩 덮어쓴다. 필드가 두 개뿐이라 Config 구조체
// 하나를 받는 방식도 충분히 괜찮지만, 여기서는 "옵션 각각을 독립적으로 생략할
// 수 있다"는 점이 호출부(`NewRotationScheduler(km)` vs
// `NewRotationScheduler(km, WithTickInterval(5*time.Second))`)에서 더 잘
// 드러나는 이 패턴을 선택했다.
type Option func(*RotationScheduler)

// WithTickInterval은 점검 주기를 설정한다. 지정하지 않으면 기본값(10초)을 쓴다.
func WithTickInterval(d time.Duration) Option {
	return func(s *RotationScheduler) {
		s.tickInterval = d
	}
}

// WithOnRotate는 키가 회전될 때마다 호출할 콜백을 설정한다(로깅/관측용).
// 지정하지 않으면 아무 것도 호출되지 않는다.
func WithOnRotate(fn func(name string)) Option {
	return func(s *RotationScheduler) {
		s.onRotate = fn
	}
}

// RotationScheduler는 tickInterval마다 keys.KeyManager.FindKeysDueForRotation으로
// 회전 대상을 찾아 RotateKey를 호출한다.
type RotationScheduler struct {
	km           *keys.KeyManager
	tickInterval time.Duration
	onRotate     func(name string)

	// mu는 아래 실행 상태 필드들을 Start/Stop이 여러 번, 혹은 동시에 호출되어도
	// 안전하게 보호한다.
	mu      sync.Mutex
	running bool
	stopCh  chan struct{} // Start가 띄운 goroutine에게 "멈춰라"를 알리는 신호 채널
	doneCh  chan struct{} // 그 goroutine이 실제로 종료됐음을 Stop에게 알리는 채널
}

// NewRotationScheduler는 km으로 회전을 수행하는 스케줄러를 만든다.
func NewRotationScheduler(km *keys.KeyManager, opts ...Option) *RotationScheduler {
	s := &RotationScheduler{
		km:           km,
		tickInterval: defaultTickInterval,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// tick은 한 번의 점검을 수행하는 핵심 로직이다. FindKeysDueForRotation으로
// 대상을 찾고 하나씩 RotateKey를 호출한다. 특정 키의 회전이 실패해도 나머지
// 키의 회전은 계속 시도한다 — 키 하나의 문제로 전체 점검이 멈추지 않게 하기
// 위해서다. 회전에 성공한 이름들만 반환한다.
//
// nowMs를 인자로 받는 이유: Start는 실제 time.Now()를 넘기지만, 테스트에서는
// 임의의 시각을 주입해 "이 시점엔 어떤 키가 회전 대상인가"를 결정적으로
// 검증할 수 있게 하기 위함이다.
func (s *RotationScheduler) tick(nowMs int64) ([]string, error) {
	due, err := s.km.FindKeysDueForRotation(nowMs)
	if err != nil {
		return nil, err
	}

	var rotated []string
	for _, name := range due {
		if _, err := s.km.RotateKey(name); err != nil {
			log.Printf("rotation: failed to rotate key %q: %v", name, err)
			continue
		}
		rotated = append(rotated, name)
		if s.onRotate != nil {
			s.onRotate(name)
		}
	}
	return rotated, nil
}

// Start는 백그라운드 goroutine을 하나 띄워 tickInterval마다 tick을 반복
// 호출한다. 이미 실행 중이면 아무 것도 하지 않는다(중복 시작 방지).
//
// Go 동시성 개념 정리:
//   - goroutine: `go func() { ... }()`로 시작하는 경량 스레드. Start를 호출한
//     쪽(메인 goroutine)은 이 함수를 만들자마자 즉시 리턴하고, 실제 점검
//     루프는 별도로 백그라운드에서 계속 돈다.
//   - time.Ticker: tickInterval마다 자신의 채널(ticker.C)에 값을 하나씩
//     밀어넣는 타이머. `for { select { case <-ticker.C: ... } }` 형태로 그
//     신호를 받을 때마다 tick을 실행한다.
//   - stopCh(정지 채널): Stop이 이 채널을 close(닫기)하면, goroutine 안의
//     `select`가 그 즉시 `<-s.stopCh` 케이스를 선택해 루프를 빠져나간다.
//     "값을 보낸다"가 아니라 "채널을 닫는다"를 신호로 쓰는 이유는, close는
//     그 채널을 읽는 모든 goroutine에 동시에 신호를 전달할 수 있고 여러 번
//     보내지 않아도 되기 때문이다 — "그만두라"는 신호는 한 번이면 충분하다.
//   - doneCh: goroutine이 실제로 루프를 빠져나와 완전히 끝났음을 Stop 쪽에
//     알리는 채널. 이게 없으면 Stop이 반환된 직후에도 goroutine이 아직 정리
//     중일 수 있어서, "Stop이 끝났으니 완전히 멈췄다"고 보장할 수 없다.
func (s *RotationScheduler) Start() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.doneCh = make(chan struct{})

	go func() {
		defer close(s.doneCh)

		ticker := time.NewTicker(s.tickInterval)
		defer ticker.Stop() // 타이머 리소스 해제 — 안 하면 프로세스 종료와 무관하게 계속 자원을 차지한다.

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				if _, err := s.tick(time.Now().UnixMilli()); err != nil {
					log.Printf("rotation: tick failed: %v", err)
				}
			}
		}
	}()
}

// Stop은 백그라운드 goroutine에 정지 신호를 보내고, 실제로 멈출 때까지
// 기다린다. 실행 중이 아니면 아무 것도 하지 않는다 — 여러 번 호출해도 안전하다.
func (s *RotationScheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	stopCh := s.stopCh
	doneCh := s.doneCh
	s.mu.Unlock()

	close(stopCh)
	<-doneCh
}
