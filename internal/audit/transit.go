package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// Transit(암복호화) 감사는 관리 감사(Log)와 달리 "요청 경로를 막지 않는" 비동기 방식이다.
//
// 왜 다른가: 관리 감사는 요청마다 동기 쓰기 + fsync라 요청 하나가 디스크 왕복만큼 느려진다.
// 관리 작업은 드물어서 괜찮지만, Transit은 초당 수천 건이라 같은 방식을 쓰면 처리량이 무너진다.
// 그래서 요청은 이벤트를 버퍼 채널에 넣고 바로 돌아가고, 별도 goroutine이 배치로 파일에 쓰고
// 주기적으로 fsync한다. 대가: 프로세스가 비정상 종료하면 마지막 fsync 이후(기본 1초)의 기록을
// 잃을 수 있고, 버퍼가 가득 차면 요청을 막는 대신 이벤트를 버리고 kms_audit_dropped_total을
// 올린다. 즉 "감사 완전성"보다 "가용성"을 택했고, 유실은 지표로 드러난다(ADR 참고).
//
// 기록 금지: 요청/응답 본문, 토큰, 평문, 암호문. 필드는 TransitEvent가 전부다.
const (
	// DefaultTransitBuffer: 버퍼 채널 크기(이벤트 수).
	DefaultTransitBuffer = 8192
	// DefaultTransitFsync: fsync 주기.
	DefaultTransitFsync = time.Second
	transitDayCap       = 256 << 20 // 하루 파일 상한. 넘으면 버린다(디스크 보호).
	transitRetention    = 30 * 24 * time.Hour
	transitBatch        = 512
)

// TransitEvent는 Transit 요청 하나의 감사 기록이다.
type TransitEvent struct {
	UTC          time.Time `json:"utc"`
	RequestID    string    `json:"request_id"`
	Subject      string    `json:"subject"`       // system:serviceaccount:<ns>:<name>
	Action       string    `json:"action"`        // encrypt | decrypt | rewrap
	Key          string    `json:"key"`           // 키 이름
	SARNamespace string    `json:"sar_namespace"` // SAR 판단 네임스페이스 ("" = 클러스터 범위)
	Status       int       `json:"status"`        // 결과 HTTP 상태 코드
	LatencyMs    float64   `json:"latency_ms"`
	// Detail: 거부 사유 같은 내부 설명(키 버전 숫자 등 응답에는 숨기는 정보). 본문/비밀값은 넣지 않는다.
	Detail string `json:"detail,omitempty"`
	// Listener/ClientIP: 외부(인터넷) 리스너 요청에만 채운다. ClientIP는 TCP 연결의 RemoteAddr(X-Forwarded-For는
	// 신뢰하지 않음)다. 내부 Transit 리스너의 기록에는 생략된다.
	Listener string `json:"listener,omitempty"`
	ClientIP string `json:"client_ip,omitempty"`
}

// TransitLog는 비동기 Transit 감사 기록기다.
type TransitLog struct {
	dir        string
	ch         chan TransitEvent
	fsyncEvery time.Duration

	mu     sync.RWMutex // closed와 채널 close를 보호한다 (Record vs Close 경쟁)
	closed bool
	wg     sync.WaitGroup

	// 아래는 writer goroutine만 만진다.
	f       *os.File
	bw      *bufio.Writer
	day     string
	size    int64
	dirty   bool
	pruned  string
	lastErr error

	gate chan struct{} // 테스트 전용: 닫힐 때까지 writer가 처리를 시작하지 않는다 (버퍼 포화를 결정적으로 만들기 위함)
}

// NewTransit은 dir에 기록하는 TransitLog를 만들고 writer goroutine을 시작한다.
// buffer<=0, fsyncEvery<=0이면 기본값을 쓴다.
func NewTransit(dir string, buffer int, fsyncEvery time.Duration) (*TransitLog, error) {
	if dir == "" {
		return nil, errors.New("transit audit directory required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if buffer <= 0 {
		buffer = DefaultTransitBuffer
	}
	if fsyncEvery <= 0 {
		fsyncEvery = DefaultTransitFsync
	}
	l := &TransitLog{dir: dir, ch: make(chan TransitEvent, buffer), fsyncEvery: fsyncEvery}
	l.start()
	return l, nil
}

func (l *TransitLog) start() {
	l.wg.Add(1)
	go l.run()
}

// Record는 이벤트를 큐에 넣는다. 절대 블로킹하지 않는다: 버퍼가 가득 차면(또는 이미 닫혔으면)
// 이벤트를 버리고 kms_audit_dropped_total을 올린다.
func (l *TransitLog) Record(e TransitEvent) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		metrics.AuditDroppedTotal.Inc()
		return
	}
	select {
	case l.ch <- e:
	default:
		metrics.AuditDroppedTotal.Inc()
	}
}

// Close는 더 받지 않고, 큐에 남은 기록을 모두 쓰고 fsync한 뒤 파일을 닫는다 (정상 종료 시 유실 없음).
func (l *TransitLog) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.ch)
	l.mu.Unlock()
	l.wg.Wait()
	return l.lastErr
}

func (l *TransitLog) run() {
	defer l.wg.Done()
	if l.gate != nil {
		<-l.gate
	}
	tick := time.NewTicker(l.fsyncEvery)
	defer tick.Stop()
	for {
		select {
		case e, ok := <-l.ch:
			if !ok {
				l.syncClose()
				return
			}
			l.write(e)
			// 배치: 이미 쌓여 있는 것은 한꺼번에 쓴다.
			for i := 0; i < transitBatch; i++ {
				select {
				case e, ok = <-l.ch:
					if !ok {
						l.syncClose()
						return
					}
					l.write(e)
				default:
					i = transitBatch
				}
			}
			if l.bw != nil {
				l.setErr(l.bw.Flush()) // write() 시스템콜까지만; fsync는 주기적으로
			}
		case <-tick.C:
			l.sync()
		}
	}
}

func (l *TransitLog) setErr(err error) {
	if err != nil {
		l.lastErr = err
	}
}

// write는 이벤트 하나를 버퍼에 쓴다. 실패하거나 하루 상한을 넘으면 버리고 지표를 올린다.
func (l *TransitLog) write(e TransitEvent) {
	if e.UTC.IsZero() {
		e.UTC = time.Now().UTC()
	}
	rec, err := json.Marshal(e)
	if err != nil {
		metrics.AuditDroppedTotal.Inc()
		return
	}
	rec = append(rec, '\n')
	day := e.UTC.Format("2006-01-02")
	if day != l.day || l.f == nil {
		if err := l.openDay(day); err != nil {
			l.setErr(err)
			metrics.AuditDroppedTotal.Inc()
			return
		}
	}
	if l.size+int64(len(rec)) > transitDayCap {
		metrics.AuditDroppedTotal.Inc()
		return
	}
	n, err := l.bw.Write(rec)
	l.size += int64(n)
	l.dirty = true
	if err != nil {
		l.setErr(err)
		metrics.AuditDroppedTotal.Inc()
	}
}

func (l *TransitLog) openDay(day string) error {
	l.sync()
	if l.f != nil {
		l.f.Close()
		l.f, l.bw = nil, nil
	}
	p := filepath.Join(l.dir, day+".jsonl")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.bw, l.day, l.size = f, bufio.NewWriterSize(f, 64<<10), day, st.Size()
	if l.pruned != day {
		l.pruned = day
		l.prune()
	}
	return nil
}

// prune은 보존 기간(30일)이 지난 파일을 지운다 (날짜가 바뀔 때 한 번).
func (l *TransitLog) prune() {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	for _, f := range entries {
		if filepath.Ext(f.Name()) != ".jsonl" {
			continue
		}
		if st, err := f.Info(); err == nil && time.Since(st.ModTime()) > transitRetention {
			os.Remove(filepath.Join(l.dir, f.Name()))
		}
	}
}

func (l *TransitLog) sync() {
	if l.bw == nil || !l.dirty {
		return
	}
	l.setErr(l.bw.Flush())
	l.setErr(l.f.Sync())
	l.dirty = false
}

func (l *TransitLog) syncClose() {
	l.sync()
	if l.f != nil {
		l.setErr(l.f.Close())
		l.f, l.bw = nil, nil
	}
}

// ReadTransitToday는 오늘 파일의 Transit 감사 기록을 (최대 1000건, 최신 우선 유지) 읽는다.
// 관리 화면의 /api/audit이 관리 감사(ReadToday)와 합칠 수 있게 별도 함수로 제공한다.
func ReadTransitToday(dir string) ([]TransitEvent, error) {
	f, err := os.Open(filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl"))
	if os.IsNotExist(err) {
		return []TransitEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 64<<20))
	events := []TransitEvent{}
	for {
		var e TransitEvent
		if err := d.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			// 쓰는 도중의 마지막 불완전한 줄은 무시한다 (이미 읽은 것은 돌려준다).
			break
		}
		events = append(events, e)
		if len(events) > 1000 {
			events = events[1:]
		}
	}
	return events, nil
}
