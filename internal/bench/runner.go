package bench

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// 측정 가능한 작업 종류. internal/api/transit의 라우트 이름과 일치한다.
const (
	OpEncrypt = "encrypt"
	OpDecrypt = "decrypt"
	OpRewrap  = "rewrap"
)

// AllOps는 --op=all이 펼쳐지는 순서다.
var AllOps = []string{OpEncrypt, OpDecrypt, OpRewrap}

// RunConfig는 측정 한 번(= 결과 표의 한 행)을 정의한다.
type RunConfig struct {
	Scenario     string // 보고용 라벨: "basic"/"payload"/"concurrency"
	Operation    string // encrypt/decrypt/rewrap
	PayloadBytes int
	Concurrency  int
	Count        int           // Duration이 0일 때만 쓰인다
	Duration     time.Duration // 0보다 크면 Count 대신 이 시간만큼 측정한다
	Warmup       int
	Keepalive    bool // 보고용 — 실제 연결 재사용 여부는 호출부의 http.Client가 결정한다
}

// RunResult는 Execute 한 번의 원시 결과다 — 집계(백분위 등)는 report.go에서
// 한다.
type RunResult struct {
	Config       RunConfig
	StartedAt    time.Time
	EndedAt      time.Time
	Samples      []time.Duration // 성공한 요청의 지연 시간만
	SuccessCount int
	ErrorCount   int
	ErrorSamples []string // 진단용 — 서로 다른 에러 메시지를 최대 5개까지만 보관
}

const maxErrorSamples = 5

// ValidateWarmupForOps는 ops에 decrypt/rewrap이 포함돼 있는데 warmup이
// 1 미만이면 에러를 반환한다 — decrypt/rewrap 측정은 warmup 단계에서 만든
// 암호문 풀이 반드시 있어야 하기 때문이다(요구사항: "벤치 도구가 키를
// 생성하지 않는다" — 암호문도 미리 받아둔 것만 쓸 수 있다는 뜻).
func ValidateWarmupForOps(ops []string, warmup int) error {
	for _, op := range ops {
		if (op == OpDecrypt || op == OpRewrap) && warmup < 1 {
			return fmt.Errorf("--warmup must be >= 1 when measuring %q (decrypt/rewrap need warmup encrypts to build a ciphertext pool)", op)
		}
	}
	return nil
}

// Execute는 cfg가 정의한 측정 한 번을 수행한다.
//
//  1. warmup: Operation이 encrypt면 그냥 버리는 encrypt를 Warmup번 호출한다.
//     decrypt/rewrap이면 Warmup번 encrypt해 그 결과(암호문)를 풀로 모아두고,
//     측정 구간에서는 그 풀을 순환하며 재사용한다 — decrypt/rewrap의 비용은
//     어떤 유효한 암호문이든 동일하므로(내용 의존적이지 않음) 문제가 없다.
//  2. 측정: Concurrency개의 goroutine(worker)이 각자 반복해서 요청을 보낸다.
//     Duration>0이면 그 시간이 지날 때까지, 아니면 Count개를 다 채울 때까지
//     (atomic 카운터로 작업을 나눠 가진다) 반복한다. ctx가 취소되면(Ctrl+C)
//     그 즉시 중단하고, 그때까지 모은 샘플만 반환한다 — 에러가 아니다.
func Execute(ctx context.Context, client *Client, key string, cfg RunConfig) (RunResult, error) {
	if cfg.Concurrency < 1 {
		return RunResult{}, fmt.Errorf("concurrency must be >= 1, got %d", cfg.Concurrency)
	}
	if cfg.Count <= 0 && cfg.Duration <= 0 {
		return RunResult{}, fmt.Errorf("either count or duration must be > 0")
	}
	if err := ValidateWarmupForOps([]string{cfg.Operation}, cfg.Warmup); err != nil {
		return RunResult{}, err
	}

	plaintext, err := RandomPlaintext(cfg.PayloadBytes)
	if err != nil {
		return RunResult{}, err
	}

	var pool []string
	switch cfg.Operation {
	case OpEncrypt:
		for i := 0; i < cfg.Warmup; i++ {
			if _, _, _, err := client.Encrypt(ctx, key, plaintext); err != nil {
				return RunResult{}, fmt.Errorf("warmup encrypt: %w", err)
			}
		}
	case OpDecrypt, OpRewrap:
		pool = make([]string, 0, cfg.Warmup)
		for i := 0; i < cfg.Warmup; i++ {
			ct, _, _, err := client.Encrypt(ctx, key, plaintext)
			if err != nil {
				return RunResult{}, fmt.Errorf("building ciphertext pool: %w", err)
			}
			pool = append(pool, ct)
		}
	default:
		return RunResult{}, fmt.Errorf("unknown operation %q", cfg.Operation)
	}

	call := func(i int) (time.Duration, error) {
		switch cfg.Operation {
		case OpEncrypt:
			_, _, lat, err := client.Encrypt(ctx, key, plaintext)
			return lat, err
		case OpDecrypt:
			_, _, lat, err := client.Decrypt(ctx, key, pool[i%len(pool)])
			return lat, err
		case OpRewrap:
			_, _, lat, err := client.Rewrap(ctx, key, pool[i%len(pool)])
			return lat, err
		default:
			return 0, fmt.Errorf("unknown operation %q", cfg.Operation)
		}
	}

	type workerOut struct {
		samples []time.Duration
		errs    int
		errMsgs []string
	}
	outs := make([]workerOut, cfg.Concurrency)

	useCount := cfg.Duration <= 0
	var remaining atomic.Int64
	if useCount {
		remaining.Store(int64(cfg.Count))
	}
	deadline := time.Now().Add(cfg.Duration)

	var seq atomic.Int64
	var wg sync.WaitGroup
	started := time.Now()

	for w := 0; w < cfg.Concurrency; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			out := &outs[idx]
			for {
				if ctx.Err() != nil {
					return
				}
				if useCount {
					if remaining.Add(-1) < 0 {
						return
					}
				} else if time.Now().After(deadline) {
					return
				}

				i := int(seq.Add(1))
				lat, err := call(i)
				if err != nil {
					out.errs++
					if len(out.errMsgs) < maxErrorSamples {
						out.errMsgs = append(out.errMsgs, err.Error())
					}
					continue
				}
				out.samples = append(out.samples, lat)
			}
		}(w)
	}
	wg.Wait()
	ended := time.Now()

	result := RunResult{Config: cfg, StartedAt: started, EndedAt: ended}
	for _, o := range outs {
		result.Samples = append(result.Samples, o.samples...)
		result.SuccessCount += len(o.samples)
		result.ErrorCount += o.errs
		if len(result.ErrorSamples) < maxErrorSamples {
			result.ErrorSamples = append(result.ErrorSamples, o.errMsgs...)
		}
	}
	if len(result.ErrorSamples) > maxErrorSamples {
		result.ErrorSamples = result.ErrorSamples[:maxErrorSamples]
	}
	return result, nil
}
