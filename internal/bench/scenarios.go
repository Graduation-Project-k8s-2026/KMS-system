package bench

import (
	"fmt"
	"time"
)

// 측정 시나리오 이름.
const (
	ScenarioBasic       = "basic"
	ScenarioPayload     = "payload"
	ScenarioConcurrency = "concurrency"
	ScenarioAll         = "all"
)

// ResolveOps는 --op 값을 실제 측정할 operation 목록으로 바꾼다.
// "all"이면 encrypt/decrypt/rewrap 전부(이 순서대로)를 반환한다.
func ResolveOps(op string) ([]string, error) {
	switch op {
	case OpEncrypt, OpDecrypt, OpRewrap:
		return []string{op}, nil
	case ScenarioAll, "":
		return append([]string(nil), AllOps...), nil
	default:
		return nil, fmt.Errorf("unknown op %q; want encrypt|decrypt|rewrap|all", op)
	}
}

// BenchConfig는 scenario 전체에 공통으로 적용되는 파라미터를 모은다 —
// 어떤 scenario를 고르든 이 값들로 RunConfig 목록을 만든다.
type BenchConfig struct {
	Ops []string

	Count    int
	Duration time.Duration

	BaselineConcurrency int   // basic/payload 시나리오가 쓰는 고정 동시성
	ConcurrencyLevels   []int // concurrency 시나리오가 훑는 동시성 집합

	BaselinePayload int   // basic/concurrency 시나리오가 쓰는 고정 페이로드 크기
	PayloadSizes    []int // payload 시나리오가 훑는 페이로드 크기 집합

	Warmup    int
	Keepalive bool
}

// BuildRunConfigs는 scenario와 cfg로부터 실제로 수행할 RunConfig 목록을
// 만든다. "all"은 basic/payload/concurrency를 순서대로 이어붙인 것이다.
func BuildRunConfigs(scenario string, cfg BenchConfig) ([]RunConfig, error) {
	base := func(s string, operation string, payload, concurrency int) RunConfig {
		return RunConfig{
			Scenario:     s,
			Operation:    operation,
			PayloadBytes: payload,
			Concurrency:  concurrency,
			Count:        cfg.Count,
			Duration:     cfg.Duration,
			Warmup:       cfg.Warmup,
			Keepalive:    cfg.Keepalive,
		}
	}

	var runs []RunConfig
	addBasic := func() {
		for _, op := range cfg.Ops {
			runs = append(runs, base(ScenarioBasic, op, cfg.BaselinePayload, cfg.BaselineConcurrency))
		}
	}
	addPayload := func() {
		for _, op := range cfg.Ops {
			for _, sz := range cfg.PayloadSizes {
				runs = append(runs, base(ScenarioPayload, op, sz, cfg.BaselineConcurrency))
			}
		}
	}
	addConcurrency := func() {
		for _, op := range cfg.Ops {
			for _, c := range cfg.ConcurrencyLevels {
				runs = append(runs, base(ScenarioConcurrency, op, cfg.BaselinePayload, c))
			}
		}
	}

	switch scenario {
	case ScenarioBasic:
		addBasic()
	case ScenarioPayload:
		addPayload()
	case ScenarioConcurrency:
		addConcurrency()
	case ScenarioAll:
		addBasic()
		addPayload()
		addConcurrency()
	default:
		return nil, fmt.Errorf("unknown scenario %q; want basic|payload|concurrency|all", scenario)
	}
	return runs, nil
}
