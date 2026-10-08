// cmd/bench: KMS Transit API에 인위적으로 부하를 걸어 처리량·지연을
// 측정하는 로컬 실행 CLI. internal/metrics(Prometheus)가 "운영 중 무슨 일이
// 일어났는가"를 수동적으로 기록한다면, 이 도구는 조건을 통제한 상태에서
// 능동적으로 부하를 걸어 측정한다 — 논문 성능 평가용 데이터 생산이 목적이다.
//
// 이 도구는 Transit API(:8200)만 HTTP로 호출하는 외부 클라이언트다. Admin
// 평면(유닉스 소켓)에는 접근하지 않고, 서버 설정을 바꾸거나 키를 만들지
// 않는다 — "측정만 하고 상태는 바꾸지 않는다"는 원칙을 지킨다.
//
// 접근 제어 오버헤드 비교(authn/authz on/off, 캐시 적중/미스)는 이 도구가
// 서버를 재기동하지 않는다 — 각 조건으로 서버를 띄운 뒤 --label로 조건을
// 표시해 이 도구를 네 번 실행하고, 그 결과를 나중에 비교한다. 운영 절차는
// docs/benchmark.md 참고.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flagHelpRequested) {
			return nil
		}
		return err
	}

	maxConc := cfg.BaselineConcurrency
	for _, c := range cfg.ConcurrencyLevels {
		if c > maxConc {
			maxConc = c
		}
	}
	transport := &http.Transport{
		DisableKeepAlives:   !cfg.Keepalive,
		MaxIdleConnsPerHost: maxConc,
	}
	httpClient := &http.Client{Transport: transport, Timeout: cfg.Timeout}
	client := bench.NewClient(cfg.Addr, cfg.Token, httpClient)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := bench.Preflight(ctx, client, cfg.Key); err != nil {
		return err
	}

	runConfigs, err := bench.BuildRunConfigs(cfg.Scenario, bench.BenchConfig{
		Ops:                 cfg.Ops,
		Count:               cfg.Count,
		Duration:            cfg.Duration,
		BaselineConcurrency: cfg.BaselineConcurrency,
		ConcurrencyLevels:   cfg.ConcurrencyLevels,
		BaselinePayload:     cfg.BaselinePayload,
		PayloadSizes:        cfg.PayloadSizes,
		Warmup:              cfg.Warmup,
		Keepalive:           cfg.Keepalive,
	})
	if err != nil {
		return err
	}

	report := bench.Report{
		Label:       cfg.Label,
		Timestamp:   time.Now(),
		Addr:        cfg.Addr,
		Key:         cfg.Key,
		Environment: bench.CollectEnvironment(),
	}

	for _, rc := range runConfigs {
		if ctx.Err() != nil {
			fmt.Fprintln(stderr, "bench: interrupted — stopping before the next run, reporting what was collected so far")
			break
		}
		fmt.Fprintf(stderr, "bench: running %s/%s payload=%s concurrency=%d...\n",
			rc.Scenario, rc.Operation, bench.FormatSize(rc.PayloadBytes), rc.Concurrency)

		result, err := bench.Execute(ctx, client, cfg.Key, rc)
		if err != nil {
			return fmt.Errorf("run %s/%s payload=%s concurrency=%d: %w",
				rc.Scenario, rc.Operation, bench.FormatSize(rc.PayloadBytes), rc.Concurrency, err)
		}
		report.Runs = append(report.Runs, bench.NewRunReport(result))
	}

	writeErr := writeReport(cfg, report, stdout)

	// 제출은 측정 결과 출력·저장이 끝난 뒤에 한다. 실패해도 이미 만든
	// 결과는 그대로이고, 경고만 남긴다.
	if cfg.Submit != "" {
		submitCtx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
		id, err := bench.Submit(submitCtx, &http.Client{Timeout: cfg.Timeout}, cfg.Submit, report)
		cancel()
		if err != nil {
			fmt.Fprintf(stderr, "bench: warning: --submit to %s failed: %v (results above are unaffected)\n", cfg.Submit, err)
		} else {
			fmt.Fprintf(stderr, "bench: submitted result %q to %s\n", id, cfg.Submit)
		}
	}
	return writeErr
}

// writeReport는 --output 파일(없으면 stdout)에 --format 형식으로 결과를 쓴다.
func writeReport(cfg cliConfig, report bench.Report, stdout io.Writer) error {
	out := stdout
	if cfg.Output != "" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			return fmt.Errorf("--output: %w", err)
		}
		defer f.Close()
		out = f
	}
	if cfg.Format == "json" {
		return bench.WriteJSON(out, report)
	}
	return bench.WriteTable(out, report)
}

var flagHelpRequested = errors.New("help requested")

// cliConfig는 파싱되고 검증된 플래그 값을 담는다. parseFlags는 네트워크
// 호출을 전혀 하지 않으므로 서버 없이도 전부 테스트할 수 있다.
type cliConfig struct {
	Addr string
	Key  string

	Scenario string
	Ops      []string

	Count    int
	Duration time.Duration

	BaselineConcurrency int
	ConcurrencyLevels   []int

	BaselinePayload int
	PayloadSizes    []int

	Warmup int

	Token string

	Label  string
	Format string
	Output string

	// Submit: 결과를 제출할 관리 API 주소(빈 값이면 제출 안 함).
	Submit string

	Keepalive bool
	Timeout   time.Duration
}

func parseFlags(args []string, stderr io.Writer) (cliConfig, error) {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(stderr)

	addr := fs.String("addr", "http://localhost:8200", "Transit API base URL")
	key := fs.String("key", "", "key name to benchmark (required; bench does not create it)")
	scenario := fs.String("scenario", bench.ScenarioBasic, "scenario: basic|payload|concurrency|all")
	op := fs.String("op", "all", "operation: encrypt|decrypt|rewrap|all")
	count := fs.Int("count", 1000, "number of measured requests per run (ignored if --duration > 0)")
	duration := fs.Duration("duration", 0, "measure for this long instead of a fixed count (e.g. 10s)")
	concurrency := fs.Int("concurrency", 1, "baseline concurrency used by the basic/payload scenarios")
	concurrencyLevels := fs.String("concurrency-levels", "1,10,50,100", "concurrency levels swept by the concurrency scenario")
	payload := fs.String("payload", "1KB", "baseline payload size used by the basic/concurrency scenarios")
	payloadSizes := fs.String("payload-sizes", "1KB,10KB,100KB,1MB", "payload sizes swept by the payload scenario")
	warmup := fs.Int("warmup", 20, "warmup requests discarded before measuring (also builds the ciphertext pool for decrypt/rewrap)")
	token := fs.String("token", "", "bearer token to send (mutually exclusive with --token-file)")
	tokenFile := fs.String("token-file", "", "path to a file containing the bearer token")
	label := fs.String("label", "", "free-form condition label attached to the output (e.g. \"authz-cached\")")
	format := fs.String("format", "table", "output format: table|json")
	output := fs.String("output", "", "output file path (default: stdout)")
	submit := fs.String("submit", "", "admin API base URL (e.g. http://localhost:8201); after measuring, POST the JSON result to /api/bench/results. A failed submit only prints a warning")
	keepalive := fs.Bool("keepalive", true, "reuse HTTP connections (disable to measure the cost of a fresh connection per request)")
	timeout := fs.Duration("timeout", 30*time.Second, "per-request HTTP timeout")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cliConfig{}, flagHelpRequested
		}
		return cliConfig{}, err
	}

	if *key == "" {
		return cliConfig{}, errors.New("--key is required")
	}

	ops, err := bench.ResolveOps(*op)
	if err != nil {
		return cliConfig{}, err
	}

	switch *scenario {
	case bench.ScenarioBasic, bench.ScenarioPayload, bench.ScenarioConcurrency, bench.ScenarioAll:
	default:
		return cliConfig{}, fmt.Errorf("unknown --scenario %q; want basic|payload|concurrency|all", *scenario)
	}

	if err := bench.ValidateWarmupForOps(ops, *warmup); err != nil {
		return cliConfig{}, err
	}

	if *concurrency < 1 {
		return cliConfig{}, errors.New("--concurrency must be >= 1")
	}
	if *count <= 0 && *duration <= 0 {
		return cliConfig{}, errors.New("either --count or --duration must be > 0")
	}
	if *format != "table" && *format != "json" {
		return cliConfig{}, fmt.Errorf("unknown --format %q; want table|json", *format)
	}
	if *token != "" && *tokenFile != "" {
		return cliConfig{}, errors.New("--token and --token-file are mutually exclusive")
	}

	baselinePayload, err := bench.ParseSize(*payload)
	if err != nil {
		return cliConfig{}, fmt.Errorf("--payload: %w", err)
	}
	payloadSizesParsed, err := bench.ParseSizeList(*payloadSizes)
	if err != nil {
		return cliConfig{}, fmt.Errorf("--payload-sizes: %w", err)
	}
	concurrencyLevelsParsed, err := bench.ParseIntList(*concurrencyLevels)
	if err != nil {
		return cliConfig{}, fmt.Errorf("--concurrency-levels: %w", err)
	}

	submitURL := ""
	if *submit != "" {
		submitURL, err = bench.ParseSubmitURL(*submit)
		if err != nil {
			return cliConfig{}, fmt.Errorf("--submit: %w", err)
		}
	}

	resolvedToken := *token
	if *tokenFile != "" {
		data, err := os.ReadFile(*tokenFile)
		if err != nil {
			return cliConfig{}, fmt.Errorf("--token-file: %w", err)
		}
		resolvedToken = strings.TrimSpace(string(data))
	}

	return cliConfig{
		Addr:                *addr,
		Key:                 *key,
		Scenario:            *scenario,
		Ops:                 ops,
		Count:               *count,
		Duration:            *duration,
		BaselineConcurrency: *concurrency,
		ConcurrencyLevels:   concurrencyLevelsParsed,
		BaselinePayload:     baselinePayload,
		PayloadSizes:        payloadSizesParsed,
		Warmup:              *warmup,
		Token:               resolvedToken,
		Label:               *label,
		Format:              *format,
		Output:              *output,
		Submit:              submitURL,
		Keepalive:           *keepalive,
		Timeout:             *timeout,
	}, nil
}
