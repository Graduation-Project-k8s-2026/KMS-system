package bench_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

func TestExecute_EncryptFlow_Basic(t *testing.T) {
	srv := newFakeServer("demo")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	cfg := bench.RunConfig{
		Scenario: "basic", Operation: bench.OpEncrypt,
		PayloadBytes: 128, Concurrency: 3, Count: 30, Warmup: 2,
	}

	result, err := bench.Execute(context.Background(), client, "demo", cfg)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if result.SuccessCount != 30 {
		t.Errorf("SuccessCount = %d, want 30", result.SuccessCount)
	}
	if result.ErrorCount != 0 {
		t.Errorf("ErrorCount = %d, want 0, errors: %v", result.ErrorCount, result.ErrorSamples)
	}
	if len(result.Samples) != 30 {
		t.Errorf("len(Samples) = %d, want 30", len(result.Samples))
	}

	encryptCalls, _, _ := srv.counts()
	// warmup(2) + measured(30) = 32 encrypt calls total.
	if encryptCalls != 32 {
		t.Errorf("server saw %d encrypt calls, want 32 (2 warmup + 30 measured)", encryptCalls)
	}
}

// TestExecute_DecryptFlow_UsesCiphertextPool은 decrypt 측정이 warmup
// 단계에서 만든 암호문 풀만 재사용하고, 측정 요청마다 새로 암호화하지
// 않는지 확인한다 — "벤치 도구가 상태를 바꾸지 않는다"는 설계와, warmup
// 암호문 풀 재사용 설계를 검증한다.
func TestExecute_DecryptFlow_UsesCiphertextPool(t *testing.T) {
	srv := newFakeServer("demo")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	cfg := bench.RunConfig{
		Scenario: "basic", Operation: bench.OpDecrypt,
		PayloadBytes: 128, Concurrency: 2, Count: 20, Warmup: 3,
	}

	result, err := bench.Execute(context.Background(), client, "demo", cfg)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if result.SuccessCount != 20 {
		t.Errorf("SuccessCount = %d, want 20", result.SuccessCount)
	}

	encryptCalls, decryptCalls, _ := srv.counts()
	if encryptCalls != 3 {
		t.Errorf("server saw %d encrypt calls, want 3 (exactly the warmup pool, no more)", encryptCalls)
	}
	if decryptCalls != 20 {
		t.Errorf("server saw %d decrypt calls, want 20", decryptCalls)
	}
}

func TestExecute_RewrapFlow_UsesCiphertextPool(t *testing.T) {
	srv := newFakeServer("demo")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	cfg := bench.RunConfig{
		Scenario: "basic", Operation: bench.OpRewrap,
		PayloadBytes: 128, Concurrency: 2, Count: 10, Warmup: 2,
	}

	result, err := bench.Execute(context.Background(), client, "demo", cfg)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if result.SuccessCount != 10 {
		t.Errorf("SuccessCount = %d, want 10", result.SuccessCount)
	}
	encryptCalls, _, rewrapCalls := srv.counts()
	if encryptCalls != 2 {
		t.Errorf("server saw %d encrypt calls, want 2 (warmup pool)", encryptCalls)
	}
	if rewrapCalls != 10 {
		t.Errorf("server saw %d rewrap calls, want 10", rewrapCalls)
	}
}

// TestExecute_ConcurrencyReflected는 --concurrency로 지정한 worker 수가
// 실제로 서버에 동시 요청으로 도달하는지 확인한다. 서버가 요청마다 살짝
// 멈춰(sleep) 겹칠 시간을 벌어준다.
func TestExecute_ConcurrencyReflected(t *testing.T) {
	srv := newFakeServer("demo")
	srv.sleep = 20 * time.Millisecond
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	cfg := bench.RunConfig{
		Scenario: "concurrency", Operation: bench.OpEncrypt,
		PayloadBytes: 64, Concurrency: 5, Count: 25, Warmup: 0,
	}

	result, err := bench.Execute(context.Background(), client, "demo", cfg)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if result.SuccessCount != 25 {
		t.Fatalf("SuccessCount = %d, want 25", result.SuccessCount)
	}
	if srv.maxInFlight != 5 {
		t.Errorf("max observed in-flight requests = %d, want 5 (concurrency level)", srv.maxInFlight)
	}
}

// TestExecute_DurationMode_StopsAfterDuration는 --duration이 설정되면
// Count 대신 경과 시간으로 측정을 멈추는지 확인한다.
func TestExecute_DurationMode_StopsAfterDuration(t *testing.T) {
	srv := newFakeServer("demo")
	srv.sleep = 5 * time.Millisecond
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	cfg := bench.RunConfig{
		Scenario: "basic", Operation: bench.OpEncrypt,
		PayloadBytes: 64, Concurrency: 3, Duration: 150 * time.Millisecond, Warmup: 0,
	}

	result, err := bench.Execute(context.Background(), client, "demo", cfg)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	wall := result.EndedAt.Sub(result.StartedAt)
	if wall < 150*time.Millisecond {
		t.Errorf("wall time = %v, want >= 150ms", wall)
	}
	if wall > 500*time.Millisecond {
		t.Errorf("wall time = %v, want well under 500ms (duration was 150ms)", wall)
	}
	if result.SuccessCount == 0 {
		t.Error("SuccessCount = 0, want > 0")
	}
}

// TestExecute_ContextCancelledUpfront_StopsImmediately_NoError는 이미
// 취소된 ctx로 호출하면 요청을 전혀 보내지 않고 즉시(에러 없이) 돌아오는지
// 확인한다 — Ctrl+C로 중단했을 때 에러가 아니라 "그때까지의 결과"를
// 보여줘야 한다는 요구사항의 경계 조건이다.
func TestExecute_ContextCancelledUpfront_StopsImmediately_NoError(t *testing.T) {
	srv := newFakeServer("demo")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	cfg := bench.RunConfig{
		Scenario: "basic", Operation: bench.OpEncrypt,
		PayloadBytes: 64, Concurrency: 4, Count: 1000, Warmup: 0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := bench.Execute(ctx, client, "demo", cfg)
	if err != nil {
		t.Fatalf("Execute with pre-cancelled context returned error: %v", err)
	}
	if result.SuccessCount != 0 || result.ErrorCount != 0 {
		t.Errorf("expected no requests to be made, got success=%d error=%d", result.SuccessCount, result.ErrorCount)
	}
}

func TestExecute_WarmupFailure_ReturnsError(t *testing.T) {
	srv := newFakeServer("demo")
	srv.setSealed(true) // every request (including warmup) will 503
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	cfg := bench.RunConfig{
		Scenario: "basic", Operation: bench.OpEncrypt,
		PayloadBytes: 64, Concurrency: 1, Count: 10, Warmup: 1,
	}

	if _, err := bench.Execute(context.Background(), client, "demo", cfg); err == nil {
		t.Fatal("Execute succeeded despite sealed server, want error")
	}
}

func TestExecute_InvalidConcurrency(t *testing.T) {
	cfg := bench.RunConfig{Operation: bench.OpEncrypt, Concurrency: 0, Count: 10}
	if _, err := bench.Execute(context.Background(), nil, "demo", cfg); err == nil {
		t.Fatal("Execute with Concurrency=0 succeeded, want error")
	}
}

func TestExecute_InvalidCountAndDuration(t *testing.T) {
	cfg := bench.RunConfig{Operation: bench.OpEncrypt, Concurrency: 1, Count: 0, Duration: 0}
	if _, err := bench.Execute(context.Background(), nil, "demo", cfg); err == nil {
		t.Fatal("Execute with Count=0 and Duration=0 succeeded, want error")
	}
}

func TestExecute_DecryptWithoutWarmup_ReturnsError(t *testing.T) {
	cfg := bench.RunConfig{Operation: bench.OpDecrypt, Concurrency: 1, Count: 10, Warmup: 0}
	if _, err := bench.Execute(context.Background(), nil, "demo", cfg); err == nil {
		t.Fatal("Execute(decrypt, warmup=0) succeeded, want error")
	}
}
