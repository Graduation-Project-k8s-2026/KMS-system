package authz

import (
	"errors"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"k8s.io/client-go/rest"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// TestApplyRateLimit_Zero_UsesDefaults는 QPS/Burst를 0으로(설정 안 함)
// 주면 rest.Config에 DefaultQPS/DefaultBurst가 반영되는지 확인한다 —
// internal/authz 안에서만 알 수 있는 *rest.Config 필드를 직접 들여다보기
// 위해 이 파일은 (authz_test가 아니라) authz 패키지 안에 둔다.
func TestApplyRateLimit_Zero_UsesDefaults(t *testing.T) {
	cfg := &rest.Config{}
	applyRateLimit(cfg, 0, 0)

	if cfg.QPS != DefaultQPS {
		t.Errorf("cfg.QPS = %v, want %v (default)", cfg.QPS, DefaultQPS)
	}
	if cfg.Burst != DefaultBurst {
		t.Errorf("cfg.Burst = %v, want %v (default)", cfg.Burst, DefaultBurst)
	}
	if cfg.RateLimiter != nil {
		t.Error("cfg.RateLimiter should be nil so client-go builds its own token-bucket limiter from QPS/Burst")
	}
}

// TestApplyRateLimit_Positive_UsesGivenValues는 양수 QPS/Burst가 그대로
// rest.Config에 반영되는지 확인한다.
func TestApplyRateLimit_Positive_UsesGivenValues(t *testing.T) {
	cfg := &rest.Config{}
	applyRateLimit(cfg, 75, 150)

	if cfg.QPS != 75 {
		t.Errorf("cfg.QPS = %v, want 75", cfg.QPS)
	}
	if cfg.Burst != 150 {
		t.Errorf("cfg.Burst = %v, want 150", cfg.Burst)
	}
}

// TestApplyRateLimit_Negative_DisablesViaRateLimiter는 QPS 또는 Burst가
// 음수면 cfg.RateLimiter가 설정되어(QPS/Burst 필드를 완전히 무시시킴)
// 속도 제한이 꺼지는지 확인한다.
func TestApplyRateLimit_Negative_DisablesViaRateLimiter(t *testing.T) {
	cases := []struct {
		name       string
		qps        float32
		burst      int
	}{
		{"negative QPS", -1, 100},
		{"negative burst", 50, -1},
		{"both negative", -1, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &rest.Config{}
			applyRateLimit(cfg, tc.qps, tc.burst)

			if cfg.RateLimiter == nil {
				t.Fatal("cfg.RateLimiter should be set to disable rate limiting")
			}
			// RateLimiter가 설정되면 client-go는 QPS/Burst를 완전히
			// 무시하므로, 테스트는 그 사실 자체(RateLimiter != nil)만
			// 확인하면 충분하다. NewFakeAlwaysRateLimiter는 즉시 통과시키는지
			// 그 자체로 검증한다.
			if !cfg.RateLimiter.TryAccept() {
				t.Error("disabled rate limiter should always accept immediately")
			}
		})
	}
}

// fakeRoundTripper는 실제 네트워크 호출 없이 instrumentTransport를 테스트
//하기 위한 최소한의 http.RoundTripper다.
type fakeRoundTripper struct {
	resp *http.Response
	err  error
}

func (f *fakeRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return f.resp, f.err
}

// histogramSampleCount는 Histogram의 현재 관측 개수(_count)를 읽는다.
// testutil.ToFloat64는 값이 하나뿐인 Counter/Gauge용이라 Histogram에는
// 쓸 수 없으므로, Write(*dto.Metric)으로 직접 꺼낸다.
func histogramSampleCount(t *testing.T, h prometheus.Histogram) uint64 {
	t.Helper()
	var m dto.Metric
	if err := h.Write(&m); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	return m.GetHistogram().GetSampleCount()
}

// TestInstrumentTransport_RecordsRoundtripDuration은 instrumentTransport가
// 감싼 RoundTripper를 그대로 호출하고(응답/에러를 바꾸지 않고), 그 호출
// 하나당 kms_authz_apiserver_roundtrip_seconds의 관측 개수가 정확히 1만큼
// 늘어나는지 확인한다.
func TestInstrumentTransport_RecordsRoundtripDuration(t *testing.T) {
	before := histogramSampleCount(t, metrics.AuthzAPIServerRoundtripDuration)

	wantResp := &http.Response{StatusCode: http.StatusOK}
	rt := instrumentTransport(&fakeRoundTripper{resp: wantResp})

	gotResp, err := rt.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatalf("RoundTrip returned error: %v", err)
	}
	if gotResp != wantResp {
		t.Fatal("RoundTrip should pass through the wrapped response unchanged")
	}

	after := histogramSampleCount(t, metrics.AuthzAPIServerRoundtripDuration)
	if after != before+1 {
		t.Fatalf("sample count = %d, want %d", after, before+1)
	}
}

// TestInstrumentTransport_PassesThroughError는 아래 RoundTripper가 에러를
// 반환하면 instrumentTransport도 그 에러를 그대로 전달하는지(삼키지 않는지)
// 확인한다.
func TestInstrumentTransport_PassesThroughError(t *testing.T) {
	wantErr := errors.New("connection refused")
	rt := instrumentTransport(&fakeRoundTripper{err: wantErr})

	_, err := rt.RoundTrip(&http.Request{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("RoundTrip error = %v, want %v", err, wantErr)
	}
}
