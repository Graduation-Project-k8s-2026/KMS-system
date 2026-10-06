package dashboard

import (
	"math"
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, m fixedMetrics, at time.Time) Sample {
	t.Helper()
	s, err := parseSample(strings.NewReader(m.text()), at)
	if err != nil {
		t.Fatalf("parseSample: %v", err)
	}
	return s
}

func approx(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s = null, want %v", name, want)
	}
	if math.Abs(*got-want) > 1e-9 {
		t.Fatalf("%s = %v, want %v", name, *got, want)
	}
}

func TestParseSample_ExtractsValues(t *testing.T) {
	s := mustParse(t, metricsA, time.Unix(1000, 0))
	if s.Sealed == nil || *s.Sealed != 0 || *s.Keys != 3 || *s.KeyVersions != 7 || *s.LastUnseal != 1.7e9 {
		t.Fatalf("gauges not parsed: %+v", s)
	}
	enc := s.Ops["encrypt"]
	if enc == nil || enc.Success != 100 || enc.Error != 0 || enc.Dur.Count != 100 || len(enc.Dur.Buckets) != 3 {
		t.Fatalf("encrypt sample = %+v", enc)
	}
	if s.Ops["decrypt"] != nil || s.Ops["rewrap"] != nil {
		t.Fatal("decrypt/rewrap must be absent when never observed")
	}
	if s.Authz == nil || s.Authz.CacheHit != 10 || s.Authz.SAR.Count != 20 {
		t.Fatalf("authz sample = %+v", s.Authz)
	}
}

func TestParseSample_RejectsGarbage(t *testing.T) {
	if _, err := parseSample(strings.NewReader("kms_keys_total{ not prometheus\n"), time.Now()); err == nil {
		t.Fatal("garbage input must fail to parse")
	}
}

func TestParseSample_AuthzOffYieldsNoAuthz(t *testing.T) {
	m := metricsA
	m.withAuthz, m.sarCount, m.sarSum, m.rttCount, m.rttSum = false, 0, 0, 0, 0
	if s := mustParse(t, m, time.Now()); s.Authz != nil {
		t.Fatalf("authz = %+v, want nil when authorization was never used", s.Authz)
	}
}

func TestComputeTraffic_RatesAndPercentiles(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	a := mustParse(t, metricsA, t0)
	b := mustParse(t, metricsB, t0.Add(10*time.Second))

	tr := computeTraffic([]Sample{a, b}, 5*time.Minute, 5*time.Second)
	if len(tr.T) != 1 || tr.T[0] != t0.Add(10*time.Second).Unix() {
		t.Fatalf("T = %v", tr.T)
	}

	enc := tr.Ops["encrypt"]
	if enc == nil {
		t.Fatal("encrypt series missing")
	}
	approx(t, "rps", enc.RPS[0], 22)                      // (200+20)/10s
	approx(t, "error_rate", enc.ErrorRate[0], 20.0/220.0) //
	approx(t, "p50_ms", enc.P50ms[0], 1.9)                // 0.001 + 0.009*(110-100)/(200-100)
	approx(t, "p99_ms", enc.P99ms[0], 100)                // 상위 1%가 마지막 유한 버킷 밖 → 상한으로 대체
	if tr.Ops["decrypt"] != nil || tr.Ops["rewrap"] != nil {
		t.Fatal("never-observed operations must be null")
	}

	az := tr.Authz
	if az == nil {
		t.Fatal("authz series missing")
	}
	approx(t, "cache_hit_ratio", az.CacheHitRatio[0], 0.75) // 30/(30+10)
	approx(t, "sar_rps", az.SARRPS[0], 2)                   // 20콜/10s
	approx(t, "sar_avg_ms", az.SARAvgMs[0], 10)             // 0.2s/20
	approx(t, "apiserver_rtt_avg_ms", az.APIServerRTTAvgMs[0], 6)
	approx(t, "client_wait_avg_ms", az.ClientWaitAvgMs[0], 4)
}

func TestComputeTraffic_NoAuthzIsNull(t *testing.T) {
	m := metricsA
	m.withAuthz, m.sarCount, m.sarSum, m.rttCount, m.rttSum = false, 0, 0, 0, 0
	t0 := time.Unix(1_000_000, 0)
	tr := computeTraffic([]Sample{mustParse(t, m, t0), mustParse(t, m, t0.Add(5*time.Second))}, time.Minute, 5*time.Second)
	if tr.Authz != nil {
		t.Fatalf("authz = %+v, want null", tr.Authz)
	}
}

func TestComputeTraffic_CounterResetAndIdleAreNull(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	a := mustParse(t, metricsB, t0)
	// 서버 재시작: 카운터가 작아졌다.
	reset := mustParse(t, metricsA, t0.Add(5*time.Second))
	// 이후 5초 동안 요청 없음.
	idle := mustParse(t, metricsA, t0.Add(10*time.Second))

	tr := computeTraffic([]Sample{a, reset, idle}, time.Minute, 5*time.Second)
	enc := tr.Ops["encrypt"]
	if enc.RPS[0] != nil || enc.P50ms[0] != nil || enc.ErrorRate[0] != nil {
		t.Fatal("a counter reset must yield null, not a negative rate")
	}
	approx(t, "idle rps", enc.RPS[1], 0)
	if enc.ErrorRate[1] != nil || enc.P99ms[1] != nil {
		t.Fatal("no requests in the interval => error rate and percentiles are null")
	}
	if tr.Authz.CacheHitRatio[1] != nil || tr.Authz.SARAvgMs[1] != nil {
		t.Fatal("no authz traffic => ratio/average are null")
	}
}

func TestComputeTraffic_TooFewSamples(t *testing.T) {
	tr := computeTraffic([]Sample{mustParse(t, metricsA, time.Now())}, time.Minute, 5*time.Second)
	if len(tr.T) != 0 {
		t.Fatalf("T = %v, want empty", tr.T)
	}
}
