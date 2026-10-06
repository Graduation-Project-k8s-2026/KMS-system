package dashboard

import (
	"fmt"
	"strings"
)

// fixedMetrics는 테스트용 고정 /metrics 텍스트를 만든다. 값은 손으로 검산할
// 수 있게 고른 것이다(traffic_test.go 참고).
type fixedMetrics struct {
	sealed, keys, versions, lastUnseal float64

	encOK, encErr float64
	// encrypt 지연 히스토그램: le=0.001, 0.01, 0.1 누적, 전체 개수, 합
	encB1, encB2, encB3, encCount, encSum float64

	withAuthz                          bool
	hit, miss                          float64
	sarCount, sarSum, rttCount, rttSum float64
}

func (m fixedMetrics) text() string {
	var b strings.Builder
	gauge := func(name string, v float64) {
		fmt.Fprintf(&b, "# TYPE %s gauge\n%s %g\n", name, name, v)
	}
	gauge("kms_seal_sealed", m.sealed)
	gauge("kms_seal_last_unsealed_timestamp_seconds", m.lastUnseal)
	gauge("kms_keys_total", m.keys)
	gauge("kms_key_versions_total", m.versions)

	fmt.Fprintf(&b, "# TYPE kms_transit_requests_total counter\n")
	fmt.Fprintf(&b, "kms_transit_requests_total{operation=\"encrypt\",result=\"success\"} %g\n", m.encOK)
	fmt.Fprintf(&b, "kms_transit_requests_total{operation=\"encrypt\",result=\"error\"} %g\n", m.encErr)
	fmt.Fprintf(&b, "# TYPE kms_transit_request_duration_seconds histogram\n")
	n := "kms_transit_request_duration_seconds"
	fmt.Fprintf(&b, "%s_bucket{operation=\"encrypt\",le=\"0.001\"} %g\n", n, m.encB1)
	fmt.Fprintf(&b, "%s_bucket{operation=\"encrypt\",le=\"0.01\"} %g\n", n, m.encB2)
	fmt.Fprintf(&b, "%s_bucket{operation=\"encrypt\",le=\"0.1\"} %g\n", n, m.encB3)
	fmt.Fprintf(&b, "%s_bucket{operation=\"encrypt\",le=\"+Inf\"} %g\n", n, m.encCount)
	fmt.Fprintf(&b, "%s_sum{operation=\"encrypt\"} %g\n%s_count{operation=\"encrypt\"} %g\n", n, m.encSum, n, m.encCount)

	hist := func(name string, count, sum float64) {
		fmt.Fprintf(&b, "# TYPE %s histogram\n", name)
		fmt.Fprintf(&b, "%s_bucket{le=\"0.005\"} %g\n%s_bucket{le=\"+Inf\"} %g\n", name, count/2, name, count)
		fmt.Fprintf(&b, "%s_sum %g\n%s_count %g\n", name, sum, name, count)
	}
	// 인가를 꺼도 히스토그램은 0으로 노출된다 — 그 경우를 흉내 낸다.
	hist("kms_authz_sar_duration_seconds", m.sarCount, m.sarSum)
	hist("kms_authz_apiserver_roundtrip_seconds", m.rttCount, m.rttSum)
	if m.withAuthz {
		fmt.Fprintf(&b, "# TYPE kms_authz_cache_requests_total counter\n")
		fmt.Fprintf(&b, "kms_authz_cache_requests_total{result=\"hit\"} %g\n", m.hit)
		fmt.Fprintf(&b, "kms_authz_cache_requests_total{result=\"miss\"} %g\n", m.miss)
	}
	return b.String()
}

var (
	metricsA = fixedMetrics{
		sealed: 0, keys: 3, versions: 7, lastUnseal: 1.7e9,
		encOK: 100, encErr: 0,
		encB1: 50, encB2: 90, encB3: 100, encCount: 100, encSum: 0.5,
		withAuthz: true, hit: 10, miss: 10,
		sarCount: 20, sarSum: 0.1, rttCount: 20, rttSum: 0.06,
	}
	// A로부터 10초 뒤. encrypt는 성공 200건·오류 20건이 늘었다.
	metricsB = fixedMetrics{
		sealed: 0, keys: 3, versions: 7, lastUnseal: 1.7e9,
		encOK: 300, encErr: 20,
		encB1: 150, encB2: 290, encB3: 315, encCount: 320, encSum: 2.5,
		withAuthz: true, hit: 40, miss: 20,
		sarCount: 40, sarSum: 0.3, rttCount: 40, rttSum: 0.18,
	}
)
