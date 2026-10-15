package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// Denials can terminate before the Transit operation middleware runs. The outer
// observer must preserve their responses and expose them to Prometheus anyway.
func TestAllHTTPIncludesAuthenticationSealedAndBackendFailures(t *testing.T) {
	counts := func() map[string]float64 {
		families, err := prometheus.DefaultGatherer.Gather()
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]float64{}
		for _, family := range families {
			if family.GetName() != "kms_http_requests_total" {
				continue
			}
			for _, metric := range family.Metric {
				if len(metric.Label) != 1 || metric.Label[0].GetName() != "code" {
					t.Fatal("unbounded identity or key label")
				}
				out[metric.Label[0].GetValue()] = metric.GetCounter().GetValue()
			}
		}
		return out
	}
	before := counts()
	for _, code := range []int{200, 401, 403, 503, 500} {
		handler := metrics.AllHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", "/v1/encrypt/fixture", nil))
		if w.Code != code {
			t.Fatal("observer changed response")
		}
	}
	after := counts()
	for _, code := range []int{200, 401, 403, 503, 500} {
		label := strconv.Itoa(code)
		if after[label] != before[label]+1 {
			t.Fatalf("missing status %d in Prometheus counter", code)
		}
	}
}
