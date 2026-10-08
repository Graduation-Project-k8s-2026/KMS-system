package metrics_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	dto "github.com/prometheus/client_model/go"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// histogramSampleCount는 HistogramVec의 특정 라벨 조합에 지금까지 몇 건이
// 관측됐는지를 읽는다. Histogram은 버킷/합계/건수를 한꺼번에 담은 단일
// dto.Metric으로 직렬화되므로(testutil.ToFloat64은 Gauge/Counter/Untyped만
// 지원해 여기 쓸 수 없다), Collect로 그 Metric 하나를 직접 꺼내 Write한다.
func histogramSampleCount(t *testing.T, h prometheus.Observer) uint64 {
	t.Helper()
	collector, ok := h.(prometheus.Collector)
	if !ok {
		t.Fatalf("observer %T does not implement prometheus.Collector", h)
	}

	ch := make(chan prometheus.Metric, 1)
	collector.Collect(ch)
	close(ch)

	m := <-ch
	pb := &dto.Metric{}
	if err := m.Write(pb); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	return pb.GetHistogram().GetSampleCount()
}

// TestInstrumentTransit_SuccessIncrementsSuccessCounterAndDuration은 200을
// 반환하는 핸들러를 감싸면 requests_total{result="success"}가 늘고,
// request_duration_seconds에도 관측치가 기록되는지 확인한다.
func TestInstrumentTransit_SuccessIncrementsSuccessCounterAndDuration(t *testing.T) {
	duration := metrics.TransitRequestDuration.WithLabelValues("encrypt")
	before := testutil.ToFloat64(metrics.TransitRequestsTotal.WithLabelValues("encrypt", "success"))
	beforeCount := histogramSampleCount(t, duration)

	handler := metrics.InstrumentTransit("encrypt")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/encrypt/app", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	after := testutil.ToFloat64(metrics.TransitRequestsTotal.WithLabelValues("encrypt", "success"))
	if after-before != 1 {
		t.Fatalf("requests_total{encrypt,success} delta = %v, want 1", after-before)
	}

	afterCount := histogramSampleCount(t, duration)
	if afterCount-beforeCount != 1 {
		t.Fatalf("request_duration_seconds_count{encrypt} delta = %d, want 1", afterCount-beforeCount)
	}
}

// TestInstrumentTransit_ErrorIncrementsErrorCounter는 400 이상을 반환하는
// 핸들러를 감싸면 requests_total{result="error"}가 늘어나는지 확인한다.
func TestInstrumentTransit_ErrorIncrementsErrorCounter(t *testing.T) {
	before := testutil.ToFloat64(metrics.TransitRequestsTotal.WithLabelValues("decrypt", "error"))

	handler := metrics.InstrumentTransit("decrypt")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/decrypt/app", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	after := testutil.ToFloat64(metrics.TransitRequestsTotal.WithLabelValues("decrypt", "error"))
	if after-before != 1 {
		t.Fatalf("requests_total{decrypt,error} delta = %v, want 1", after-before)
	}
}
