package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// TestHandler_MetricsEndpoint_ReturnsPrometheusText는 /metrics가 200과
// Prometheus 텍스트 포맷("# HELP"/"# TYPE" 라인이 있는 형식)을 반환하는지
// 확인한다.
func TestHandler_MetricsEndpoint_ReturnsPrometheusText(t *testing.T) {
	srv := httptest.NewServer(metrics.NewHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body failed: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "# HELP") || !strings.Contains(text, "# TYPE") {
		t.Fatalf("body does not look like Prometheus text format (missing # HELP/# TYPE):\n%s", text)
	}
	if !strings.Contains(text, "go_goroutines") {
		t.Fatal("body missing Go runtime metrics (go_goroutines) — expected via client_golang's default-registered collectors")
	}
}

// TestHandler_OtherPaths_Return404는 /metrics 이외의 경로가 전부 404인지
// 확인한다.
func TestHandler_OtherPaths_Return404(t *testing.T) {
	srv := httptest.NewServer(metrics.NewHandler())
	defer srv.Close()

	for _, path := range []string{"/", "/healthz", "/foo", "/metrics/"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s status = %d, want %d", path, resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}
