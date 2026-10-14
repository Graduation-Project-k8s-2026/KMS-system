package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"net/http"
	"strconv"
)

var httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{Name: "kms_http_requests_total", Help: "All Transit requests including authentication, sealed and backend failures."}, []string{"code"})

func AllHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusCapturingWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		httpRequests.WithLabelValues(strconv.Itoa(sw.status)).Inc()
	})
}
