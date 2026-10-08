package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewHandler는 /metrics 하나만 서빙하는 핸들러를 만든다 — 그 외 경로는
// http.ServeMux의 기본 동작대로 404가 된다. promhttp.Handler()는
// prometheus.DefaultRegisterer/DefaultGatherer를 쓴다 — 이 패키지의
// promauto 지표들과, cmd/server가 등록하는 Go/Process collector·
// SealKeyCollector가 모두 거기 등록되므로 별도로 넘겨줄 게 없다.
func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}
