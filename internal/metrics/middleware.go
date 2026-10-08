package metrics

import (
	"net/http"
	"time"
)

// statusCapturingWriter는 핸들러가 실제로 보낸 상태 코드를 옆에서
// 기록해두는 http.ResponseWriter 래퍼다. 핸들러가 WriteHeader를 한 번도
// 부르지 않으면(암묵적 200) status는 초기값 200을 그대로 유지한다.
type statusCapturingWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCapturingWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// InstrumentTransit(operation)은 encrypt/decrypt/rewrap 라우트마다
// 하나씩 붙이는 계측 미들웨어다. 핸들러 코드를 전혀 건드리지 않고 요청
// 수(operation, result별)와 처리 시간을 기록한다 — result는 응답 상태
// 코드가 400 이상이면 "error", 아니면 "success"로 판정한다. 키 이름은
// 요청 경로에 있지만 라벨로 쓰지 않는다(cardinality/정보 노출 방지 —
// 패키지 최상단 주석 참고).
func InstrumentTransit(operation string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusCapturingWriter{ResponseWriter: w, status: http.StatusOK}
			start := time.Now()

			next.ServeHTTP(sw, r)

			TransitRequestDuration.WithLabelValues(operation).Observe(time.Since(start).Seconds())

			result := "success"
			if sw.status >= 400 {
				result = "error"
			}
			TransitRequestsTotal.WithLabelValues(operation, result).Inc()
		})
	}
}
