package transit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
)

type auditCtxKey struct{}

// AnnotateAudit: 핸들러가 감사 기록에만 남기고 응답에는 숨기는 설명을 붙인다
// (예: 최소 복호화 버전 거부의 키 버전 숫자). 감사가 꺼져 있으면 아무 일도 하지 않는다.
func AnnotateAudit(r *http.Request, detail string) {
	if e, ok := r.Context().Value(auditCtxKey{}).(*audit.TransitEvent); ok {
		e.Detail = detail
	}
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// auditMiddleware는 Transit 요청 하나를 비동기 감사 기록으로 남긴다. log가 nil이면 통과용이다.
// 인증 미들웨어 뒤, 인가 미들웨어 앞에 놓는다: 주체를 알 수 있으면서 403/503 거부도 기록된다.
// (인증 실패 401은 주체가 없어 여기 오지 못한다 — kms_transit_requests_total 지표로 센다.)
// 요청 본문·토큰은 읽지도 저장하지도 않는다.
func auditMiddleware(l *audit.TransitLog, op string) func(http.Handler) http.Handler {
	if l == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			key := chi.URLParam(r, "name")
			subject := "anonymous"
			if id, ok := authn.IdentityFromContext(r.Context()); ok {
				subject = id.Subject
			}
			ns, _ := authz.JudgedNamespace(key) // 형식 오류면 ""
			var rid [8]byte
			_, _ = rand.Read(rid[:])
			ev := &audit.TransitEvent{RequestID: hex.EncodeToString(rid[:]), Subject: subject, Action: op, Key: key, SARNamespace: ns}
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			sw.Header().Set("X-Request-ID", ev.RequestID)
			next.ServeHTTP(sw, r.WithContext(context.WithValue(r.Context(), auditCtxKey{}, ev)))
			ev.Status = sw.status
			ev.LatencyMs = float64(time.Since(start).Microseconds()) / 1000
			l.Record(*ev)
		})
	}
}
