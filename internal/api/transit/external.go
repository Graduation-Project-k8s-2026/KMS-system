package transit

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/httputil"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// ExternalConfig는 외부(인터넷 공개) 리스너의 방어선 설정이다.
type ExternalConfig struct {
	// SubjectNamespaces: 요청자 ServiceAccount의 네임스페이스가 여기에 속해야 한다 (기본 kms-external).
	SubjectNamespaces []string
	// KeyNamespaces: 키 이름 <ns>.<name>의 ns가 여기에 속해야 한다 (기본 kms-external).
	KeyNamespaces []string
	// RPS/Burst: 클라이언트 IP별 토큰 버킷.
	RPS   float64
	Burst int
	// AuthFailMax: IP당 1분에 허용하는 인증 실패(401) 횟수. 넘으면 5분 차단.
	AuthFailMax int
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// NewExternalRouter는 인터넷에 공개하는 외부 리스너용 라우터다. 내부 Transit 라우터와 달리 암복호화 4개 경로와
// GET /healthz만 있다 (sys, seal-profile, 관리 기능 없음).
//
// 요청 흐름: ① IP별 요청 수 제한 / 인증 실패 차단 → ② authn(토큰 검증) → ③ 라우트별 지표 →
// 감사 → 요청자 네임스페이스 확인 → 키 네임스페이스 확인 → authz(SAR). 방어선 3개의 이유:
//   - 요청자 네임스페이스 제한: 내부 SA 토큰이 유출돼도 인터넷에서는 못 쓴다 (외부 전용 SA만 통과).
//   - 키 네임스페이스 제한: 외부 사용자가 내부 키 이름을 두드려 보는 것을 SAR 이전에 막는다. 존재 여부를 드러내지
//     않도록 일반 403(forbidden)만 돌려준다.
//   - 요청 수 제한 + 인증 실패 차단: 공개 포트에 대한 무차별 대입·폭주를 줄인다.
func NewExternalRouter(deps Deps, cfg ExternalConfig) http.Handler {
	guard := newIPGuard(cfg.RPS, cfg.Burst, cfg.AuthFailMax)
	metrics.SetExternalBlockedSource(guard.blocked)
	return newExternalRouter(deps, cfg, guard)
}

func newExternalRouter(deps Deps, cfg ExternalConfig, guard *ipGuard) http.Handler {
	r := chi.NewRouter()

	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		httputil.WriteJSONError(w, http.StatusNotFound, "not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, req *http.Request) {
		httputil.WriteJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
	})

	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ip := clientIP(req)
			if ok, reason, retry := guard.allow(ip); !ok {
				metrics.ExternalRejectedTotal.WithLabelValues(reason).Inc()
				metrics.ExternalRequestsTotal.WithLabelValues("error").Inc()
				w.Header().Set("Retry-After", strconv.Itoa(retry))
				httputil.WriteAPIError(w, http.StatusTooManyRequests, "rate_limited", "too many requests", "retry after the indicated delay")
				return
			}
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, req)
			if sw.status == http.StatusUnauthorized {
				guard.authFailed(ip)
			}
			if sw.status >= 400 {
				metrics.ExternalRequestsTotal.WithLabelValues("error").Inc()
			} else {
				metrics.ExternalRequestsTotal.WithLabelValues("success").Inc()
			}
		})
	})

	r.Get("/healthz", func(w http.ResponseWriter, req *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Group(func(r chi.Router) {
		if deps.Verifier != nil {
			r.Use(authn.Middleware(deps.Verifier))
		}
		r.Use(httputil.SealedGuard(deps.Barrier))

		route := func(op string, h http.HandlerFunc) {
			r.With(metrics.InstrumentTransit(op), auditMiddlewareFor(deps.Audit, op, "external"),
				subjectNamespaceGuard(cfg.SubjectNamespaces), keyNamespaceGuard(cfg.KeyNamespaces), authzMiddleware(deps.Authorizer, op)).Post("/v1/"+op+"/{name}", h)
		}
		route("encrypt", handleEncrypt(deps))
		route("decrypt", handleDecrypt(deps))
		route("rewrap", handleRewrap(deps))
		route("datakey", handleDataKey(deps))
	})
	return r
}

// subjectNamespaceGuard: 요청자 SA의 네임스페이스가 허용 목록에 있어야 한다. authn 뒤에 놓이며(신원이 있어야 확인 가능),
// 감사 뒤에 놓여 거부도 감사 기록에 남는다 (내부 토큰이 외부에서 쓰인 시도를 알아볼 수 있다).
func subjectNamespaceGuard(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			id, ok := authn.IdentityFromContext(req.Context())
			if !ok || !contains(allowed, id.Namespace) {
				forbidden(w)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

func forbidden(w http.ResponseWriter) {
	httputil.WriteAPIError(w, http.StatusForbidden, "forbidden", "request is not permitted", "")
}

// keyNamespaceGuard: 키 이름이 <ns>.<name>이고 ns가 허용 목록에 있어야 한다. 점 없는 전역 키, 다른 팀의 키,
// 형식이 틀린 이름은 모두 같은 403이다 (키의 존재 여부를 드러내지 않는다).
func keyNamespaceGuard(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			ns, _, err := keys.ParseName(chi.URLParam(req, "name"))
			if err != nil || ns == "" || !contains(allowed, ns) || strings.Contains(ns, ".") {
				forbidden(w)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}
