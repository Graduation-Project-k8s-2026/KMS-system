package adminapi

import (
	"encoding/json"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/jobs"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/console"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/dashboard"
)

// Deps는 관리 API 라우터가 필요로 하는 설정을 모은 것이다.
type Deps struct {
	// SocketPath: /v1/*를 중계할 admin.sock 경로. /readyz도 이 경로에
	// 연결 가능한지로 판단한다.
	SocketPath    string
	Jobs          *jobs.Service
	PrometheusURL string
	AuditDir      string
	CoreAuditDir  string

	// Dashboard: 운영·성능 대시보드(/dashboard, /api/dashboard/*, /api/bench/*).
	// nil이면 이 경로들을 등록하지 않는다.
	Dashboard *dashboard.Service
}

// NewRouter mounts explicit method/path allowlists. The production entrypoint wraps it with Security and audit middleware.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", handleHealthz())
	r.Get("/readyz", handleReadyz(deps.SocketPath))

	proxy := NewSocketProxy(deps.SocketPath)
	for _, path := range []string{"/v1/sys/seal-status", "/v1/keys/", "/v1/keys/{name}"} {
		r.Method("GET", path, proxy)
	}
	for _, path := range []string{"/v1/sys/init", "/v1/sys/unseal", "/v1/sys/seal", "/v1/keys/", "/v1/keys/{name}/rotate", "/v1/keys/{name}/config"} {
		r.Method("POST", path, proxy)
	}
	if deps.AuditDir != "" {
		r.Get("/api/audit", func(w http.ResponseWriter, req *http.Request) {
			events, err := audit.ReadToday(deps.AuditDir)
			if err != nil {
				http.Error(w, "audit unavailable", 503)
				return
			}
			if deps.CoreAuditDir != "" {
				core, err := audit.ReadToday(deps.CoreAuditDir)
				if err != nil {
					http.Error(w, "core audit unavailable", 503)
					return
				}
				events = append(events, core...)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(events)
		})
	}
	if deps.Jobs != nil {
		deps.Jobs.Mount(r)
		mountOperations(r, deps.PrometheusURL)
	}

	if deps.Dashboard != nil {
		deps.Dashboard.Mount(r)
	}

	r.Get("/console", handleConsole())
	r.Get("/", handleHomeRedirect())

	return r
}

func handleConsole() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(console.HTML)
	}
}

func handleHomeRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/console", http.StatusFound)
	}
}
