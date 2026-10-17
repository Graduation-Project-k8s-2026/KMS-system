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
	// TransitAuditDir: Transit(암복호화) 비동기 감사 파일 디렉터리(읽기 전용). 비우면 감사 화면에 Transit 기록이 없다.
	TransitAuditDir string

	// Dashboard: 운영·성능 대시보드(/dashboard, /api/dashboard/*, /api/bench/*).
	// nil이면 이 경로들을 등록하지 않는다.
	Dashboard *dashboard.Service

	// Info: GET /api/info에 보여 줄 배포 정보. RolesFile: GET /api/console-users가 읽는 역할 파일.
	Info      Info
	RolesFile string

	// DefaultUI: "/"가 보낼 화면. "v1"이면 기존 /console, 그 외(빈 값 포함)는 새 화면 /v2/.
	DefaultUI string
}

// NewRouter mounts explicit method/path allowlists. The production entrypoint wraps it with Security and audit middleware.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", handleHealthz())
	r.Get("/readyz", handleReadyz(deps.SocketPath))

	proxy := NewSocketProxy(deps.SocketPath)
	for _, path := range []string{"/v1/sys/seal-status", "/v1/sys/seal-profile", "/v1/keys", "/v1/keys/", "/v1/keys/{name}"} {
		r.Method("GET", path, proxy)
	}
	for _, path := range []string{"/v1/sys/init", "/v1/sys/unseal", "/v1/sys/seal", "/v1/keys", "/v1/keys/", "/v1/keys/{name}/rotate", "/v1/keys/{name}/config", "/v1/keys/{name}/disable", "/v1/keys/{name}/enable", "/v1/keys/{name}/schedule-deletion", "/v1/keys/{name}/cancel-deletion"} {
		r.Method("POST", path, proxy)
	}
	// 주의: /v1/sys/seal-migrate는 일부러 허용 목록에 넣지 않는다. 이번 운영 적용은 init 기록 v1을 유지해야 이전 이미지로 되돌릴 수 있는데,
	// 조각 재발급(target=shamir)도 기록을 v2로 올린다. 필요하면 서버의 관리 소켓으로 직접 실행한다(docs/usage.md).
	r.Get("/api/info", handleInfo(deps.Info, deps.AuditDir != ""))
	r.Get("/api/console-users", handleConsoleUsers(deps.RolesFile))
	if deps.AuditDir != "" {
		r.Get("/api/audit", handleAudit(deps))
	}
	if deps.Jobs != nil {
		deps.Jobs.Mount(r)
		mountOperations(r, deps.PrometheusURL)
	}

	if deps.Dashboard != nil {
		deps.Dashboard.Mount(r)
	}

	r.Get("/console", handleConsole())
	mountUI2(r)
	r.Get("/", handleHomeRedirect(deps.DefaultUI))

	return r
}

func handleConsole() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(console.HTML)
	}
}

func handleHomeRedirect(defaultUI string) http.HandlerFunc {
	target := "/v2/"
	if defaultUI == UIDefaultV1 {
		target = "/console"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}
}

// auditRow는 감사 화면이 보는 한 줄이다. 관리 감사(audit.Event)와 Transit 감사(audit.TransitEvent)를 같은 모양으로 합친다.
// Source는 "admin"(관리 소켓·콘솔) 또는 "transit". Transit 행의 Listener는 "internal"|"external".
type auditRow struct {
	audit.Event
	Source    string  `json:"source"`
	Listener  string  `json:"listener,omitempty"`
	ClientIP  string  `json:"client_ip,omitempty"`
	Status    int     `json:"status,omitempty"`
	LatencyMs float64 `json:"latency_ms,omitempty"`
}

func handleAudit(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		events, err := audit.ReadToday(deps.AuditDir)
		if err != nil {
			http.Error(w, "audit unavailable", 503)
			return
		}
		rows := make([]auditRow, 0, len(events))
		for _, e := range events {
			rows = append(rows, auditRow{Event: e, Source: "admin"})
		}
		if deps.CoreAuditDir != "" {
			core, err := audit.ReadToday(deps.CoreAuditDir)
			if err != nil {
				http.Error(w, "core audit unavailable", 503)
				return
			}
			for _, e := range core {
				rows = append(rows, auditRow{Event: e, Source: "admin"})
			}
		}
		if deps.TransitAuditDir != "" {
			tev, err := audit.ReadTransitToday(deps.TransitAuditDir)
			if err != nil {
				http.Error(w, "transit audit unavailable", 503)
				return
			}
			for _, e := range tev {
				listener := e.Listener
				if listener == "" {
					listener = "internal"
				}
				rows = append(rows, auditRow{
					Event: audit.Event{UTC: e.UTC, RequestID: e.RequestID, Subject: e.Subject, Action: e.Action, Key: e.Key,
						Allowed: e.Status != http.StatusUnauthorized && e.Status != http.StatusForbidden, Success: e.Status < 400},
					Source: "transit", Listener: listener, ClientIP: e.ClientIP, Status: e.Status, LatencyMs: e.LatencyMs})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)
	}
}
