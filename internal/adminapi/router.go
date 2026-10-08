package adminapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/console"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/dashboard"
)

// Deps는 관리 API 라우터가 필요로 하는 설정을 모은 것이다.
type Deps struct {
	// SocketPath: /v1/*를 중계할 admin.sock 경로. /readyz도 이 경로에
	// 연결 가능한지로 판단한다.
	SocketPath string

	// Dashboard: 운영·성능 대시보드(/dashboard, /api/dashboard/*, /api/bench/*).
	// nil이면 이 경로들을 등록하지 않는다.
	Dashboard *dashboard.Service
}

// NewRouter는 Deps를 엮어 chi 라우터를 구성해 반환한다.
//
//   - /healthz, /readyz: 이 프로세스와 admin.sock의 생존/연결 상태 확인.
//   - /v1/*: admin.sock으로 그대로 중계(NewSocketProxy) — 요청을 해석하지
//     않는다.
//   - /console: 운영자 콘솔(internal/api/console)을 그대로 서빙한다. 콘솔이
//     쓰는 API는 전부 상대 경로(/v1/...)라 위 프록시를 그대로 타고, 실제로
//     쓰는 엔드포인트는 거의 전부 Admin 평면이다(예외 하나 — seal-profile —
//     는 console.html이 자체적으로 "Transit API 필요" 안내를 보여준다).
//   - /dashboard, /api/dashboard/*, /api/bench/*: internal/dashboard의 운영·성능
//     대시보드. KMS /metrics를 직접 수집해 보여주고 bench 결과를 저장·비교한다.
//     Deps.Dashboard가 있을 때만 등록한다.
//   - /: 아직 /dashboard, /portal이 등록되지 않아 internal/api/home의 3장
//     카드 페이지를 그대로 쓰면 죽은 링크가 둘 생긴다. 그래서 지금은 단순히
//     /console로 안내한다.
//
// 옛 /dashboard(internal/api/dashboard)와 /portal(internal/api/portal)은
// 의도적으로 등록하지 않는다:
//   - 옛 dashboard는 seal-profile/seal-benchmark(둘 다 Transit 평면)에만
//     의존하는데, admin.sock 경유로는 이 둘에 접근할 수 없다. 벤치마크
//     실행기(Job)가 측정하고 관리 API가 결과를 저장·표시하는 구조로 다시
//     설계한 뒤 연결할 예정이다.
//   - portal은 Transit API(암복호화)를 직접 호출하는 고객용 화면이라,
//     목표 구조에서는 별도의 데모 애플리케이션이 된다.
//
// 두 패키지 모두 코드는 그대로 남아있다 — 라우팅에서만 빠져 있다.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", handleHealthz())
	r.Get("/readyz", handleReadyz(deps.SocketPath))

	r.Handle("/v1/*", NewSocketProxy(deps.SocketPath))

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
