package adminapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Deps는 관리 API 라우터가 필요로 하는 설정을 모은 것이다.
type Deps struct {
	// SocketPath: /v1/*를 중계할 admin.sock 경로. /readyz도 이 경로에
	// 연결 가능한지로 판단한다.
	SocketPath string
}

// NewRouter는 Deps를 엮어 chi 라우터를 구성해 반환한다.
//
//   - /healthz, /readyz: 이 프로세스와 admin.sock의 생존/연결 상태 확인.
//   - /v1/*: admin.sock으로 그대로 중계(NewSocketProxy) — 요청을 해석하지
//     않는다.
//
// 웹 UI(console/dashboard/home) 서빙은 이번 범위가 아니다 — 별도 작업에서
// 다룬다.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", handleHealthz())
	r.Get("/readyz", handleReadyz(deps.SocketPath))

	r.Handle("/v1/*", NewSocketProxy(deps.SocketPath))

	return r
}
