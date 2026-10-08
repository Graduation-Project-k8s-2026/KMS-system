package adminapi

import (
	"net"
	"net/http"
	"time"
)

// readyzDialTimeout: /readyz가 admin.sock 연결을 시도할 때 기다리는 최대
// 시간. 소켓이 응답 없이 걸려있는 비정상 상태에서도 헬스체크 자체가
// 무한정 붙잡히지 않도록 짧게 잡는다.
const readyzDialTimeout = 2 * time.Second

// handleHealthz는 관리 API 프로세스 자체의 생존만 확인한다 — admin.sock을
// 전혀 건드리지 않는다. KMS 서버가 떠 있는지와 무관하게, 이 프로세스가
// 요청을 처리할 수 있는 상태이기만 하면 항상 200이다.
func handleHealthz() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
}

// handleReadyz는 admin.sock에 실제로 연결이 가능한지 확인한다. KMS 서버가
// 아직 뜨지 않았거나 죽어서 소켓이 없어졌으면 503을 반환한다 — 연결만
// 확인하고 바로 닫으며, 실제 요청은 보내지 않는다(barrier가 sealed인지와는
// 무관하게 "중계할 대상이 살아있는가"만 본다).
func handleReadyz(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := net.DialTimeout("unix", socketPath, readyzDialTimeout)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("admin.sock unreachable: " + err.Error() + "\n"))
			return
		}
		_ = conn.Close()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}
}
