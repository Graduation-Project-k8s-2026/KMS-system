// Package adminapi는 "관리 API" 프로세스의 라우팅/프록시 로직을 담는다.
// 이 프로세스는 KMS 서버(cmd/server)와 별개로 떠서, 네트워크(HTTP)로 받은
// 관리 요청을 그대로 admin.sock(유닉스 도메인 소켓)에 중계하고, 웹 UI를
// 서빙한다. KMS 서버 자체는 이 패키지가 존재하는지조차 모른다 — admin.sock
// 위에서는 그저 평소처럼 internal/api/admin이 만든 라우터가 요청을 받을
// 뿐이다.
package adminapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
)

// NewSocketProxy는 들어온 요청을 해석하지 않고 그대로 admin.sock으로
// 중계하는 투명 프록시를 만든다. 요청의 경로/메서드/헤더/바디, 응답의
// 상태코드/헤더/바디 모두 손대지 않는다 — 실제 요청/응답 처리는 전부
// admin.sock 반대편의 internal/api/admin 라우터가 담당한다.
//
// Transport.DialContext가 항상 유닉스 소켓으로만 연결하도록 고정하고,
// Director는 req.URL.Host를 더미 값("admin.sock")으로만 채운다 —
// net/http.Transport가 요청을 만들려면 URL.Host가 비어있으면 안 되기
// 때문일 뿐, DialContext는 여기 전달되는 network/addr 인자를 무시하고
// 항상 socketPath로 다이얼하므로 이 값 자체는 실제로 어디로도 쓰이지
// 않는다.
func NewSocketProxy(socketPath string) http.Handler {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}

	return &httputil.ReverseProxy{
		Transport: &http.Transport{DialContext: dial},
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = "admin.sock"
		},
		// FlushInterval: -1은 백엔드가 쓰는 즉시 클라이언트로 흘려보낸다.
		// 응답을 버퍼링했다가 한꺼번에 보내면, 시간이 걸리는 관리 연산
		// (예: TPM/K8s init)에서 클라이언트가 응답을 필요 이상으로 늦게
		// 받게 된다.
		FlushInterval: -1,
	}
}
