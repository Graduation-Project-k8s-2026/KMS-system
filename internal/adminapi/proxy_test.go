package adminapi_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
)

// newFakeAdminSocket은 실제 admin.sock 대신 쓸 가짜 유닉스 소켓 서버를
// 띄운다. handler가 받은 요청을 그대로 관찰할 수 있게 해, 프록시가 경로/
// 메서드/헤더/바디를 원형 그대로 넘기는지 검증하는 데 쓴다.
func newFakeAdminSocket(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	dir := t.TempDir()
	sockPath := filepath.Join(dir, "admin.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on fake admin socket: %v", err)
	}

	srv := &http.Server{Handler: handler}
	go srv.Serve(l)
	t.Cleanup(func() {
		srv.Shutdown(context.Background())
		os.Remove(sockPath)
	})

	return sockPath
}

// TestProxy_ForwardsMethodPathHeadersAndBody는 프록시를 거친 요청이
// admin.sock 반대편에 메서드/경로/헤더/바디 그대로 도착하는지 확인한다.
func TestProxy_ForwardsMethodPathHeadersAndBody(t *testing.T) {
	var (
		gotMethod string
		gotPath   string
		gotHeader string
		gotBody   string
	)

	sockPath := newFakeAdminSocket(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotHeader = r.Header.Get("X-Test-Header")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	router := adminapi.NewRouter(adminapi.Deps{SocketPath: sockPath})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/keys/app/rotate", strings.NewReader(`{"name":"app"}`))
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("X-Test-Header", "hello")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if gotMethod != http.MethodPost {
		t.Errorf("backend saw method = %q, want %q", gotMethod, http.MethodPost)
	}
	if gotPath != "/v1/keys/app/rotate" {
		t.Errorf("backend saw path = %q, want %q", gotPath, "/v1/keys/app/rotate")
	}
	if gotHeader != "hello" {
		t.Errorf("backend saw X-Test-Header = %q, want %q", gotHeader, "hello")
	}
	if gotBody != `{"name":"app"}` {
		t.Errorf("backend saw body = %q, want %q", gotBody, `{"name":"app"}`)
	}

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("client saw status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if string(respBody) != `{"ok":true}` {
		t.Errorf("client saw body = %q, want %q", string(respBody), `{"ok":true}`)
	}
}

// TestProxy_PreservesStatusCodeOnError는 백엔드가 4xx/5xx를 반환해도 프록시가
// 그대로 클라이언트에 넘기는지 확인한다 — 프록시가 임의로 에러를 삼키거나
// 다른 코드로 바꾸면 안 된다.
func TestProxy_PreservesStatusCodeOnError(t *testing.T) {
	sockPath := newFakeAdminSocket(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	})

	router := adminapi.NewRouter(adminapi.Deps{SocketPath: sockPath})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/keys/does-not-exist")
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}
