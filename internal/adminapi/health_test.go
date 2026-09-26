package adminapi_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
)

// TestHealthz_AlwaysOK는 /healthz가 admin.sock 상태와 무관하게(존재하지
// 않아도) 항상 200을 반환하는지 확인한다 — 이 프로세스 자체의 생존만
// 보기 때문이다.
func TestHealthz_AlwaysOK(t *testing.T) {
	router := adminapi.NewRouter(adminapi.Deps{SocketPath: filepath.Join(t.TempDir(), "does-not-exist.sock")})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestReadyz_SocketMissing_Returns503는 admin.sock이 아예 없을 때 /readyz가
// 503을 반환하는지 확인한다.
func TestReadyz_SocketMissing_Returns503(t *testing.T) {
	router := adminapi.NewRouter(adminapi.Deps{SocketPath: filepath.Join(t.TempDir(), "does-not-exist.sock")})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

// TestReadyz_SocketReachable_Returns200는 admin.sock에 실제로 연결 가능하면
// /readyz가 200을 반환하는지 확인한다.
func TestReadyz_SocketReachable_Returns200(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "admin.sock")
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on fake admin socket: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	router := adminapi.NewRouter(adminapi.Deps{SocketPath: sockPath})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
