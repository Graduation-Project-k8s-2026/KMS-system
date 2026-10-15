package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckSocketExists_MissingSocket_ReturnsError는 admin.sock 경로에 아무
// 파일도 없을 때 checkSocketExists가 에러를 반환하는지 확인한다 — main이
// 이 에러로 log.Fatalf해 기동을 실패시키는 경로를 검증하는 셈이다.
func TestCheckSocketExists_MissingSocket_ReturnsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.sock")

	if err := checkSocketExists(path); err == nil {
		t.Fatal("checkSocketExists = nil, want error for missing socket")
	}
}

// TestCheckSocketExists_SocketPresent_ReturnsNil은 실제로 소켓 파일이
// 있으면 에러 없이 통과하는지 확인한다.
func TestCheckSocketExists_SocketPresent_ReturnsNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")

	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("failed to create socket: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	if err := checkSocketExists(path); err != nil {
		t.Fatalf("checkSocketExists = %v, want nil", err)
	}
}

func TestServeFailsClosedOnMissingContract(t *testing.T) {
	t.Setenv("ADMIN_API_ADDR", "0.0.0.0:8201")
	if err := serve(); err == nil {
		t.Fatal("public management accepted")
	}
	t.Setenv("ADMIN_API_ADDR", "127.0.0.1:8201")
	t.Setenv("ADMIN_API_AUTH_MODE", "off")
	if err := serve(); err == nil {
		t.Fatal("authentication off accepted")
	}
	t.Setenv("ADMIN_API_AUTH_MODE", "tailscale")
	t.Setenv("ADMIN_API_ROLES_FILE", "/missing/roles.json")
	t.Setenv("ADMIN_API_PUBLIC_ORIGIN", "https://kms.example.test")
	if err := serve(); err == nil {
		t.Fatal("missing roles accepted")
	}
}

func TestEveryRequiredAdminSettingFailsBeforeBackendAccess(t *testing.T) {
	roles := filepath.Join(t.TempDir(), "roles.json")
	if err := os.WriteFile(roles, []byte(`{"version":1,"users":{"fixture@example.test":"admin"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ADMIN_API_ADDR", "127.0.0.1:8201")
	t.Setenv("ADMIN_API_AUTH_MODE", "tailscale")
	t.Setenv("ADMIN_API_ROLES_FILE", roles)
	t.Setenv("ADMIN_API_PUBLIC_ORIGIN", "https://fixture.example.test")
	names := []string{"ADMIN_API_INGEST_ADDR", "ADMIN_API_DATA_DIR", "ADMIN_API_PROMETHEUS_URL", "ADMIN_API_BENCH_IMAGE", "ADMIN_API_SOURCE_SHA", "ADMIN_API_SERVER_VERSION", "ADMIN_API_TRANSIT_URL", "ADMIN_API_INGEST_URL", "ADMIN_API_INGEST_TLS_CERT", "ADMIN_API_INGEST_TLS_KEY"}
	for _, name := range names {
		t.Setenv(name, "fixture")
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "")
			err := serve()
			if err == nil || !strings.Contains(err.Error(), name+" required") {
				t.Fatal("missing setting not rejected before backend access")
			}
		})
	}
}
