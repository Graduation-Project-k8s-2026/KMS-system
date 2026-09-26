package main

import (
	"net"
	"path/filepath"
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
