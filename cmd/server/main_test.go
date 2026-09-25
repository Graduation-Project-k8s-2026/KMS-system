package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

// TestListenUnixSocket_CreatesParentDirAndPermissions는 부모 디렉터리가 아직
// 없어도 listenUnixSocket이 만들어주고, 소켓 파일 권한이 0600으로 좁혀지는지
// 확인한다.
func TestListenUnixSocket_CreatesParentDirAndPermissions(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "nested", "admin.sock")

	l, err := listenUnixSocket(sockPath)
	if err != nil {
		t.Fatalf("listenUnixSocket failed: %v", err)
	}
	defer l.Close()
	defer os.Remove(sockPath)

	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatalf("stat socket file failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != adminSocketPerm {
		t.Fatalf("socket file perm = %o, want %o", perm, adminSocketPerm)
	}
}

// TestListenUnixSocket_RemovesStaleSocket은 이전 실행이 비정상 종료해 소켓
// 파일이 남아있는 상황(stale socket)에서도 listenUnixSocket이 정상적으로
// 재바인딩하는지 확인한다.
func TestListenUnixSocket_RemovesStaleSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "admin.sock")

	// 이전 실행이 남긴 것처럼, 미리 소켓을 하나 만들었다가 리스너만 닫는다
	// (소켓 파일 자체는 지워지지 않고 남는다 — 우리 main도 정상 종료 시에만
	// os.Remove로 지우므로, kill -9 등으로 죽으면 이런 상태가 된다).
	stale, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to create stale socket: %v", err)
	}
	stale.Close()

	l, err := listenUnixSocket(sockPath)
	if err != nil {
		t.Fatalf("listenUnixSocket with stale socket file present failed: %v", err)
	}
	defer l.Close()
	defer os.Remove(sockPath)
}

// TestListenUnixSocket_ServesHTTPOverSocket은 listenUnixSocket이 반환한
// 리스너 위에 Admin 라우터를 올리고, net.Dial("unix", path)로 직접 연결해
// 실제 요청/응답이 오가는지 확인하는 통합 테스트다.
func TestListenUnixSocket_ServesHTTPOverSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "admin.sock")

	l, err := listenUnixSocket(sockPath)
	if err != nil {
		t.Fatalf("listenUnixSocket failed: %v", err)
	}
	defer os.Remove(sockPath)

	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	router := admin.NewRouter(admin.Deps{Barrier: b, Keys: km, Seal: sealer})

	srv := &http.Server{Handler: router}
	go srv.Serve(l)
	defer srv.Shutdown(context.Background())

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", sockPath)
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("http://admin.sock/v1/sys/seal-status")
	if err != nil {
		t.Fatalf("GET over unix socket failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var status struct {
		Sealed bool `json:"sealed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode response failed: %v", err)
	}
	if !status.Sealed {
		t.Fatal("sealed = false, want true (no unseal called yet)")
	}
}
