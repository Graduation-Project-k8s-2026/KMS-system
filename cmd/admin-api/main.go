// cmd/admin-api: 관리 API 프로세스 실행 진입점. KMS 서버(cmd/server)와는
// 별개의 프로세스로 떠서, 네트워크(HTTP)로 받은 관리 요청을 그대로
// admin.sock(유닉스 도메인 소켓)에 중계하고 /healthz, /readyz를 제공한다.
// 웹 UI 서빙은 이번 범위가 아니다 — 별도 작업에서 다룬다.
//
// 이 프로세스는 인증도 TLS도 없다 — 신뢰된 네트워크 밖에 노출하면 안 된다.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/dashboard"
)

// shutdownTimeout: SIGINT/SIGTERM 수신 후 진행 중인 요청(admin.sock으로
// 중계 중인 요청 포함)을 정리할 수 있게 주는 최대 유예 시간.
const shutdownTimeout = 10 * time.Second

func main() {
	addr := getenvDefault("ADMIN_API_ADDR", ":8201")
	socketPath := getenvDefault("KMS_ADMIN_SOCKET", "/var/run/kms/admin.sock")

	if err := checkSocketExists(socketPath); err != nil {
		log.Fatalf("%v (KMS 서버가 아직 기동되지 않았을 수 있습니다 — cmd/server가 이 경로에 admin.sock을 만들어야 합니다)", err)
	}

	log.Print("admin API is running without authentication or TLS — do not expose outside a trusted network")
	log.Print("the bench result upload/delete APIs (/api/bench/results) are also unauthenticated")

	dashCfg, err := dashboard.ConfigFromEnv(os.LookupEnv, socketPath)
	if err != nil {
		log.Fatal(err)
	}
	dash, err := dashboard.NewService(dashCfg)
	if err != nil {
		log.Fatalf("dashboard: %v", err)
	}
	if dashCfg.MetricsURL == "" {
		log.Printf("dashboard: metrics collection disabled (%s is empty)", dashboard.EnvMetricsURL)
	} else {
		log.Printf("dashboard: scraping %s every %s, keeping %s", dashCfg.MetricsURL, dashCfg.MetricsInterval, dashCfg.MetricsWindow)
	}
	log.Printf("dashboard: bench results dir=%s", dashCfg.BenchDir)

	collectCtx, stopCollect := context.WithCancel(context.Background())
	defer stopCollect()
	go dash.Run(collectCtx)

	router := adminapi.NewRouter(adminapi.Deps{SocketPath: socketPath, Dashboard: dash})
	srv := &http.Server{Addr: addr, Handler: router}

	log.Printf("admin-api starting: addr=%s admin_socket=%s", addr, socketPath)

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Print("shutdown signal received, shutting down")
	case err := <-serverErr:
		log.Fatalf("admin-api stopped: %v", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}

// checkSocketExists는 admin.sock 경로에 파일이 있는지만 확인한다 — 실제로
// 연결 가능한지(/readyz가 하는 일)까지는 보지 않는다. 시작 시점에는 KMS
// 서버가 아직 소켓을 만들지 않았을 가능성이 가장 흔한 실패 원인이므로,
// 그 경우를 명확한 메시지로 구분해준다.
func checkSocketExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("admin socket not found at %q", path)
		}
		return fmt.Errorf("cannot access admin socket at %q: %w", path, err)
	}
	return nil
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
