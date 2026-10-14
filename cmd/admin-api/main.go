// cmd/admin-api serves authenticated loopback management and a separate TLS result ingest listener.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/jobs"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/security"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
)

// shutdownTimeout: SIGINT/SIGTERM 수신 후 진행 중인 요청(admin.sock으로
// 중계 중인 요청 포함)을 정리할 수 있게 주는 최대 유예 시간.
const shutdownTimeout = 10 * time.Second

func main() {
	if err := serve(); err != nil {
		log.Fatal(err)
	}
}
func serve() error {
	addr := getenvDefault("ADMIN_API_ADDR", "127.0.0.1:8201")
	if addr != "127.0.0.1:8201" {
		return fmt.Errorf("management must bind 127.0.0.1:8201")
	}
	if getenvDefault("ADMIN_API_AUTH_MODE", "tailscale") != "tailscale" {
		return fmt.Errorf("tailscale authentication required")
	}
	auth, err := adminapi.NewSecurity(os.Getenv("ADMIN_API_ROLES_FILE"), os.Getenv("ADMIN_API_PUBLIC_ORIGIN"))
	if err != nil {
		return err
	}
	for _, key := range []string{"ADMIN_API_INGEST_ADDR", "ADMIN_API_DATA_DIR", "ADMIN_API_PROMETHEUS_URL", "ADMIN_API_BENCH_IMAGE", "ADMIN_API_SOURCE_SHA", "ADMIN_API_SERVER_VERSION", "ADMIN_API_TRANSIT_URL", "ADMIN_API_INGEST_URL", "ADMIN_API_INGEST_TLS_CERT", "ADMIN_API_INGEST_TLS_KEY"} {
		if os.Getenv(key) == "" {
			return fmt.Errorf("%s required", key)
		}
	}
	if !strings.Contains(os.Getenv("ADMIN_API_BENCH_IMAGE"), "@sha256:") {
		return fmt.Errorf("bench image must be pinned by digest")
	}
	if os.Getenv("ADMIN_API_PROMETHEUS_URL") != "http://127.0.0.1:9090" {
		return fmt.Errorf("Prometheus must use host loopback")
	}
	if os.Getenv("ADMIN_API_METRICS_URL") != "" {
		return fmt.Errorf("direct metrics scrape is disabled; use Prometheus")
	}
	store, err := storage.OpenFileStorage(os.Getenv("ADMIN_API_DATA_DIR"))
	if err != nil {
		return err
	}
	defer store.Close()
	auditLog, err := audit.New(filepath.Join(os.Getenv("ADMIN_API_DATA_DIR"), "audit"))
	if err != nil {
		return err
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	cfg.Timeout = 5 * time.Second
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	service := &jobs.Service{Client: client, Store: store, Config: jobs.Config{Namespace: getenvDefault("ADMIN_API_JOB_NAMESPACE", "kms-bench"), PluginNamespace: getenvDefault("ADMIN_API_PLUGIN_NAMESPACE", "kms-bench-plugin"), E2ENamespace: getenvDefault("ADMIN_API_E2E_NAMESPACE", "kms-bench-e2e"), Image: os.Getenv("ADMIN_API_BENCH_IMAGE"), TransitURL: os.Getenv("ADMIN_API_TRANSIT_URL"), IngestURL: os.Getenv("ADMIN_API_INGEST_URL"), Audience: getenvDefault("ADMIN_API_INGEST_AUDIENCE", "kms-bench-results"), SourceSHA: os.Getenv("ADMIN_API_SOURCE_SHA"), ServerVersion: os.Getenv("ADMIN_API_SERVER_VERSION")}}
	if err := service.Config.Validate(); err != nil {
		return err
	}
	host, port, e := net.SplitHostPort(os.Getenv("ADMIN_API_INGEST_ADDR"))
	ip := net.ParseIP(host)
	if e != nil || ip == nil || !ip.IsPrivate() || port != "8202" {
		return fmt.Errorf("ingest must bind private node IP on 8202")
	}
	socket := getenvDefault("KMS_ADMIN_SOCKET", "/run/custom-kms/admin/admin.sock")
	router := auth.Wrap(adminapi.NewRouter(adminapi.Deps{SocketPath: socket, Jobs: service, AuditDir: filepath.Join(os.Getenv("ADMIN_API_DATA_DIR"), "audit"), CoreAuditDir: os.Getenv("ADMIN_API_CORE_AUDIT_DIR"), PrometheusURL: os.Getenv("ADMIN_API_PROMETHEUS_URL")}))
	// Subjects come from the trusted loopback Serve boundary; bodies/headers are never logged.
	router = auditLog.Middleware(auth.Subject, router)
	srv := security.Server(addr, router)
	ingest := security.Server(getenvDefault("ADMIN_API_INGEST_ADDR", ":8202"), auditLog.Middleware(func(*http.Request) string { return "unauthenticated-job" }, service.Ingest()))
	pair, err := tls.LoadX509KeyPair(os.Getenv("ADMIN_API_INGEST_TLS_CERT"), os.Getenv("ADMIN_API_INGEST_TLS_KEY"))
	if err != nil {
		return fmt.Errorf("ingest TLS certificate/key required")
	}
	ingest.TLSConfig.Certificates = []tls.Certificate{pair}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 2)
	go func() { errs <- srv.ListenAndServe() }()
	go func() { errs <- ingest.ListenAndServeTLS("", "") }()
	reconcileDone := make(chan struct{})
	go func() {
		defer close(reconcileDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			if err := service.Reconcile(ctx); err != nil {
				log.Print("job reconciliation pending: backend unavailable")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	select {
	case <-ctx.Done():
	case err = <-errs:
	}
	stop()
	<-reconcileDone
	shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	_ = ingest.Shutdown(shutdown)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
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
