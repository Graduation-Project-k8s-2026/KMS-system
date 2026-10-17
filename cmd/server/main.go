// cmd/server: KMS 서버 실행 진입점. 여기서 모든 층(seal, storage, barrier,
// keys, transit, rotation, api)을 실제 구현체로 조립한다 — "무엇을 쓸지
// 결정하고 서로 연결하는" 책임은 main에 있고, "요청을 어떻게 처리할지"는
// api 패키지의 책임이다.
//
// 서버는 세 개의 독립된 리스너를 동시에 띄운다:
//   - Transit(데이터 평면): TCP, KMS_TRANSIT_ADDR(기본 :8200) — 네트워크로
//     열려 사용자 애플리케이션이 암복호화를 요청한다.
//   - Admin(관리 평면): 유닉스 도메인 소켓, KMS_ADMIN_SOCKET(기본
//     /var/run/kms/admin.sock) — 같은 노드의 관리자만 접근해 키 관리와
//     init/unseal을 수행한다. 브라우저는 유닉스 소켓에 접속할 수 없으므로
//     웹 UI(console/portal/dashboard/home)는 어느 리스너에도 등록하지
//     않는다 — 관리 API(HTTPS -> admin.sock 중계)가 생기기 전까지는 비활성.
//   - Metrics: TCP, KMS_METRICS_ADDR(기본 :9100) — Prometheus가 스크레이프.
//     Transit에 두지 않는 이유: KMS_AUTHN=on이면 Prometheus도 토큰이
//     필요해지고, 메트릭이 애플리케이션 트래픽과 같은 경로로 노출된다.
//     전용 포트로 분리하면 인증과 무관하게 수집할 수 있고, 네트워크
//     정책으로 Prometheus만 접근하도록 제한하기 쉽다. 이 리스너에는 인증을
//     붙이지 않는다 — 대신 메트릭에 민감 정보(키 자료, 토큰, 평문 등)가
//     절대 포함되지 않게 하고(internal/metrics 패키지 주석 참고),
//     README에 네트워크 정책으로 접근을 제한하라고 명시한다.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/kmsv2"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/security"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/tlsreload"
	"google.golang.org/grpc"
	pb "k8s.io/kms/apis/v2"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/rotation"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	transitsvc "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// shutdownTimeout: SIGINT/SIGTERM 수신 후 진행 중인 요청을 정리할 수 있게
// 주는 최대 유예 시간.
const shutdownTimeout = 10 * time.Second

// adminSocketPerm: admin.sock의 파일 권한. 같은 노드의 소유자만 접근
// 가능해야 하므로 그룹/other에는 아무 권한도 주지 않는다.
const adminSocketPerm = 0o600

func main() {
	cert, key := os.Getenv("KMS_TRANSIT_TLS_CERT"), os.Getenv("KMS_TRANSIT_TLS_KEY")
	// 인증서 파일이 바뀌면(30초 이내 확인) 재시작 없이 새 인증서를 쓴다. 처음 읽기에 실패하면 기동 실패.
	tlsReload, err := tlsreload.New(cert, key)
	if err != nil {
		log.Fatal("Transit TLS certificate/key required")
	}
	if getenvDefault("KMS_AUTHN", "on") != "on" || getenvDefault("KMS_AUTHZ", "on") != "on" || os.Getenv("KMS_AUTHZ_FAIL_OPEN") == "true" {
		log.Fatal("production requires JWT and fail-closed SAR")
	}
	if os.Getenv("KMS_SA_ISSUER") == "" || os.Getenv("KMS_SA_AUDIENCE") == "" || os.Getenv("KMS_KUBECONFIG") == "" {
		log.Fatal("issuer, audience and SAR kubeconfig required")
	}
	auditLog, err := audit.New(os.Getenv("KMS_AUDIT_DIR"))
	if err != nil {
		log.Fatal(err)
	}

	// Transit 요청 감사(비동기). KMS_TRANSIT_AUDIT_DIR이 비어 있으면 끈다. 관리 감사(KMS_AUDIT_DIR)와는
	// 파일 형식·위치가 별개다. 버퍼가 가득 차면 요청을 막지 않고 버리고 kms_audit_dropped_total을 올린다.
	var transitAudit *audit.TransitLog
	if dir := os.Getenv("KMS_TRANSIT_AUDIT_DIR"); dir != "" {
		transitAudit, err = audit.NewTransit(dir,
			getenvIntDefault("KMS_TRANSIT_AUDIT_BUFFER", audit.DefaultTransitBuffer),
			time.Duration(getenvIntDefault("KMS_TRANSIT_AUDIT_FSYNC_MS", int(audit.DefaultTransitFsync/time.Millisecond)))*time.Millisecond)
		if err != nil {
			log.Fatalf("transit audit: %v", err)
		}
		defer transitAudit.Close() // 정상 종료 시 남은 기록을 flush한다
	}

	storageKind := getenvDefault("KMS_STORAGE", "file")
	dataDir := getenvDefault("KMS_DATA_DIR", "./data")
	autoUnseal := os.Getenv("KMS_AUTO_UNSEAL") == "true"

	transitAddr := getenvDefault("KMS_TRANSIT_ADDR", "")
	if transitAddr == "" {
		// PORT는 하위호환을 위해 계속 인식한다 — 기존 배포 설정이 그대로
		// 동작해야 한다.
		transitAddr = ":" + getenvDefault("PORT", "8200")
	}
	adminSocketPath := getenvDefault("KMS_ADMIN_SOCKET", "/var/run/kms/admin.sock")

	metricsAddr, metricsEnabled := resolveMetricsAddr()

	// newStorage는 barrier용 storage와, TPMSeal 전용 storage(barrier와는
	// 완전히 별개 — 이유는 internal/seal/tpm.go의 store 필드 주석 참고)를
	// 같은 KMS_STORAGE 설정으로 일관되게 만들기 위한 헬퍼다. subdir은 file
	// 백엔드일 때만 의미가 있고(memory는 매번 새 인스턴스일 뿐 경로가 없다),
	// TPMSeal용 storage가 barrier용과 같은 파일을 공유하지 않도록 구분한다.
	newStorage := func(subdir string) storage.StorageBackend {
		switch storageKind {
		case "memory":
			return storage.NewMemoryStorage()
		case "file":
			dir := dataDir
			if subdir != "" {
				dir = filepath.Join(dataDir, subdir)
			}
			return storage.NewFileStorage(dir)
		default:
			log.Fatalf("unknown KMS_STORAGE %q; want \"memory\" or \"file\"", storageKind)
			return nil // unreachable
		}
	}

	// 허용 봉인 방식. 실제 방식은 저장소의 init 기록(seal 값)이 정한다 — 환경변수가
	// 아니라 기록이 진실의 원천이다(ADR-010). KMS_SEAL_ALLOWED는 "이 서버가 허용하는
	// 방식의 목록"일 뿐이고, 기록이 허용 목록 밖이면 기동을 거부한다(fail-closed).
	// dev/k8s 같은 방식은 운영 서버에서 계속 거부한다.
	allowedSeals, err := parseAllowedSeals(getenvDefault("KMS_SEAL_ALLOWED", "shamir,tpm"))
	if err != nil {
		log.Fatal(err)
	}
	if legacy := os.Getenv("KMS_SEAL_TYPE"); legacy != "" {
		if legacy != "shamir" {
			log.Fatal("production server supports only shamir/tpm seals (KMS_SEAL_ALLOWED); KMS_SEAL_TYPE=" + legacy + " is rejected")
		}
		log.Print("KMS_SEAL_TYPE is deprecated and ignored (the seal mode comes from the initialization record); use KMS_SEAL_ALLOWED to restrict allowed modes")
	}

	shamirParts := getenvIntDefault("KMS_SHAMIR_PARTS", 5)
	shamirThreshold := getenvIntDefault("KMS_SHAMIR_THRESHOLD", 3)
	if shamirParts < 2 || shamirParts > 255 || shamirThreshold < 2 || shamirThreshold > shamirParts {
		log.Fatal("invalid Shamir parameters")
	}
	tpmPCRs, err := seal.ParsePCRs(os.Getenv("KMS_TPM_PCRS"))
	if err != nil {
		log.Fatal(err)
	}

	store := newStorage("")
	if storageKind != "file" {
		log.Fatal("production requires file storage")
	}
	locked, err := storage.OpenFileStorage(dataDir)
	if err != nil {
		log.Fatal(err)
	}
	defer locked.Close()
	store = locked

	// 조립 순서: seal -> storage -> barrier -> keys -> transit -> rotation.
	// 각 층은 자신보다 아래 층을 인터페이스로만 알고 있으므로, 실제 구현체가
	// 무엇인지 결정해서 서로 연결하는 건 이 main의 책임이다.
	//
	// Seal은 Switch 하나로 조립한다: 안에 Shamir(항상, 복구 조각용)와 TPM(필요할 때
	// 장치를 열어서)이 들어 있고, 어느 쪽으로 해제할지는 init 기록의 seal 값이 정한다.
	var openTPM func() (seal.TPMBackend, error)
	if allowedSeals["tpm"] {
		tpmDevice := getenvDefault("KMS_TPM_DEVICE", seal.DefaultTPMDevice)
		var opts []seal.TPMOption
		if len(tpmPCRs) > 0 {
			opts = append(opts, seal.WithPCRs(tpmPCRs))
		}
		openTPM = func() (seal.TPMBackend, error) {
			dev, err := seal.OpenTPMDevice(tpmDevice)
			if err != nil {
				return nil, err
			}
			return seal.NewTPMSeal(dev, store, opts...), nil
		}
	}
	sealer := seal.NewSwitch("shamir", seal.NewShamirSeal(shamirThreshold), nil, openTPM, store)
	b := barrier.NewBarrier(store, sealer)
	if err := b.CheckInitialization(shamirParts, shamirThreshold); err != nil {
		log.Fatal(err)
	}
	sealMode, err := b.SealMode()
	if err != nil {
		log.Fatalf("initialization record unreadable: %v", err)
	}
	if sealMode == "" {
		sealMode = "shamir" // 미초기화 저장소: POST /v1/sys/init이 shamir로 시작한다
	}
	if !allowedSeals[sealMode] {
		log.Fatalf("initialization record uses seal %q, which is not in KMS_SEAL_ALLOWED", sealMode)
	}
	sealer.SetMode(sealMode)
	km := keys.NewKeyManager(b)
	// 보호 키: 비활성화·삭제 예약이 거부되는 키. KMS v2 키는 kmsv2.New가 자동으로 보호하므로 설정이
	// 비어 있어도 안전하다. KMS_PROTECTED_KEYS(쉼표 목록)로 키를 더 지정할 수 있다.
	for _, name := range strings.Split(os.Getenv("KMS_PROTECTED_KEYS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			if _, _, err := keys.ParseName(name); err != nil {
				log.Fatalf("invalid KMS_PROTECTED_KEYS entry %q", name)
			}
			km.Protect(name)
		}
	}
	v2Name := getenvDefault("KMS_V2_KEY_NAME", "k8s-secrets")
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(v2Name) {
		log.Fatal("invalid reserved KMS v2 key name")
	}
	v2Service := kmsv2.New(km, v2Name)
	ts := transitsvc.NewTransitService(km)
	scheduler := rotation.NewRotationScheduler(km, rotation.WithOnRotate(func(name string) {
		log.Printf("rotation: rotated key %q", name)
	}))

	defer scheduler.Stop()

	// 삭제 유예가 끝난 키를 지우는 백그라운드 작업. 삭제는 되돌릴 수 없으므로 지우기 전과 후에 관리 감사
	// 기록을 남기고, 기록이 실패하면 삭제하지 않는다.
	reaper := rotation.NewReaper(km, time.Duration(getenvIntDefault("KMS_KEY_REAPER_INTERVAL_SEC", 600))*time.Second,
		func(name string) error {
			return auditLog.Write(audit.Event{Subject: "system:key-reaper", Action: "key purge requested", Key: name, Allowed: true})
		},
		func(name string) {
			if err := auditLog.Write(audit.Event{Subject: "system:key-reaper", Action: "key purge completed", Key: name, Allowed: true, Success: true}); err != nil {
				log.Printf("key reaper: audit write after purge failed: %v", err)
			}
		})
	defer reaper.Stop()

	// Shamir 모드는 항상 사람이 조각을 넣어야 한다(자동 해제 거부). TPM 모드는 자동
	// 해제가 목적이라 이 규칙을 적용하지 않는다 — 아래에서 기동 시 TPM 해제를 시도한다.
	if autoUnseal && sealMode == "shamir" {
		log.Fatal("KMS_AUTO_UNSEAL must be false for the production Shamir server")
	}

	verifier, err := buildAuthnVerifier()
	if err != nil {
		log.Fatalf("KMS_AUTHN=on but building the ServiceAccount token verifier failed: %v", err)
	}

	authorizer, err := buildAuthzAuthorizer(verifier != nil)
	if err != nil {
		log.Fatalf("KMS_AUTHZ=on but building the authorizer failed: %v", err)
	}

	transitDeps := transit.Deps{
		ReservedKey: v2Name,
		Barrier:     b,
		Transit:     ts,
		Seal:        sealer,
		Verifier:    verifier,
		Authorizer:  authorizer,
		Audit:       transitAudit, // KMS_TRANSIT_AUDIT_DIR이 비어 있으면 nil(감사 꺼짐)
	}
	transitRouter := transit.NewRouter(transitDeps)
	onUnseal := func() error {
		_, err := km.GetKeyMeta(v2Name)
		if errors.Is(err, &keys.KeyNotFoundError{}) {
			_, err = km.CreateKey(v2Name, 0)
		}
		if err != nil {
			return err
		}
		scheduler.Start()
		reaper.Start()
		return nil
	}

	// TPM 모드: 기동 시 TPM으로 자동 해제를 시도한다. 실패하면(장치 없음, blob 손상,
	// 기록과 불일치 등) 다른 방식으로 바꾸거나 초기화하지 않고 봉인 상태로 뜬다 —
	// 운영자가 POST /v1/sys/unseal로 복구 조각 threshold개를 넣어 해제한다.
	// 로그에는 실패 원인만 남기고 키 자료는 남기지 않는다.
	if sealMode == "tpm" {
		if err := b.Unseal(); err != nil {
			log.Printf("TPM auto-unseal failed, starting sealed; submit recovery shares to POST /v1/sys/unseal: %v", err)
		} else if err := onUnseal(); err != nil {
			b.Seal()
			log.Printf("TPM auto-unseal succeeded but post-unseal setup failed, staying sealed: %v", err)
		} else {
			log.Print("TPM auto-unseal succeeded")
		}
	}

	adminRouter := admin.NewRouter(admin.Deps{
		Barrier:         b,
		Keys:            km,
		Seal:            sealer,
		OnUnseal:        onUnseal,
		OnSeal:          func() { scheduler.Stop(); reaper.Stop() },
		ReservedKey:     v2Name,
		ShamirParts:     shamirParts,
		ShamirThreshold: shamirThreshold,
	})

	// namedServer는 리스너 하나를 이름과 함께 묶어, 시작/종료를 반복문으로
	// 처리할 수 있게 한다. Metrics 리스너는 KMS_METRICS_ADDR=""이면 아예
	// 만들지 않으므로(비활성화), 리스너 개수가 2개일 때와 3개일 때를 모두
	// 같은 코드로 다뤄야 한다.
	type namedServer struct {
		name     string
		srv      *http.Server
		listener net.Listener
	}

	// 모든 리스너의 바인딩을 먼저 동기적으로 끝낸다 — 기동 실패는 goroutine을
	// 띄우기 전에 여기서 바로 드러나야 "리스너 중 하나라도 기동 실패하면
	// 명확한 에러와 함께 종료"할 수 있다.
	transitListener, err := net.Listen("tcp", transitAddr)
	if err != nil {
		log.Fatalf("failed to listen on transit address %q: %v", transitAddr, err)
	}
	adminListener, err := listenUnixSocket(adminSocketPath)
	if err != nil {
		log.Fatalf("failed to listen on admin socket %q: %v", adminSocketPath, err)
	}
	defer os.Remove(adminSocketPath)
	v2Path := getenvDefault("KMS_V2_SOCKET", "/run/custom-kms/kmsv2/kms-v2.sock")
	v2Listener, err := listenUnixSocket(v2Path)
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(v2Path)
	grpcServer := grpc.NewServer(grpc.MaxRecvMsgSize(2 << 20))
	pb.RegisterKeyManagementServiceServer(grpcServer, v2Service)
	defer grpcServer.Stop()
	v2Errs := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(v2Listener); err != nil {
			v2Errs <- err
		}
	}()
	transitListener = tls.NewListener(transitListener, tlsReload.Config())
	adminRouter = auditLog.Middleware(audit.PeerSubject, adminRouter)

	adminHTTP := security.Server("", adminRouter)
	adminHTTP.ConnContext = audit.PeerContext
	servers := []namedServer{
		{"transit", security.Server("", metrics.AllHTTP(transitRouter)), transitListener},
		{"admin", adminHTTP, adminListener},
	}

	// 외부(인터넷 공개) 리스너: KMS_EXTERNAL_ADDR이 비어 있으면 꺼진다. Transit과 같은 인증서(재로딩 포함)를 쓰고,
	// 암복호화 4개 경로와 /healthz만 연다. 방어선(요청자·키 네임스페이스 제한, IP별 요청 수 제한·인증 실패 차단)은
	// transit.NewExternalRouter 주석 참고. hostNetwork 파드라 별도 Service 없이 노드 주소로 바로 받는다.
	if extAddr := os.Getenv("KMS_EXTERNAL_ADDR"); extAddr != "" {
		extListener, err := net.Listen("tcp", extAddr)
		if err != nil {
			log.Fatalf("failed to listen on external address %q: %v", extAddr, err)
		}
		extRouter := transit.NewExternalRouter(transitDeps, transit.ExternalConfig{
			SubjectNamespaces: splitCSV(getenvDefault("KMS_EXTERNAL_SUBJECT_NAMESPACES", "kms-external")),
			KeyNamespaces:     splitCSV(getenvDefault("KMS_EXTERNAL_KEY_NAMESPACES", "kms-external")),
			RPS:               float64(getenvIntDefault("KMS_EXTERNAL_RPS", 20)),
			Burst:             getenvIntDefault("KMS_EXTERNAL_BURST", 40),
			AuthFailMax:       getenvIntDefault("KMS_EXTERNAL_AUTHFAIL_MAX", 10),
		})
		servers = append(servers, namedServer{"external", security.Server("", extRouter), tls.NewListener(extListener, tlsReload.Config())})
		log.Printf("external listener enabled on %s", extAddr)
	}

	metricsStatus := "disabled (KMS_METRICS_ADDR=\"\")"
	if metricsEnabled {
		registerMetricsCollectors(b, km)
		metricsListener, err := net.Listen("tcp", metricsAddr)
		if err != nil {
			log.Fatalf("failed to listen on metrics address %q: %v", metricsAddr, err)
		}
		servers = append(servers, namedServer{"metrics", &http.Server{Handler: metrics.NewHandler()}, metricsListener})
		metricsStatus = metricsAddr
	}

	log.Printf("kms-system starting: transit=%s admin=%s metrics=%s storage=%s seal=%s sealed=%v",
		transitAddr, adminSocketPath, metricsStatus, storageKind, sealer.Type(), b.IsSealed())

	serverErrs := make(chan error, len(servers))
	var wg sync.WaitGroup
	wg.Add(len(servers))
	for _, s := range servers {
		s := s
		go func() {
			defer wg.Done()
			if err := s.srv.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				serverErrs <- fmt.Errorf("%s: %w", s.name, err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Print("shutdown signal received, shutting down all listeners")
	case <-v2Errs:
		log.Print("KMS v2 listener failed; shutting down")
	case err := <-serverErrs:
		log.Printf("listener failed: %v; shutting down all listeners", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, s := range servers {
		if err := s.srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("%s listener shutdown error: %v", s.name, err)
		}
	}
	grpcDone := make(chan struct{})
	go func() { grpcServer.GracefulStop(); close(grpcDone) }()
	select {
	case <-grpcDone:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
	scheduler.Stop()
	b.Seal()
	wg.Wait()
}

// resolveMetricsAddr는 KMS_METRICS_ADDR의 세 가지 상태를 구분한다:
//   - 아예 설정하지 않음 -> 기본값 :9100으로 활성화
//   - 값을 줌(빈 문자열이 아님) -> 그 값으로 활성화
//   - 빈 문자열로 명시적으로 설정함(KMS_METRICS_ADDR="") -> 비활성화
//
// getenvDefault(os.Getenv 기반)는 "설정 안 함"과 "빈 값으로 설정함"을
// 구분하지 못해 세 번째 상태(명시적 비활성화)를 표현할 수 없으므로,
// os.LookupEnv를 직접 쓴다.
func resolveMetricsAddr() (addr string, enabled bool) {
	v, set := os.LookupEnv("KMS_METRICS_ADDR")
	if !set {
		return "127.0.0.1:9100", true
	}
	if v == "" {
		return "", false
	}
	return v, true
}

// registerMetricsCollectors는 seal/키 현황 collector(internal/metrics.
// SealKeyCollector)를 prometheus.DefaultRegisterer(promhttp.Handler()가
// 서빙하는 것과 같은 레지스트리)에 등록한다.
//
// Go 런타임 기본 메트릭(고루틴 수, GC 등)과 프로세스 메트릭(CPU/메모리/
// 파일디스크립터)은 여기서 따로 등록하지 않는다 — client_golang이
// DefaultRegisterer를 초기화할 때(prometheus 패키지의 init()) 이미
// NewGoCollector/NewProcessCollector를 등록해두므로, 다시 등록하면
// "중복 등록" 에러로 패닉한다. 암복호화/인가 지표도 internal/metrics의
// promauto 전역 변수라 이미 등록돼 있어 여기서 손댈 게 없다.
func registerMetricsCollectors(b *barrier.Barrier, km *keys.KeyManager) {
	prometheus.MustRegister(metrics.NewSealKeyCollector(b, km))
}

// buildAuthnVerifier는 KMS_AUTHN에 따라 Transit 라우터에 붙일 인증 검증기를
// 만든다. KMS_AUTHN=off(격리된 테스트 helper용)면 nil을 반환한다 — Transit 라우터는 nil
// Verifier를 "인증 미들웨어를 등록하지 않음"으로 취급한다. 로컬 개발/테스트가
// 지금 토큰 없는 curl로 이뤄지고 있으므로, 기본 동작을 깨지 않기 위한
// 선택이다.
//
// Admin(유닉스 소켓)에는 이 인증을 적용하지 않는다 — 소켓 파일 권한(0600)과
// 같은 노드 제약으로 이미 보호되며, 관리 API 인증은 별도 과제다.
func buildAuthnVerifier() (*authn.Verifier, error) {
	mode := getenvDefault("KMS_AUTHN", "on")
	switch mode {
	case "off":
		log.Print("authentication is disabled (KMS_AUTHN=off) — all Transit requests are accepted")
		return nil, nil

	case "on":
		keyPaths := authn.SplitKeyPaths(getenvDefault("KMS_SA_PUBLIC_KEY", "/etc/kubernetes/pki/sa.pub"))
		keys, err := authn.LoadPublicKeys(keyPaths)
		if err != nil {
			return nil, err
		}
		return authn.NewVerifier(keys, authn.Config{
			Strict:   true,
			Issuer:   os.Getenv("KMS_SA_ISSUER"),
			Audience: os.Getenv("KMS_SA_AUDIENCE"),
		}), nil

	default:
		log.Fatalf("unknown KMS_AUTHN %q; want \"off\" or \"on\"", mode)
		return nil, nil // unreachable
	}
}

// errAuthzRequiresAuthn: KMS_AUTHZ=on인데 KMS_AUTHN=off일 때 반환하는 에러.
// 신원(1단계) 없이는 권한을 판단할 근거가 없으므로 설정 오류로 취급한다.
var errAuthzRequiresAuthn = errors.New("KMS_AUTHZ=on requires KMS_AUTHN=on — authorization needs a verified identity to check permissions against")

// buildAuthzAuthorizer는 KMS_AUTHZ에 따라 Transit 라우터에 붙일 인가기를
// 만든다. KMS_AUTHZ=off(격리된 테스트 helper용)면 nil을 반환한다 — Transit 라우터는 nil
// Authorizer를 "인가 미들웨어를 등록하지 않음"으로 취급하고, 인증만
// 통과하면 모든 키에 접근할 수 있다(2단계 이전과 동일한 동작).
//
// authnEnabled는 buildAuthnVerifier의 결과(nil이 아니었는지)를 그대로
// 받는다 — 신원 없이는 권한을 판단할 수 없으므로, KMS_AUTHN=off인데
// KMS_AUTHZ=on이면 설정 오류로 기동을 실패시킨다.
func buildAuthzAuthorizer(authnEnabled bool) (*authz.Authorizer, error) {
	mode := getenvDefault("KMS_AUTHZ", "on")
	switch mode {
	case "off":
		log.Print("authorization is disabled (KMS_AUTHZ=off) — any authenticated request is accepted")
		return nil, nil

	case "on":
		if !authnEnabled {
			return nil, errAuthzRequiresAuthn
		}

		failOpen := os.Getenv("KMS_AUTHZ_FAIL_OPEN") == "true"
		if failOpen {
			log.Print("KMS_AUTHZ_FAIL_OPEN=true — Transit requests will be ALLOWED if the SubjectAccessReview call to apiserver fails")
		}

		// KMS_AUTHZ_QPS/KMS_AUTHZ_BURST — authz 클라이언트가 apiserver에
		// SAR을 보내는 속도 상한. 설정하지 않으면(0) authz.DefaultQPS/
		// DefaultBurst(50/100)를 쓴다. 둘 중 하나라도 음수면 속도 제한을
		// 완전히 끈다 — ResolveRateLimit을 여기서 먼저 불러 로그에 "실제
		// 적용될 값"을 남기고, 같은 raw qps/burst를 NewClientFromEnv에도
		// 그대로 넘겨 거기서도 동일하게(다시) 해석하게 한다 — 순수 함수라
		// 두 번 불러도 결과가 달라지지 않는다.
		qps := float32(getenvIntDefault("KMS_AUTHZ_QPS", int(authz.DefaultQPS)))
		burst := getenvIntDefault("KMS_AUTHZ_BURST", authz.DefaultBurst)
		effQPS, effBurst, rateLimitDisabled := authz.ResolveRateLimit(qps, burst)
		if rateLimitDisabled {
			log.Print("authz client-side rate limiting is disabled (KMS_AUTHZ_QPS/KMS_AUTHZ_BURST < 0) — every SAR call is sent to the apiserver immediately; its own API Priority and Fairness is the only remaining protection")
		} else {
			log.Printf("authz client rate limit: QPS=%v Burst=%d", effQPS, effBurst)
		}

		client, err := authz.NewClientFromEnv(os.Getenv("KMS_KUBECONFIG"), qps, burst)
		if err != nil {
			return nil, err
		}

		// KMS_AUTHZ_CACHE_TTL이 음수면 authz.Authorizer가 캐시를 완전히
		// 비활성화한다(매 요청 apiserver에 SAR을 묻는다) — 성능에 큰 영향을
		// 주는 설정이므로 기동 로그에 눈에 띄게 남긴다.
		cacheTTL := getenvDurationSecondsDefault("KMS_AUTHZ_CACHE_TTL", 10)
		if cacheTTL < 0 {
			log.Print("authorization cache is disabled (KMS_AUTHZ_CACHE_TTL < 0) — every request queries the apiserver")
		}

		return authz.NewAuthorizer(client.AuthorizationV1().SubjectAccessReviews(), authz.Config{
			TTL:      cacheTTL,
			Timeout:  getenvDurationSecondsDefault("KMS_AUTHZ_TIMEOUT", 3),
			FailOpen: failOpen,
		}), nil

	default:
		log.Fatalf("unknown KMS_AUTHZ %q; want \"off\" or \"on\"", mode)
		return nil, nil // unreachable
	}
}

// listenUnixSocket은 admin.sock을 위한 유닉스 도메인 소켓 리스너를 만든다.
//   - 부모 디렉터리가 없으면 생성한다.
//   - 이전 실행이 비정상 종료해 소켓 파일이 남아있으면(stale socket) 새로
//     바인딩하기 전에 제거한다 — 그대로 두면 "address already in use"로
//     기동이 실패한다.
//   - 바인딩 후 권한을 0600으로 좁혀 같은 노드의 소유자만 접근하게 한다.
func listenUnixSocket(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to remove non-socket")
		}
		conn, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("socket already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot establish stale socket ownership")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, adminSocketPerm); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// parseAllowedSeals는 KMS_SEAL_ALLOWED("shamir,tpm")를 집합으로 바꾼다. shamir/tpm
// 외의 값(dev, k8s 등)은 운영 서버에서 허용하지 않으므로 에러다.
func parseAllowedSeals(v string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if f != "shamir" && f != "tpm" {
			return nil, fmt.Errorf("KMS_SEAL_ALLOWED: unsupported seal %q (production allows only shamir, tpm)", f)
		}
		out[f] = true
	}
	if len(out) == 0 {
		return nil, errors.New("KMS_SEAL_ALLOWED must list at least one of shamir, tpm")
	}
	return out, nil
}

// splitCSV는 쉼표 목록을 공백 제거 후 빈 항목 없이 나눈다.
func splitCSV(v string) []string {
	var out []string
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvIntDefault(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("invalid integer value for %s: %q", key, v)
	}
	return n
}

// getenvDurationSecondsDefault는 환경변수를 "초 단위 정수"로 읽어
// time.Duration으로 바꾼다. KMS_AUTHZ_CACHE_TTL/KMS_AUTHZ_TIMEOUT처럼
// 사람이 손으로 설정하는 값이라, "3600000000000"(나노초) 대신 "3" 같은
// 정수를 쓰게 하려는 것이다.
func getenvDurationSecondsDefault(key string, fallbackSeconds int) time.Duration {
	return time.Duration(getenvIntDefault(key, fallbackSeconds)) * time.Second
}
