// cmd/server: KMS 서버 실행 진입점. 여기서 모든 층(seal, storage, barrier,
// keys, transit, rotation, api)을 실제 구현체로 조립한다 — "무엇을 쓸지
// 결정하고 서로 연결하는" 책임은 main에 있고, "요청을 어떻게 처리할지"는
// api 패키지의 책임이다.
//
// 서버는 두 개의 독립된 리스너를 동시에 띄운다:
//   - Transit(데이터 평면): TCP, KMS_TRANSIT_ADDR(기본 :8200) — 네트워크로
//     열려 사용자 애플리케이션이 암복호화를 요청한다.
//   - Admin(관리 평면): 유닉스 도메인 소켓, KMS_ADMIN_SOCKET(기본
//     /var/run/kms/admin.sock) — 같은 노드의 관리자만 접근해 키 관리와
//     init/unseal을 수행한다. 브라우저는 유닉스 소켓에 접속할 수 없으므로
//     웹 UI(console/portal/dashboard/home)는 어느 리스너에도 등록하지
//     않는다 — 관리 API(HTTPS -> admin.sock 중계)가 생기기 전까지는 비활성.
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	tpm2 "github.com/google/go-tpm/legacy/tpm2"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
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

	sealType := getenvDefault("KMS_SEAL_TYPE", "dev")

	// shamirParts/shamirThreshold는 seal_type이 "shamir"일 때만 쓰이지만,
	// admin.Deps에 그대로 전달해 POST /v1/sys/init(InitShamir 호출)과
	// seal-status/unseal의 진행 상황 표시("2/3")에 재사용한다.
	var (
		sealer          seal.Seal
		shamirParts     int
		shamirThreshold int
	)

	switch sealType {
	case "dev":
		masterKey := os.Getenv("KMS_MASTER_KEY")
		if masterKey == "" {
			log.Fatal("KMS_SEAL_TYPE=dev requires KMS_MASTER_KEY; DevSeal needs a passphrase to derive the Root Key")
		}
		sealer = seal.NewDevSeal(masterKey)

	case "shamir":
		shamirParts = getenvIntDefault("KMS_SHAMIR_PARTS", 5)
		shamirThreshold = getenvIntDefault("KMS_SHAMIR_THRESHOLD", 3)
		sealer = seal.NewShamirSeal(shamirThreshold)

	case "tpm":
		var tpm io.ReadWriteCloser
		if os.Getenv("KMS_TPM_SIMULATOR") == "true" {
			sim, err := simulator.Get()
			if err != nil {
				log.Fatalf("KMS_TPM_SIMULATOR=true but starting the TPM simulator failed: %v", err)
			}
			tpm = sim
		} else {
			devicePath := getenvDefault("KMS_TPM_DEVICE", "/dev/tpmrm0")
			dev, err := tpm2.OpenTPM(devicePath)
			if err != nil {
				log.Fatalf("failed to open TPM device %q: %v", devicePath, err)
			}
			tpm = dev
		}
		// TPMSeal은 barrier가 쓰는 storage와 별개의 storage에 sealed blob을
		// 저장한다(순환 의존 방지 — 이유는 internal/seal/tpm.go 참고).
		tpmStore := newStorage("seal-tpm")
		sealer = seal.NewTPMSeal(tpm, tpmStore)

	case "k8s":
		client, err := seal.NewK8sClientFromEnv()
		if err != nil {
			log.Fatalf("KMS_SEAL_TYPE=k8s but building a K8s client failed: %v", err)
		}
		namespace := getenvDefault("KMS_K8S_NAMESPACE", "default")
		secretName := getenvDefault("KMS_K8S_SECRET_NAME", "kms-root-key")
		sealer = seal.NewK8sSeal(client, namespace, secretName)

	default:
		log.Fatalf("unknown KMS_SEAL_TYPE %q; want one of \"dev\", \"shamir\", \"tpm\", \"k8s\"", sealType)
	}

	store := newStorage("")

	// 조립 순서: seal -> storage -> barrier -> keys -> transit -> rotation.
	// 각 층은 자신보다 아래 층을 인터페이스로만 알고 있으므로, 실제 구현체가
	// 무엇인지 결정해서 서로 연결하는 건 이 main의 책임이다.
	b := barrier.NewBarrier(store, sealer)
	km := keys.NewKeyManager(b)
	ts := transitsvc.NewTransitService(km)
	scheduler := rotation.NewRotationScheduler(km, rotation.WithOnRotate(func(name string) {
		log.Printf("rotation: rotated key %q", name)
	}))

	// 스케줄러는 barrier가 unseal된 상태에서만 실제로 회전을 수행할 수 있다
	// (RotateKey는 sealed 상태면 barrier.ErrSealed를 반환한다). 지금은 단순화를
	// 위해 "부팅 시 자동 unseal된 경우에만" 스케줄러를 함께 시작한다.
	// POST /v1/sys/unseal로 수동 unseal했을 때도 스케줄러를 시작하려면
	// 그 핸들러 쪽에 스케줄러를 전달하는 확장이 필요한데, 지금 범위에서는
	// 그 경계를 의도적으로 남겨둔다.
	//
	// shamir는 애초에 자동 unseal이 불가능하다(threshold명이 각자 조각을
	// 제출해야 하므로) — KMS_AUTO_UNSEAL=true와 조합돼도 barrier.Unseal()이
	// 항상 ErrNotEnoughShares로 실패할 뿐이니, 부팅 자체를 막는 대신 그냥
	// 자동 unseal 시도를 건너뛰고 경고만 남긴다.
	if autoUnseal && sealType == "shamir" {
		log.Print("KMS_AUTO_UNSEAL=true is ignored for KMS_SEAL_TYPE=shamir (shares must be submitted by operators via POST /v1/sys/unseal)")
	} else if autoUnseal {
		if err := b.Unseal(); err != nil {
			log.Fatalf("KMS_AUTO_UNSEAL=true but Unseal failed: %v", err)
		}
		scheduler.Start()
	}

	verifier, err := buildAuthnVerifier()
	if err != nil {
		log.Fatalf("KMS_AUTHN=on but building the ServiceAccount token verifier failed: %v", err)
	}

	authorizer, err := buildAuthzAuthorizer(verifier != nil)
	if err != nil {
		log.Fatalf("KMS_AUTHZ=on but building the authorizer failed: %v", err)
	}

	transitRouter := transit.NewRouter(transit.Deps{
		Barrier:    b,
		Transit:    ts,
		Seal:       sealer,
		Verifier:   verifier,
		Authorizer: authorizer,
	})
	adminRouter := admin.NewRouter(admin.Deps{
		Barrier:         b,
		Keys:            km,
		Seal:            sealer,
		ShamirParts:     shamirParts,
		ShamirThreshold: shamirThreshold,
	})

	// 두 리스너 모두 바인딩을 먼저 동기적으로 끝낸다 — 기동 실패는 goroutine을
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

	transitSrv := &http.Server{Handler: transitRouter}
	adminSrv := &http.Server{Handler: adminRouter}

	log.Printf("kms-system starting: transit=%s admin=%s storage=%s seal=%s sealed=%v",
		transitAddr, adminSocketPath, storageKind, sealer.Type(), b.IsSealed())

	serverErrs := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := transitSrv.Serve(transitListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrs <- err
		}
	}()
	go func() {
		defer wg.Done()
		if err := adminSrv.Serve(adminListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrs <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Print("shutdown signal received, shutting down both listeners")
	case err := <-serverErrs:
		log.Printf("listener failed: %v; shutting down both listeners", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := transitSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("transit listener shutdown error: %v", err)
	}
	if err := adminSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("admin listener shutdown error: %v", err)
	}
	wg.Wait()
}

// buildAuthnVerifier는 KMS_AUTHN에 따라 Transit 라우터에 붙일 인증 검증기를
// 만든다. KMS_AUTHN=off(기본값)면 nil을 반환한다 — Transit 라우터는 nil
// Verifier를 "인증 미들웨어를 등록하지 않음"으로 취급한다. 로컬 개발/테스트가
// 지금 토큰 없는 curl로 이뤄지고 있으므로, 기본 동작을 깨지 않기 위한
// 선택이다.
//
// Admin(유닉스 소켓)에는 이 인증을 적용하지 않는다 — 소켓 파일 권한(0600)과
// 같은 노드 제약으로 이미 보호되며, 관리 API 인증은 별도 과제다.
func buildAuthnVerifier() (*authn.Verifier, error) {
	mode := getenvDefault("KMS_AUTHN", "off")
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
// 만든다. KMS_AUTHZ=off(기본값)면 nil을 반환한다 — Transit 라우터는 nil
// Authorizer를 "인가 미들웨어를 등록하지 않음"으로 취급하고, 인증만
// 통과하면 모든 키에 접근할 수 있다(2단계 이전과 동일한 동작).
//
// authnEnabled는 buildAuthnVerifier의 결과(nil이 아니었는지)를 그대로
// 받는다 — 신원 없이는 권한을 판단할 수 없으므로, KMS_AUTHN=off인데
// KMS_AUTHZ=on이면 설정 오류로 기동을 실패시킨다.
func buildAuthzAuthorizer(authnEnabled bool) (*authz.Authorizer, error) {
	mode := getenvDefault("KMS_AUTHZ", "off")
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

		client, err := authz.NewClientFromEnv(os.Getenv("KMS_KUBECONFIG"))
		if err != nil {
			return nil, err
		}

		return authz.NewAuthorizer(client.AuthorizationV1().SubjectAccessReviews(), authz.Config{
			TTL:      getenvDurationSecondsDefault("KMS_AUTHZ_CACHE_TTL", 10),
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
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
