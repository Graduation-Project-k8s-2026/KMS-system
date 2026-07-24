// cmd/server: KMS 서버 실행 진입점. 여기서 모든 층(seal, storage, barrier,
// keys, transit, rotation, api)을 실제 구현체로 조립한다 — "무엇을 쓸지
// 결정하고 서로 연결하는" 책임은 main에 있고, "요청을 어떻게 처리할지"는
// api 패키지의 책임이다.
package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/google/go-tpm-tools/simulator"
	tpm2 "github.com/google/go-tpm/legacy/tpm2"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/rotation"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

func main() {
	storageKind := getenvDefault("KMS_STORAGE", "file")
	dataDir := getenvDefault("KMS_DATA_DIR", "./data")
	port := getenvDefault("PORT", "8200")
	autoUnseal := os.Getenv("KMS_AUTO_UNSEAL") == "true"

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
	// api.Deps에 그대로 전달해 POST /v1/sys/init(InitShamir 호출)과
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
	ts := transit.NewTransitService(km)
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

	router := api.NewRouter(api.Deps{
		Barrier:         b,
		Keys:            km,
		Transit:         ts,
		Seal:            sealer,
		ShamirParts:     shamirParts,
		ShamirThreshold: shamirThreshold,
	})

	log.Printf("kms-system starting: port=%s storage=%s seal=%s sealed=%v",
		port, storageKind, sealer.Type(), b.IsSealed())

	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("server stopped: %v", err)
	}
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
