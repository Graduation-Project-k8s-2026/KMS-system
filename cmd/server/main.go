// cmd/server: KMS 서버 실행 진입점. 여기서 모든 층(seal, storage, barrier,
// keys, transit, rotation, api)을 실제 구현체로 조립한다 — "무엇을 쓸지
// 결정하고 서로 연결하는" 책임은 main에 있고, "요청을 어떻게 처리할지"는
// api 패키지의 책임이다.
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/rotation"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

func main() {
	masterKey := os.Getenv("KMS_MASTER_KEY")
	if masterKey == "" {
		log.Fatal("KMS_MASTER_KEY is not set; DevSeal needs a passphrase to derive the Root Key")
	}

	storageKind := getenvDefault("KMS_STORAGE", "file")
	dataDir := getenvDefault("KMS_DATA_DIR", "./data")
	port := getenvDefault("PORT", "8200")
	autoUnseal := os.Getenv("KMS_AUTO_UNSEAL") == "true"

	sealer := seal.NewDevSeal(masterKey)

	var store storage.StorageBackend
	switch storageKind {
	case "memory":
		store = storage.NewMemoryStorage()
	case "file":
		store = storage.NewFileStorage(dataDir)
	default:
		log.Fatalf("unknown KMS_STORAGE %q; want \"memory\" or \"file\"", storageKind)
	}

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
	if autoUnseal {
		if err := b.Unseal(); err != nil {
			log.Fatalf("KMS_AUTO_UNSEAL=true but Unseal failed: %v", err)
		}
		scheduler.Start()
	}

	router := api.NewRouter(api.Deps{Barrier: b, Keys: km, Transit: ts})

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
