package seal

import (
	"context"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	tpmsimulator "github.com/google/go-tpm-tools/simulator"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

// benchmarkShamirParts/benchmarkShamirThreshold: RunBenchmark이 shamir를
// 측정할 때 쓰는 고정 파라미터. 벤치마크는 "이 seal 방식이 일반적으로 어떤
// 성격을 갖는가"를 비교하려는 것이지 운영 설정을 흉내내려는 게 아니므로,
// 매번 같은 값으로 고정해 결과를 재현 가능하게 한다.
const (
	benchmarkShamirParts     = 5
	benchmarkShamirThreshold = 3
)

// BenchResult는 Seal 구현체 하나에 대한 벤치마크 결과다.
type BenchResult struct {
	Type     string      `json:"type"`
	InitMs   float64     `json:"init_ms"`
	UnsealMs float64     `json:"unseal_ms"`
	Profile  SealProfile `json:"profile"`
	// Error: 이 seal의 측정 자체가 실패했을 때만 채워진다(예: 이 환경에
	// cgo가 없어서 TPM 시뮬레이터를 못 띄움). 비어 있으면 성공.
	Error string `json:"error,omitempty"`
}

// RunBenchmark은 dev/shamir/tpm/k8s 네 가지 Seal 구현체 각각을 완전히
// 고립된 일회용 인스턴스로 새로 만들어 Init/Unseal에 걸리는 시간을 측정한다.
//
// 왜 매번 "고립된 인스턴스"를 새로 만드는가: 이 함수의 목적은 지금 실제로
// 떠 있는 서버가 어떤 seal로 조립됐는지와 무관하게, 네 가지 방식을 같은
// 조건에서 공정하게 비교하는 것이다. 만약 실제 서버가 쓰는 barrier/storage/
// seal 인스턴스를 그대로 재사용해서 측정하면:
//  1. shamir/tpm/k8s는 이미 한 번 InitShamir/InitTPM/InitK8s가 실행된
//     상태일 수 있어 "이미 초기화됨" 에러로 실패하거나,
//  2. 운 좋게 아직 초기화 전이더라도, 이 벤치마크가 만들어버린 Root Key가
//     실제 운영 중인 barrier의 Root Key를 대체해버리는 사고로 이어진다.
//
// 그래서 각 seal마다 전용 MemoryStorage/fake clientset/새 시뮬레이터를 새로
// 만들고, 측정이 끝나면 그 결과(Root Key, 조각, sealed blob 등)는 전부
// 버려진다 — 실제 서버 상태에는 아무 영향도 주지 않는다.
func RunBenchmark(ctx context.Context) []BenchResult {
	return []BenchResult{
		benchDev(),
		benchShamir(),
		benchTPM(),
		benchK8s(ctx),
	}
}

func benchDev() BenchResult {
	// 이 패스프레이즈는 벤치마크 전용 — 실제 운영 Root Key와는 무관하다.
	s := NewDevSeal("benchmark-only-passphrase-not-a-real-secret")

	// DevSeal은 별도의 init 단계가 없다(패스프레이즈에서 결정론적으로
	// Root Key를 유도할 뿐이라 "초기화"랄 게 없다) — InitMs는 측정 대상이
	// 없다는 뜻으로 0을 그대로 둔다.
	start := time.Now()
	_, err := s.Unseal()
	unsealMs := msSince(start)

	result := BenchResult{Type: "dev", UnsealMs: unsealMs, Profile: s.Profile()}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func benchShamir() BenchResult {
	initStart := time.Now()
	_, shares, err := InitShamir(benchmarkShamirParts, benchmarkShamirThreshold)
	initMs := msSince(initStart)
	if err != nil {
		return BenchResult{Type: "shamir", InitMs: initMs, Profile: shamirProfile(benchmarkShamirThreshold), Error: err.Error()}
	}

	s := NewShamirSeal(benchmarkShamirThreshold)

	// 실제 운영에서는 threshold명의 운영자가 각자 다른 시점에(때로는 몇 시간
	// 간격을 두고) 조각을 제출하지만, 이 벤치마크에는 사람이 없으므로
	// 프로그램이 곧바로 threshold개를 전부 연속 제출한다. 그래서 아래
	// UnsealMs는 "사람이 조각을 찾아 제출하는 데 걸리는 실제 시간"이 아니라
	// "조각이 이미 다 준비된 상태에서 서버 쪽 처리(SubmitShare N회 +
	// Combine)에 걸리는 이상적인 최소 시간"이라는 점을 분명히 해둔다 —
	// 실제 shamir unseal은 이보다 훨씬(사람 개입 시간만큼) 오래 걸린다.
	unsealStart := time.Now()
	for i := 0; i < benchmarkShamirThreshold; i++ {
		if _, err := s.SubmitShare(shares[i]); err != nil {
			return BenchResult{Type: "shamir", InitMs: initMs, Profile: s.Profile(), Error: err.Error()}
		}
	}
	_, err = s.Unseal()
	unsealMs := msSince(unsealStart)

	result := BenchResult{Type: "shamir", InitMs: initMs, UnsealMs: unsealMs, Profile: s.Profile()}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func benchTPM() BenchResult {
	// 이 시뮬레이터와 storage는 이 함수 호출 하나만을 위해 만들어졌다가
	// 함수가 끝나면 버려진다 — 실제 서버가 쓰는 TPM/storage와는 완전히
	// 무관하다.
	sim, err := tpmsimulator.Get()
	if err != nil {
		// CGO_ENABLED=0으로 빌드된 바이너리에서는 시뮬레이터를 아예 쓸 수
		// 없다("using the simulator requires building with CGO") — 이건
		// 이 환경에서 충분히 예상 가능한 실패이므로, 전체 벤치마크를
		// 중단시키지 않고 이 항목만 에러로 채워 반환한다.
		return BenchResult{Type: "tpm", Profile: tpmProfile(), Error: err.Error()}
	}
	defer sim.Close()

	store := storage.NewMemoryStorage()
	s := NewTPMSeal(sim, store)

	initStart := time.Now()
	_, err = s.InitTPM()
	initMs := msSince(initStart)
	if err != nil {
		return BenchResult{Type: "tpm", InitMs: initMs, Profile: s.Profile(), Error: err.Error()}
	}

	unsealStart := time.Now()
	_, err = s.Unseal()
	unsealMs := msSince(unsealStart)

	result := BenchResult{Type: "tpm", InitMs: initMs, UnsealMs: unsealMs, Profile: s.Profile()}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func benchK8s(ctx context.Context) BenchResult {
	// fake.NewSimpleClientset()은 진짜 클러스터 없이 메모리에서만 동작하는
	// clientset이다 — 이 함수 호출 동안만 존재하고 끝나면 사라진다.
	client := k8sfake.NewSimpleClientset()
	s := NewK8sSeal(client, "kms-benchmark", "kms-root-key")

	initStart := time.Now()
	_, err := s.InitK8s(ctx)
	initMs := msSince(initStart)
	if err != nil {
		return BenchResult{Type: "k8s", InitMs: initMs, Profile: s.Profile(), Error: err.Error()}
	}

	unsealStart := time.Now()
	_, err = s.Unseal()
	unsealMs := msSince(unsealStart)

	result := BenchResult{Type: "k8s", InitMs: initMs, UnsealMs: unsealMs, Profile: s.Profile()}
	if err != nil {
		result.Error = err.Error()
	}
	return result
}

func msSince(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}
