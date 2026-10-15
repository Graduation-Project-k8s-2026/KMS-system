package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
)

var (
	sealSealedDesc = prometheus.NewDesc(
		"kms_seal_sealed", "barrier가 현재 sealed 상태인지 (1=sealed, 0=unsealed).", nil, nil)
	sealLastUnsealedDesc = prometheus.NewDesc(
		"kms_seal_last_unsealed_timestamp_seconds",
		"실제 barrier unseal 성공 시각(Unix epoch 초), 현재 프로세스에서 아직 없으면 0.",
		nil, nil)
	keysTotalDesc = prometheus.NewDesc(
		"kms_keys_total", "현재 등록된 키 개수.", nil, nil)
	keyVersionsTotalDesc = prometheus.NewDesc(
		"kms_key_versions_total", "모든 키의 버전 총합(회전으로 늘어난 버전 수 포함).", nil, nil)
)

// sealStater/keyLister는 *barrier.Barrier / *keys.KeyManager가 실제로
// 만족하는 최소 인터페이스다 — SealKeyCollector를 테스트할 때 가벼운
// 스텁으로 대체할 수 있게 이렇게 좁혀둔다.
type sealStater interface {
	IsSealed() bool
}

type keyLister interface {
	ListKeys() ([]string, error)
	GetKeyMeta(name string) (keys.KeyRingMeta, error)
}

// SealKeyCollector는 seal 상태와 키 현황을 스크레이프 시점에 조회해
// 노출하는 prometheus.Collector다. barrier/keys 안에 상시 갱신되는 값을
// 두는 대신(코어 패키지를 건드려야 한다), 매 /metrics 요청마다 그 자리에서
// IsSealed/ListKeys/GetKeyMeta를 호출한다 — 구현이 훨씬 단순하고, 코어
// 로직에는 전혀 손대지 않는다.
type SealKeyCollector struct {
	seal sealStater
	keys keyLister

	mu             sync.Mutex
	everUnsealedAt time.Time // 마지막으로 unsealed를 관찰한 시각. 초기값(zero)이면 "아직 없음".
}

// NewSealKeyCollector는 b(seal 상태)와 km(키 현황)을 조회하는 collector를
// 만든다.
func NewSealKeyCollector(b *barrier.Barrier, km *keys.KeyManager) *SealKeyCollector {
	return &SealKeyCollector{seal: b, keys: km}
}

func (c *SealKeyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- sealSealedDesc
	ch <- sealLastUnsealedDesc
	ch <- keysTotalDesc
	ch <- keyVersionsTotalDesc
}

func (c *SealKeyCollector) Collect(ch chan<- prometheus.Metric) {
	sealed := c.seal.IsSealed()

	sealedValue := 0.0
	if sealed {
		sealedValue = 1.0
	}
	ch <- prometheus.MustNewConstMetric(sealSealedDesc, prometheus.GaugeValue, sealedValue)

	lastUnsealed := c.observeUnsealed(sealed)
	if actual, ok := c.seal.(interface{ LastUnseal() time.Time }); ok {
		lastUnsealed = 0
		if t := actual.LastUnseal(); !t.IsZero() {
			lastUnsealed = float64(t.Unix())
		}
	}
	ch <- prometheus.MustNewConstMetric(sealLastUnsealedDesc, prometheus.GaugeValue, lastUnsealed)

	// sealed 상태에서는 barrier.GetJSON이 항상 ErrSealed를 반환해 키
	// 목록/버전을 읽을 수 없다 — 에러로 취급해 노이즈를 만드는 대신, "지금
	// 이 데이터를 볼 수 없다"는 사실 자체를 0으로 표현한다.
	keysTotal, versionsTotal := 0.0, 0.0
	if !sealed {
		keysTotal, versionsTotal = c.collectKeyCounts()
	}
	ch <- prometheus.MustNewConstMetric(keysTotalDesc, prometheus.GaugeValue, keysTotal)
	ch <- prometheus.MustNewConstMetric(keyVersionsTotalDesc, prometheus.GaugeValue, versionsTotal)
}

func (c *SealKeyCollector) observeUnsealed(sealed bool) float64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !sealed {
		c.everUnsealedAt = time.Now()
	}
	if c.everUnsealedAt.IsZero() {
		return 0
	}
	return float64(c.everUnsealedAt.Unix())
}

func (c *SealKeyCollector) collectKeyCounts() (keysTotal, versionsTotal float64) {
	names, err := c.keys.ListKeys()
	if err != nil {
		return 0, 0
	}

	versions := 0
	for _, name := range names {
		meta, err := c.keys.GetKeyMeta(name)
		if err != nil {
			continue
		}
		versions += len(meta.Versions)
	}
	return float64(len(names)), float64(versions)
}
