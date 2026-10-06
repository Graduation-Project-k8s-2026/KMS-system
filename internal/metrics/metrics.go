// Package metrics는 KMS가 Prometheus에 노출하는 지표를 정의하고, 그
// 지표를 채우는 계측 코드(Transit 미들웨어, seal/키 현황 collector)를
// 담는다. 전용 리스너(KMS_METRICS_ADDR, 기본 :9100)로만 서빙되며, Transit/
// Admin과는 별개의 포트다 — 이유는 cmd/server/main.go 주석 참고.
//
// 절대 지키는 규칙: 키 이름, 키 자료, 평문, 암호문, 토큰, 주체(subject)
// 이름, 네임스페이스 이름은 어떤 지표의 값이나 라벨로도 노출하지 않는다.
// 라벨 값의 종류가 늘어날수록 시계열이 그만큼 늘어나고(cardinality),
// 이 값들은 그 자체로 요청 수만큼 다양해질 수 있는 값이라 라벨로 쓰면
// 시계열이 무한정 늘어나거나(cardinality 폭발) 정보가 새어나간다.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// transitLatencyBuckets: 암복호화 요청 지연(초) 히스토그램 버킷. 실제
// 연산(AES-GCM + KEK/DEK 언랩)은 마이크로초~저밀리초 단위로 끝나는 경우가
// 대부분이라, Prometheus 기본 버킷(5ms~10s)으로는 거의 전부 첫 버킷에
// 몰려 무의미해진다. 1µs~10s를 20개 구간으로 로그 등분해, 정상 범위(수십
// ~수백 µs)는 촘촘히 보고 파일 스토리지 I/O 경합이나 GC 정지 같은 드문
// 꼬리 지연까지도(10s까지) 잡을 수 있게 한다.
var transitLatencyBuckets = prometheus.ExponentialBucketsRange(1e-6, 10, 20)

// transitSizeBuckets: 평문/암호문 크기(바이트) 히스토그램 버킷.
// 64B에서 2배씩 12단계 늘려 64B~128KB 구간을 촘촘히 본다.
var transitSizeBuckets = prometheus.ExponentialBuckets(64, 2, 12)

var (
	// TransitRequestsTotal: Transit 암복호화 요청 수. operation은
	// encrypt/decrypt/rewrap, result는 success/error다. 키 이름은 라벨에
	// 넣지 않는다(cardinality/정보 노출).
	TransitRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kms",
		Subsystem: "transit",
		Name:      "requests_total",
		Help:      "Transit 암복호화 요청 수 (operation, result별).",
	}, []string{"operation", "result"})

	// TransitRequestDuration: Transit 암복호화 요청 처리 시간(초).
	TransitRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "kms",
		Subsystem: "transit",
		Name:      "request_duration_seconds",
		Help:      "Transit 암복호화 요청 처리 시간(초) (operation별).",
		Buckets:   transitLatencyBuckets,
	}, []string{"operation"})

	// TransitPayloadBytes: 처리한 평문/암호문 크기(바이트).
	TransitPayloadBytes = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "kms",
		Subsystem: "transit",
		Name:      "payload_bytes",
		Help:      "처리한 평문/암호문 크기(바이트) (operation별).",
		Buckets:   transitSizeBuckets,
	}, []string{"operation"})

	// AuthzSARRequestsTotal: SubjectAccessReview 호출 수. result는
	// allowed/denied/error다. 주체·namespace는 라벨에 넣지 않는다.
	AuthzSARRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kms",
		Subsystem: "authz",
		Name:      "sar_requests_total",
		Help:      "SubjectAccessReview 호출 수 (result별: allowed/denied/error).",
	}, []string{"result"})

	// AuthzSARDuration: SubjectAccessReview 호출 지연(초). 이건 apiserver로
	// 나가는 네트워크 호출이라 Transit과 시간 단위가 다르므로(밀리초~초),
	// Prometheus 기본 버킷(DefBuckets, 5ms~10s)이 그대로 적합하다.
	AuthzSARDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "kms",
		Subsystem: "authz",
		Name:      "sar_duration_seconds",
		Help:      "SubjectAccessReview 호출 지연(초).",
		Buckets:   prometheus.DefBuckets,
	})

	// AuthzCacheRequestsTotal: 인가 캐시 조회 수. result는 hit/miss다.
	AuthzCacheRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "kms",
		Subsystem: "authz",
		Name:      "cache_requests_total",
		Help:      "인가 판단 캐시 조회 수 (result별: hit/miss).",
	}, []string{"result"})

	// AuthzCacheEntries: 현재 인가 캐시에 들어있는 항목 수.
	AuthzCacheEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "kms",
		Subsystem: "authz",
		Name:      "cache_entries",
		Help:      "현재 인가 판단 캐시에 들어있는 항목 수.",
	})

	// AuthzAPIServerRoundtripDuration: SubjectAccessReview 호출의 순수 HTTP
	// 왕복 시간(초) — client-go의 클라이언트 측 rate limiter 대기는 제외한다.
	// AuthzSARDuration(대기+왕복 합산)에서 이 지표를 빼면(두 히스토그램의
	// _sum을 Prometheus에서 비교) rate limiter 대기 시간만 분리해서 볼 수
	// 있다 — ADR-008(docs/decisions.md)에서 다룬 "토큰 고갈로 매 요청이
	// 200ms씩 걸리는" 문제를 메트릭만 보고 바로 알아챌 수 있게 하기 위함.
	AuthzAPIServerRoundtripDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "kms",
		Subsystem: "authz",
		Name:      "apiserver_roundtrip_seconds",
		Help:      "SubjectAccessReview 호출의 순수 HTTP 왕복 시간(초, rate limiter 대기 제외).",
		Buckets:   prometheus.DefBuckets,
	})
)
