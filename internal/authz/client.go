package authz

import (
	"fmt"
	"net/http"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// DefaultQPS/DefaultBurst: 이 클라이언트가 apiserver에 SubjectAccessReview를
// 보내는 속도의 기본 상한. client-go 자체 기본값(QPS 5, Burst 10)은 가끔
// list/watch하고 드물게 patch하는 컨트롤러용이라, 캐시 미스마다 매번 호출하는
// 이 핫패스에는 너무 낮다 — 버스트(10) 이후로는 초당 5개까지만 토큰이
// 채워져, 동시 요청이 몰리면 요청마다 수백 ms씩 대기하다가 KMS_AUTHZ_TIMEOUT
// (기본 3초)을 넘겨 fail-closed로 403이 나는 가용성 버그가 실측으로 확인됐다
// (docs/decisions.md ADR-008).
//
// 50/100으로 올린 근거:
//   - Burst = 2×QPS는 짧은 스파이크를 흡수하는 통상적인 비율이다.
//   - SubjectAccessReview Create는 etcd를 쓰지 않는 가벼운 승인 심사
//     호출이라, 단일 KMS 인스턴스가 거는 50 QPS는 apiserver 전체 처리
//     예산에서 무시할 수준이고, 웬만한 API Priority and Fairness 우선순위
//     레벨의 동시성 셰어 안에도 넉넉히 들어간다.
//   - Burst=100이면 캐시가 한꺼번에 비워지는 상황(권한 변경, 재배포 등)에서
//     최대 100개까지 즉시 통과하고 나머지는 초당 50개로 유입 제한되므로,
//     동시 요청이 대략 150개 이하인 스파이크는 KMS_AUTHZ_TIMEOUT 기본값(3초)
//     안에 큐가 풀려 이번 버그가 재발하지 않는다. 더 큰 스파이크가 예상되면
//     운영자가 이 두 환경변수를 올리거나, 캐시 TTL을 늘려 미스 자체를
//     줄이는 쪽을 먼저 검토해야 한다.
const (
	DefaultQPS   float32 = 50
	DefaultBurst int     = 100
)

// ResolveRateLimit은 qps/burst를 Config.TTL과 똑같은 3단 규칙으로 해석한다:
//   - 0: 기본값(DefaultQPS/DefaultBurst)을 쓴다.
//   - 양수: 그 값을 그대로 쓴다.
//   - 음수(둘 중 하나라도): 클라이언트 측 속도 제한을 완전히 비활성화한다.
//     QPS와 Burst는 하나의 rate limiter를 함께 구성하는 값이라 둘을 따로
//     "비활성화"할 수 없으므로, 어느 한쪽이라도 음수면 전체를 끈다.
//
// 이 함수는 순수 함수라 cmd/server가 기동 로그에 남길 "실제 적용된 값"을
// (네트워크 호출 없이) 미리 알아내는 데도 쓰인다.
func ResolveRateLimit(qps float32, burst int) (effectiveQPS float32, effectiveBurst int, disabled bool) {
	if qps < 0 || burst < 0 {
		return 0, 0, true
	}
	if qps == 0 {
		qps = DefaultQPS
	}
	if burst == 0 {
		burst = DefaultBurst
	}
	return qps, burst, false
}

// roundTripperFunc는 http.RoundTripper 인터페이스를 함수 하나로 만족시키는
// 어댑터다 — instrumentedTransport 하나 때문에 별도 struct를 만들 필요가 없다.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// instrumentTransport는 rest.Config.WrapTransport에 꽂아, client-go가 이미
// 구성한(인증 헤더, TLS 등을 다 씌운) RoundTripper 위에 한 겹 더 씌워 "실제
// HTTP 왕복 시간"만 측정한다. rate limiter 대기는 RoundTrip 호출 전(client-go
// 내부, Request.Do 단계)에 끝나므로 이 계측 바깥이다 — kms_authz_sar_duration
// _seconds(대기+왕복 합산, Allowed()에서 측정)에서 이 왕복 시간을 빼면
// rate limiter 대기만 분리해서 볼 수 있다. WrapTransport는 client-go 자신의
// 메트릭 계측도 쓰는 공식 확장점이라, 내부 구조에 의존하지 않는다.
func instrumentTransport(rt http.RoundTripper) http.RoundTripper {
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		start := time.Now()
		resp, err := rt.RoundTrip(req)
		metrics.AuthzAPIServerRoundtripDuration.Observe(time.Since(start).Seconds())
		return resp, err
	})
}

// NewClientFromEnv는 KMS_KUBECONFIG로 kube-apiserver 클라이언트를 만든다.
// qps/burst는 ResolveRateLimit과 같은 규칙으로 해석된다.
//
// KMS는 static pod로 배포되므로 ServiceAccount 토큰이 자동 마운트되지
// 않는다(kubelet이 매니페스트를 직접 읽어 생성하므로 admission
// controller를 거치지 않는다 — internal/authn 패키지 주석 참고). 그래서
// in-cluster config를 무조건 먼저 시도하는 대신, KMS_KUBECONFIG가
// 설정돼 있으면 그 kubeconfig 파일을 우선 쓴다 — static pod에 자격
// 증명을 명시적으로 마운트해줄 방법(예: hostPath로 kubeconfig 파일 마운트)
// 이 실제 배포 경로가 될 것이기 때문이다. KMS_KUBECONFIG가 비어 있을
// 때만 in-cluster config를 시도한다(일반 Deployment로 재배치되거나,
// 나중에 static pod가 아니게 되는 경우를 대비).
func NewClientFromEnv(kubeconfigPath string, qps float32, burst int) (kubernetes.Interface, error) {
	var (
		cfg *rest.Config
		err error
	)

	if kubeconfigPath != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("authz: failed to load kubeconfig at %q (from KMS_KUBECONFIG): %w", kubeconfigPath, err)
		}
	} else {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("authz: KMS_KUBECONFIG is not set and in-cluster config is unavailable: %w", err)
		}
	}

	applyRateLimit(cfg, qps, burst)
	cfg.WrapTransport = instrumentTransport

	return kubernetes.NewForConfig(cfg)
}

// applyRateLimit은 ResolveRateLimit의 결과를 cfg에 반영한다. 네트워크
// 호출이 전혀 없는 순수한 *rest.Config 조작이라, 실제 클러스터 접속 없이도
// (NewClientFromEnv와 달리) 직접 단위 테스트할 수 있다.
func applyRateLimit(cfg *rest.Config, qps float32, burst int) {
	effQPS, effBurst, disabled := ResolveRateLimit(qps, burst)
	if disabled {
		// RateLimiter가 설정되면 QPS/Burst 필드는 완전히 무시된다(client-go
		// rest.Config 문서 참고) — NewFakeAlwaysRateLimiter는 매 요청을
		// 즉시 통과시킨다.
		cfg.RateLimiter = flowcontrol.NewFakeAlwaysRateLimiter()
		return
	}
	cfg.QPS = effQPS
	cfg.Burst = effBurst
}
