package authz

import (
	"context"
	"log/slog"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authzv1client "k8s.io/client-go/kubernetes/typed/authorization/v1"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
)

// defaultCacheTTL: 캐시 항목이 살아있는 기본 시간. 짧게 잡은 이유: 이
// 값이 곧 "권한을 회수한 뒤에도 예전 판단이 계속 통할 수 있는 최대
// 시간"이다 — 관리자가 RoleBinding을 지워도 최대 이 시간만큼은 이미
// 캐싱된 "허용"이 계속 통과될 수 있다. 10초는 매 암복호화 요청마다
// apiserver를 두드리는 것(핫패스 지연)을 막을 만큼 길고, 권한 회수
// 반영 지연을 실무적으로 감내할 만큼은 짧다.
const defaultCacheTTL = 10 * time.Second

// defaultTimeout: SubjectAccessReview 호출 하나에 허용하는 최대 시간.
// apiserver가 응답하지 않을 때 요청이 무한정 걸리지 않도록 짧게 잡는다.
const defaultTimeout = 3 * time.Second

// defaultMaxCacheEntries: 캐시가 가질 수 있는 최대 항목 수. 항목 하나가
// 문자열 4개 + bool + time.Time 정도로 작아서, 이 개수로도 메모리 사용량은
// 무시할 수준이다 — 그보다는 "한도가 있다"는 사실 자체가 중요하다(요청마다
// 새로운 (주체, namespace, 키, verb) 조합이 계속 생기는 악의적/버그
// 상황에서도 메모리가 무한정 늘지 않게).
const defaultMaxCacheEntries = 10000

// Config는 Authorizer의 동작을 정한다.
type Config struct {
	// TTL: 캐시 항목의 유효 기간.
	//   - 0 (기본값, 설정 안 함): defaultCacheTTL(10초)을 쓴다 — 하위호환을
	//     위해 기존 동작을 그대로 유지한다.
	//   - 양수: 그 값을 그대로 쓴다.
	//   - 음수: 캐시를 완전히 비활성화한다 — 조회·저장을 모두 건너뛰고 매
	//     요청 apiserver에 SubjectAccessReview를 묻는다. 캐싱 효과를
	//     분리해서 측정하는 성능 실험이나, 권한 변경이 즉시 반영돼야 하는
	//     환경에서 쓴다.
	TTL time.Duration
	// Timeout: SubjectAccessReview 호출 하나의 타임아웃. 0이면
	// defaultTimeout을 쓴다.
	Timeout time.Duration
	// MaxCacheEntries: 캐시 최대 크기. 0이면 defaultMaxCacheEntries를 쓴다.
	MaxCacheEntries int
	// FailOpen: apiserver 호출 자체가 실패(타임아웃/네트워크 에러 등)했을
	// 때 거부(false, 기본) 대신 허용(true)할지. 보안 도구이므로 기본은
	// fail-closed다 — 판단할 수 없으면 거부하는 쪽이 안전하다.
	FailOpen bool
}

// Authorizer는 SubjectAccessReview로 "이 주체가 이 키에 이 동작을 해도
// 되는가"를 판단한다. 판단 결과는 캐싱한다 — 암복호화는 요청마다 일어나는
// 핫패스라 매번 apiserver를 왕복하면 지연이 크다. cache가 nil이면(Config.TTL
// 이 음수로 설정된 경우) 캐싱 자체를 하지 않는다 — Allowed가 매번 nil
// 체크로 그 경로를 건너뛴다.
type Authorizer struct {
	client authzv1client.SubjectAccessReviewInterface
	cache  *ttlCache // nil이면 캐시 비활성화(Config.TTL < 0)
	cfg    Config
}

// NewAuthorizer는 client(보통 kubernetes.Interface의
// AuthorizationV1().SubjectAccessReviews())와 cfg로 Authorizer를 만든다.
func NewAuthorizer(client authzv1client.SubjectAccessReviewInterface, cfg Config) *Authorizer {
	cacheDisabled := cfg.TTL < 0

	if cfg.TTL == 0 {
		cfg.TTL = defaultCacheTTL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}
	if cfg.MaxCacheEntries <= 0 {
		cfg.MaxCacheEntries = defaultMaxCacheEntries
	}

	var cache *ttlCache
	if !cacheDisabled {
		cache = newTTLCache(cfg.TTL, cfg.MaxCacheEntries)
	}

	return &Authorizer{
		client: client,
		cache:  cache,
		cfg:    cfg,
	}
}

// Allowed는 identity가 resourceName(키 이름)에 verb(encrypt/decrypt/rewrap)
// 동작을 해도 되는지 판단한다. 캐시에 신선한 항목이 있으면 그것을 쓰고,
// 없으면 SubjectAccessReview를 생성해 apiserver에 묻는다.
//
// apiserver 호출 자체가 실패하면(캐시 미스 상태에서) cfg.FailOpen에 따라
// 허용/거부를 정하고, 이 폴백 결정 자체는 캐싱하지 않는다 — apiserver
// 장애가 일시적일 수 있으므로, 복구되면 곧바로 실제 판단으로 돌아가야
// 한다. 반면 apiserver가 실제로 응답한 허용/거부는(성공한 호출) 결과와
// 무관하게 캐싱한다.
func (a *Authorizer) Allowed(ctx context.Context, identity authn.Identity, resourceName, verb string) bool {
	key := cacheKey{subject: identity.Subject, namespace: identity.Namespace, name: resourceName, verb: verb}

	if a.cache != nil {
		if allowed, fresh := a.cache.get(key); fresh {
			metrics.AuthzCacheRequestsTotal.WithLabelValues("hit").Inc()
			return allowed
		}
	}
	// 캐시가 비활성화됐을 때도(a.cache == nil) miss를 그대로 기록한다 —
	// 매 요청이 miss로 집계되는 것 자체가 "캐시가 꺼져 있다"는 신호다.
	metrics.AuthzCacheRequestsTotal.WithLabelValues("miss").Inc()

	reqCtx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
	defer cancel()

	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   identity.Subject,
			Groups: identity.Groups,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: identity.Namespace,
				Verb:      verb,
				Group:     APIGroup,
				Resource:  Resource,
				Name:      resourceName,
			},
		},
	}

	start := time.Now()
	result, err := a.client.Create(reqCtx, sar, metav1.CreateOptions{})
	metrics.AuthzSARDuration.Observe(time.Since(start).Seconds())

	if err != nil {
		metrics.AuthzSARRequestsTotal.WithLabelValues("error").Inc()
		slog.Error("authz: SubjectAccessReview call failed",
			"subject", identity.Subject, "namespace", identity.Namespace,
			"key", resourceName, "verb", verb, "error", err, "fail_open", a.cfg.FailOpen)
		return a.cfg.FailOpen
	}

	allowed := result.Status.Allowed
	if a.cache != nil {
		a.cache.set(key, allowed)
		metrics.AuthzCacheEntries.Set(float64(a.cache.size()))
	}

	if allowed {
		metrics.AuthzSARRequestsTotal.WithLabelValues("allowed").Inc()
	} else {
		metrics.AuthzSARRequestsTotal.WithLabelValues("denied").Inc()
		slog.Warn("authz: denied",
			"subject", identity.Subject, "namespace", identity.Namespace,
			"key", resourceName, "verb", verb, "reason", result.Status.Reason)
	}

	return allowed
}
