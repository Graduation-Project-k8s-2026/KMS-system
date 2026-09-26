package authz

import (
	"sync"
	"time"
)

// cacheKey는 SAR 판단 결과를 캐싱하는 단위다 — 같은 주체가 같은
// namespace에서 같은 키에 같은 동작을 다시 요청하면 apiserver를 다시
// 부르지 않는다.
type cacheKey struct {
	subject   string
	namespace string
	name      string
	verb      string
}

type cacheEntry struct {
	allowed   bool
	expiresAt time.Time
}

// ttlCache는 (주체, namespace, 키 이름, verb) -> 허용/거부 판단을 TTL과
// 개수 상한을 두고 캐싱한다. 허용/거부 둘 다 캐싱한다 — 거부도 캐싱하지
// 않으면 권한이 없는 호출자가 재시도할 때마다 apiserver를 계속 두드리게
// 된다.
type ttlCache struct {
	mu      sync.Mutex
	entries map[cacheKey]cacheEntry
	ttl     time.Duration
	maxSize int
}

func newTTLCache(ttl time.Duration, maxSize int) *ttlCache {
	return &ttlCache{
		entries: make(map[cacheKey]cacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

func (c *ttlCache) get(key cacheKey) (allowed bool, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return false, false
	}
	return entry.allowed, true
}

// set은 판단 결과를 캐싱한다. 이미 개수 상한에 도달했으면 먼저 만료된
// 항목을 정리해 자리를 만들고, 그래도 꽉 차 있으면(즉 아직 만료 안 된
// 항목만 maxSize개 있으면) 이번 항목은 캐싱하지 않고 넘어간다 — 메모리가
// 무한정 늘어나는 것을 막는 게 목적이라, 이 경우 매번 apiserver를 다시
// 부르게 되더라도 정확성보다 상한 준수를 우선한다.
func (c *ttlCache) set(key cacheKey, allowed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictExpiredLocked()
	}
	if len(c.entries) >= c.maxSize {
		return
	}
	c.entries[key] = cacheEntry{allowed: allowed, expiresAt: time.Now().Add(c.ttl)}
}

func (c *ttlCache) evictExpiredLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}
