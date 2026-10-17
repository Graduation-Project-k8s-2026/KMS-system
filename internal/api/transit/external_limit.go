package transit

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// clientIP는 TCP 연결의 상대 주소(RemoteAddr)에서 IP만 꺼낸다. X-Forwarded-For는 클라이언트가 마음대로 쓸 수 있는
// 헤더라 신뢰하지 않는다 (외부 리스너는 프록시 없이 직접 받는다).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

const (
	maxTrackedIPs    = 10000            // 추적하는 IP 수 상한: 메모리가 무한히 늘지 않게
	idleEvictAfter   = 10 * time.Minute // 이 시간 동안 안 보인 IP 항목은 정리
	authFailWindow   = time.Minute      // 인증 실패를 세는 구간
	authFailBlockFor = 5 * time.Minute  // 한도를 넘으면 차단하는 시간
)

type ipState struct {
	// 토큰 버킷
	tokens float64
	last   time.Time
	// 인증 실패 카운터(구간 시작 + 횟수)와 차단 해제 시각
	failStart    time.Time
	fails        int
	blockedUntil time.Time
}

// ipGuard는 클라이언트 IP별 요청 수 제한(토큰 버킷)과 인증 실패 과다 차단을 맡는다.
type ipGuard struct {
	rps         float64
	burst       float64
	authFailMax int
	now         func() time.Time

	mu        sync.Mutex
	ips       map[string]*ipState
	lastSweep time.Time
}

func newIPGuard(rps float64, burst, authFailMax int) *ipGuard {
	return &ipGuard{rps: rps, burst: float64(burst), authFailMax: authFailMax, now: time.Now, ips: map[string]*ipState{}}
}

// stateLocked는 IP의 상태를 돌려준다(없으면 만든다). 상한에 닿으면 오래 안 보인 항목부터 정리하고,
// 그래도 가득 차면 가장 오래전에 본 항목 하나를 쫓아낸다 (차단 중인 항목은 가능하면 보존).
func (g *ipGuard) stateLocked(ip string, now time.Time) *ipState {
	if st, ok := g.ips[ip]; ok {
		return st
	}
	if now.Sub(g.lastSweep) > time.Minute || (len(g.ips) >= maxTrackedIPs && now.Sub(g.lastSweep) > time.Second) {
		g.lastSweep = now
		for k, v := range g.ips {
			if now.Sub(v.last) > idleEvictAfter && now.After(v.blockedUntil) {
				delete(g.ips, k)
			}
		}
	}
	if len(g.ips) >= maxTrackedIPs {
		// 정리해도 가득 차 있으면(서로 다른 IP가 대량으로 몰림) 차단 중이 아닌 항목 1%를 한꺼번에 비운다.
		// 항목 하나씩 가장 오래된 것을 찾으면 요청마다 전체를 훑어야 해서 공격 중에 오히려 느려진다.
		drop := maxTrackedIPs / 100
		for k, v := range g.ips {
			if drop == 0 {
				break
			}
			if now.Before(v.blockedUntil) {
				continue
			}
			delete(g.ips, k)
			drop--
		}
	}
	st := &ipState{tokens: g.burst, last: now}
	g.ips[ip] = st
	return st
}

// allow는 요청 하나를 받아도 되는지 판단한다. 거절이면 이유("authfail"|"rate")와 재시도 대기 초를 돌려준다.
func (g *ipGuard) allow(ip string) (ok bool, reason string, retryAfter int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	st := g.stateLocked(ip, now)
	if now.Before(st.blockedUntil) {
		return false, "authfail", int(st.blockedUntil.Sub(now).Seconds()) + 1
	}
	st.tokens += now.Sub(st.last).Seconds() * g.rps
	if st.tokens > g.burst {
		st.tokens = g.burst
	}
	st.last = now
	if st.tokens < 1 {
		return false, "rate", int((1-st.tokens)/g.rps) + 1
	}
	st.tokens--
	return true, "", 0
}

// authFailed는 인증 실패(401) 한 번을 기록하고, 1분 안에 한도를 넘으면 5분 차단한다.
func (g *ipGuard) authFailed(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	st := g.stateLocked(ip, now)
	if now.Sub(st.failStart) > authFailWindow {
		st.failStart, st.fails = now, 0
	}
	st.fails++
	if st.fails > g.authFailMax {
		st.blockedUntil = now.Add(authFailBlockFor)
		st.fails = 0
	}
}

// blocked는 지금 차단 중인 IP 개수다 (지표용; IP 값은 내보내지 않는다).
func (g *ipGuard) blocked() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	now, n := g.now(), 0
	for _, st := range g.ips {
		if now.Before(st.blockedUntil) {
			n++
		}
	}
	return n
}

func (g *ipGuard) size() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.ips) }
