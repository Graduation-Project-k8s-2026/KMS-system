package transit

import (
	"fmt"
	"testing"
	"time"
)

func fakeGuard(rps float64, burst, failMax int) (*ipGuard, *time.Time) {
	g := newIPGuard(rps, burst, failMax)
	now := time.Unix(1_700_000_000, 0)
	g.now = func() time.Time { return now }
	return g, &now
}

func TestGuard_TokenBucketPerIP(t *testing.T) {
	g, now := fakeGuard(2, 3, 10)
	for i := 0; i < 3; i++ {
		if ok, _, _ := g.allow("1.1.1.1"); !ok {
			t.Fatalf("burst request %d rejected", i)
		}
	}
	ok, reason, retry := g.allow("1.1.1.1")
	if ok || reason != "rate" || retry < 1 {
		t.Fatalf("4th = %v %q %d", ok, reason, retry)
	}
	if ok, _, _ := g.allow("2.2.2.2"); !ok { // 다른 IP는 영향 없음
		t.Fatal("other IP throttled")
	}
	*now = now.Add(time.Second) // 2 토큰 보충
	if ok, _, _ := g.allow("1.1.1.1"); !ok {
		t.Fatal("not refilled")
	}
}

func TestGuard_AuthFailBlocksFiveMinutesThenReleases(t *testing.T) {
	g, now := fakeGuard(1000, 1000, 3)
	for i := 0; i < 3; i++ {
		g.authFailed("9.9.9.9")
	}
	if ok, _, _ := g.allow("9.9.9.9"); !ok {
		t.Fatal("blocked at exactly the limit; must block only when exceeded")
	}
	g.authFailed("9.9.9.9") // 4번째 → 한도 초과
	if ok, reason, _ := g.allow("9.9.9.9"); ok || reason != "authfail" {
		t.Fatalf("not blocked: %v %q", ok, reason)
	}
	if g.blocked() != 1 {
		t.Fatalf("blocked count = %d", g.blocked())
	}
	if ok, _, _ := g.allow("8.8.8.8"); !ok {
		t.Fatal("other IP blocked")
	}
	*now = now.Add(5*time.Minute + time.Second)
	if ok, _, _ := g.allow("9.9.9.9"); !ok || g.blocked() != 0 {
		t.Fatal("block did not expire")
	}
}

func TestGuard_AuthFailWindowResets(t *testing.T) {
	g, now := fakeGuard(1000, 1000, 3)
	for i := 0; i < 3; i++ {
		g.authFailed("a")
	}
	*now = now.Add(61 * time.Second)
	for i := 0; i < 3; i++ {
		g.authFailed("a")
	}
	if ok, _, _ := g.allow("a"); !ok {
		t.Fatal("failures outside the 1-minute window must not accumulate")
	}
}

func TestGuard_MapIsBounded(t *testing.T) {
	g, now := fakeGuard(10, 10, 5)
	for i := 0; i < maxTrackedIPs+5000; i++ {
		g.allow(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
		*now = now.Add(time.Millisecond)
	}
	if g.size() > maxTrackedIPs {
		t.Fatalf("tracked IPs = %d, want <= %d", g.size(), maxTrackedIPs)
	}
	// 오래 안 보인 항목은 정리된다
	*now = now.Add(time.Hour)
	g.allow("new")
	for i := 0; i < 5; i++ {
		g.allow(fmt.Sprintf("x%d", i))
	}
	g.mu.Lock()
	g.lastSweep = time.Time{}
	g.mu.Unlock()
	g.allow("trigger-sweep")
	if g.size() > 20 {
		t.Fatalf("idle entries not evicted: %d", g.size())
	}
}
