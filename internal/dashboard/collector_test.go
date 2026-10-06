package dashboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// flakyMetrics는 up이 false일 때 500을 돌려주는 가짜 KMS /metrics다.
func flakyMetrics(t *testing.T, m fixedMetrics) (*httptest.Server, *atomic.Bool) {
	t.Helper()
	var up atomic.Bool
	up.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(m.text()))
	}))
	t.Cleanup(srv.Close)
	return srv, &up
}

func TestCollector_FailureThenRecovery(t *testing.T) {
	srv, up := flakyMetrics(t, metricsA)
	c := NewCollector(srv.URL, time.Second, time.Minute, nil)
	ctx := context.Background()

	if err := c.ScrapeOnce(ctx); err != nil {
		t.Fatalf("first scrape: %v", err)
	}
	if st := c.Status(); !st.OK || st.Samples != 1 || st.LastSuccess == nil || st.LastError != nil {
		t.Fatalf("status after success = %+v", st)
	}

	up.Store(false)
	if err := c.ScrapeOnce(ctx); err == nil {
		t.Fatal("scrape against a failing endpoint must return an error")
	}
	st := c.Status()
	if st.OK || st.LastError == nil || st.Samples != 1 {
		t.Fatalf("status after failure = %+v (want ok=false, error set, old samples kept)", st)
	}
	if _, ok := c.Latest(); ok {
		t.Fatal("Latest must not hand out stale data while scraping is failing")
	}

	up.Store(true)
	if err := c.ScrapeOnce(ctx); err != nil {
		t.Fatalf("scrape after recovery: %v", err)
	}
	if st := c.Status(); !st.OK || st.LastError != nil || st.Samples != 2 {
		t.Fatalf("status after recovery = %+v", st)
	}
}

func TestCollector_UnreachableDoesNotPanic(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // 연결 거부
	c := NewCollector(url, time.Second, time.Minute, nil)
	if err := c.ScrapeOnce(context.Background()); err == nil {
		t.Fatal("expected a connection error")
	}
	if c.Status().OK {
		t.Fatal("status must report failure")
	}
}

func TestCollector_RingBufferCapacity(t *testing.T) {
	srv, _ := flakyMetrics(t, metricsA)
	c := NewCollector(srv.URL, time.Second, 3*time.Second, nil) // 용량 4
	for i := 0; i < 10; i++ {
		if err := c.ScrapeOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := c.Status().Samples; n != 4 {
		t.Fatalf("samples = %d, want capacity 4", n)
	}
}

func TestCollector_DisabledWhenURLEmpty(t *testing.T) {
	c := NewCollector("", time.Second, time.Minute, nil)
	if c.Status().Enabled {
		t.Fatal("empty URL must disable collection")
	}
	c.Run(context.Background()) // 즉시 반환해야 한다
}

// Run 루프가 실패 중에도 죽지 않고 계속 재시도해 회복 후 다시 쌓는지 확인한다.
func TestCollector_RunKeepsRetrying(t *testing.T) {
	srv, up := flakyMetrics(t, metricsA)
	up.Store(false)
	c := NewCollector(srv.URL, 10*time.Millisecond, time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()

	waitFor(t, "failure reported", func() bool { st := c.Status(); return !st.OK && st.LastError != nil })
	up.Store(true)
	waitFor(t, "recovery", func() bool { st := c.Status(); return st.OK && st.Samples >= 2 })

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fakeAdminSocket은 seal-status와 keys 목록을 돌려주는 가짜 admin.sock이다.
func fakeAdminSocket(t *testing.T, sealed bool) (path string, keysCalls *atomic.Int32) {
	t.Helper()
	keysCalls = new(atomic.Int32)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"sealed": sealed, "seal_type": "dev"})
	})
	mux.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		keysCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []string{"secret-a", "secret-b"}})
	})
	path = filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return path, keysCalls
}

func TestStatus_FromMetrics(t *testing.T) {
	srv, _ := flakyMetrics(t, metricsA)
	c := NewCollector(srv.URL, time.Second, time.Minute, nil)
	_ = c.ScrapeOnce(context.Background())

	st := buildStatus(context.Background(), c, nil)
	if st.Sealed == nil || *st.Sealed || st.Keys == nil || *st.Keys != 3 || st.KeyVersions == nil || *st.KeyVersions != 7 {
		t.Fatalf("status = %+v", st)
	}
	if st.LastUnseal == nil || st.LastUnseal.Unix() != 1_700_000_000 {
		t.Fatalf("last_unseal = %v", st.LastUnseal)
	}
	for name, src := range map[string]*string{"sealed": st.Sources.Sealed, "keys": st.Sources.Keys,
		"key_versions": st.Sources.KeyVersions, "last_unseal": st.Sources.LastUnseal} {
		if src == nil || *src != SourceMetrics {
			t.Fatalf("source[%s] = %v, want metrics", name, src)
		}
	}
}

func TestStatus_SocketFallbackWhenScrapeFails(t *testing.T) {
	srv, up := flakyMetrics(t, metricsA)
	c := NewCollector(srv.URL, time.Second, time.Minute, nil)
	_ = c.ScrapeOnce(context.Background())
	up.Store(false)
	_ = c.ScrapeOnce(context.Background())

	sock, _ := fakeAdminSocket(t, false)
	st := buildStatus(context.Background(), c, newSocketClient(sock))

	if st.Sealed == nil || *st.Sealed || st.Keys == nil || *st.Keys != 2 {
		t.Fatalf("status = %+v", st)
	}
	if st.KeyVersions != nil || st.LastUnseal != nil {
		t.Fatal("key_versions and last_unseal exist only in metrics and must be null")
	}
	if *st.Sources.Sealed != SourceSocket || *st.Sources.Keys != SourceSocket ||
		st.Sources.KeyVersions != nil || st.Sources.LastUnseal != nil {
		t.Fatalf("sources = %+v", st.Sources)
	}
	if st.Metrics.OK {
		t.Fatal("metrics.ok must be false")
	}
}

func TestStatus_SocketFallbackWhenCollectionDisabled(t *testing.T) {
	c := NewCollector("", time.Second, time.Minute, nil)
	sock, _ := fakeAdminSocket(t, false)
	st := buildStatus(context.Background(), c, newSocketClient(sock))
	if st.Keys == nil || *st.Keys != 2 || *st.Sources.Keys != SourceSocket || st.Metrics.Enabled {
		t.Fatalf("status = %+v", st)
	}
}

func TestStatus_SealedSkipsKeysCall(t *testing.T) {
	c := NewCollector("", time.Second, time.Minute, nil)
	sock, keysCalls := fakeAdminSocket(t, true)
	st := buildStatus(context.Background(), c, newSocketClient(sock))
	if st.Sealed == nil || !*st.Sealed || st.Keys != nil || st.Sources.Keys != nil {
		t.Fatalf("status = %+v", st)
	}
	if keysCalls.Load() != 0 {
		t.Fatal("/v1/keys must not be called while sealed")
	}
}

func TestStatus_NothingAvailable(t *testing.T) {
	c := NewCollector("", time.Second, time.Minute, nil)
	sock := newSocketClient(filepath.Join(t.TempDir(), "missing.sock"))
	st := buildStatus(context.Background(), c, sock)
	if st.Sealed != nil || st.Keys != nil || st.Sources.Sealed != nil {
		t.Fatalf("status = %+v, want all null", st)
	}
}

func TestStatus_ResponseHasNoKeyNames(t *testing.T) {
	c := NewCollector("", time.Second, time.Minute, nil)
	sock, _ := fakeAdminSocket(t, false)
	raw, _ := json.Marshal(buildStatus(context.Background(), c, newSocketClient(sock)))
	if string(raw) == "" || contains(string(raw), "secret-a") {
		t.Fatalf("key names leaked into status: %s", raw)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
