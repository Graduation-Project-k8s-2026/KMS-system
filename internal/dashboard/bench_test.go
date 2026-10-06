package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func benchJSON(label string, concs ...int) []byte {
	runs := []map[string]any{}
	for _, c := range concs {
		runs = append(runs, map[string]any{
			"scenario": "concurrency", "operation": "encrypt", "payload_bytes": 1024,
			"concurrency": c, "ops_per_sec": 1234.5, "success_count": 100, "error_count": 0,
			"latency":      map[string]any{"mean_seconds": 0.001, "p50_seconds": 0.001, "p99_seconds": 0.002, "max_seconds": 0.01},
			"future_field": "kept",
		})
	}
	raw, _ := json.Marshal(map[string]any{
		"label": label, "timestamp": "2026-10-06T12:48:56+09:00", "addr": "http://localhost:8200",
		"key": "demo", "environment": map[string]any{"go_version": "go1.23"}, "runs": runs,
	})
	return raw
}

func newTestService(t *testing.T, maxBytes int64, maxFiles int) (*Service, string, http.Handler) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bench")
	store, err := NewBenchStore(dir, maxBytes, maxFiles)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{Bench: store, Collector: NewCollector("", time.Second, time.Minute, nil)}
	r := chi.NewRouter()
	svc.Mount(r)
	return svc, dir, r
}

func do(h http.Handler, method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestBench_UploadStoresRawJSON(t *testing.T) {
	_, dir, h := newTestService(t, 0, 0)
	body := benchJSON("authz-cached", 1, 10)

	rec := do(h, "POST", "/api/bench/results", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d body=%s", rec.Code, rec.Body)
	}
	var created struct {
		ID   string `json:"id"`
		Runs int    `json:"runs"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !strings.HasSuffix(created.ID, "-authz-cached") || created.Runs != 2 {
		t.Fatalf("created = %+v", created)
	}

	onDisk, err := os.ReadFile(filepath.Join(dir, created.ID+".json"))
	if err != nil || !bytes.Equal(onDisk, body) {
		t.Fatalf("stored file differs from the uploaded bytes (err=%v)", err)
	}

	got := do(h, "GET", "/api/bench/results/"+created.ID, nil)
	if got.Code != 200 || !bytes.Equal(got.Body.Bytes(), body) {
		t.Fatalf("GET one = %d, body mismatch", got.Code)
	}

	list := do(h, "GET", "/api/bench/results", nil)
	var metas []BenchMeta
	_ = json.Unmarshal(list.Body.Bytes(), &metas)
	if len(metas) != 1 || metas[0].ID != created.ID || metas[0].Label != "authz-cached" ||
		metas[0].Conditions != 2 || len(metas[0].Scenarios) != 1 || metas[0].Scenarios[0] != "concurrency" {
		t.Fatalf("list = %s", list.Body)
	}

	if del := do(h, "DELETE", "/api/bench/results/"+created.ID, nil); del.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d", del.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, created.ID+".json")); !os.IsNotExist(err) {
		t.Fatal("file must be gone after DELETE")
	}
	if do(h, "GET", "/api/bench/results/"+created.ID, nil).Code != http.StatusNotFound {
		t.Fatal("GET after DELETE must be 404")
	}
	if do(h, "DELETE", "/api/bench/results/"+created.ID, nil).Code != http.StatusNotFound {
		t.Fatal("second DELETE must be 404")
	}
}

func TestBench_RejectsInvalidInput(t *testing.T) {
	_, dir, h := newTestService(t, 0, 0)

	mutate := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(benchJSON("x", 1), &m)
		f(m)
		raw, _ := json.Marshal(m)
		return raw
	}
	run0 := func(m map[string]any) map[string]any { return m["runs"].([]any)[0].(map[string]any) }

	cases := map[string][]byte{
		"not json":          []byte("this is not json"),
		"empty":             {},
		"array":             []byte(`[1,2,3]`),
		"trailing data":     append(benchJSON("x", 1), []byte(`{"extra":1}`)...),
		"no timestamp":      mutate(func(m map[string]any) { delete(m, "timestamp") }),
		"bad timestamp":     mutate(func(m map[string]any) { m["timestamp"] = "yesterday" }),
		"no runs":           mutate(func(m map[string]any) { m["runs"] = []any{} }),
		"label wrong type":  mutate(func(m map[string]any) { m["label"] = 42 }),
		"unknown operation": mutate(func(m map[string]any) { run0(m)["operation"] = "delete-everything" }),
		"zero concurrency":  mutate(func(m map[string]any) { run0(m)["concurrency"] = 0 }),
		"negative ops":      mutate(func(m map[string]any) { run0(m)["ops_per_sec"] = -1 }),
		"missing latency":   mutate(func(m map[string]any) { delete(run0(m), "latency") }),
		"too many runs":     benchJSON("x", manyConcs(201)...),
		"label too long":    mutate(func(m map[string]any) { m["label"] = strings.Repeat("a", 300) }),
	}
	for name, body := range cases {
		if rec := do(h, "POST", "/api/bench/results", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (body=%s)", name, rec.Code, rec.Body)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("rejected uploads left files behind: %v", entries)
	}
}

func TestBench_RejectsOversizedBody(t *testing.T) {
	_, dir, h := newTestService(t, 1024, 0)
	big := benchJSON("big", 1, 2, 3, 4, 5, 6, 7, 8) // 1KB 초과
	if len(big) <= 1024 {
		t.Fatalf("test body too small: %d", len(big))
	}
	if rec := do(h, "POST", "/api/bench/results", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("oversized upload left files: %v", entries)
	}
}

func TestBench_PathTraversalIsNeutralised(t *testing.T) {
	_, dir, h := newTestService(t, 0, 0)
	parent := filepath.Dir(dir)

	// 라벨에 경로 조작 문자열을 넣어도 파일은 저장소 안에, 안전한 이름으로만 생긴다.
	rec := do(h, "POST", "/api/bench/results", benchJSON("../../../etc/passwd\x00/..\\evil", 1))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST = %d %s", rec.Code, rec.Body)
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if strings.ContainsAny(created.ID, "/\\.\x00") {
		t.Fatalf("id %q contains unsafe characters", created.ID)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != created.ID+".json" {
		t.Fatalf("dir = %v", entries)
	}
	outside, _ := os.ReadDir(parent)
	if len(outside) != 1 { // bench 디렉터리 하나뿐
		t.Fatalf("something was written outside the store: %v", outside)
	}

	// 조회·삭제 id에 조작 문자열을 넣어도 거부되고, 바깥 파일은 건드려지지 않는다.
	victim := filepath.Join(parent, "victim.json")
	_ = os.WriteFile(victim, benchJSON("v", 1), 0o600)
	for _, id := range []string{"..%2Fvictim", "..%2F..%2Fvictim", "%2e%2e%2fvictim", "victim.json", "..", "a%00b", "a%5Cb"} {
		for _, method := range []string{"GET", "DELETE"} {
			rec := do(h, method, "/api/bench/results/"+id, nil)
			if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d, want 400/404", method, id, rec.Code)
			}
		}
	}
	if _, err := os.Stat(victim); err != nil {
		t.Fatal("a file outside the store was deleted")
	}
}

func TestBench_StrayFilesAreNotServed(t *testing.T) {
	_, dir, h := newTestService(t, 0, 0)
	// 색인에 없는(직접 놓인) 파일은 조회·삭제 대상이 아니다.
	_ = os.WriteFile(filepath.Join(dir, "stray.json"), benchJSON("s", 1), 0o600)
	if rec := do(h, "GET", "/api/bench/results/stray", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("GET stray = %d, want 404", rec.Code)
	}
}

func TestBench_CountCapEvictsOldest(t *testing.T) {
	store, err := NewBenchStore(filepath.Join(t.TempDir(), "b"), 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { clock = clock.Add(time.Second); return clock }

	var ids []string
	for i := 0; i < 5; i++ {
		meta, err := store.Put(benchJSON(fmt.Sprintf("run%d", i), 1))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, meta.ID)
	}
	if n := len(store.List()); n != 3 {
		t.Fatalf("stored = %d, want cap 3", n)
	}
	for _, old := range ids[:2] {
		if _, err := store.Get(old); err != ErrNotFound {
			t.Errorf("oldest %s should have been evicted, Get err = %v", old, err)
		}
		if _, err := os.Stat(store.path(old)); !os.IsNotExist(err) {
			t.Errorf("evicted file %s still on disk", old)
		}
	}
	for _, kept := range ids[2:] {
		if _, err := store.Get(kept); err != nil {
			t.Errorf("newest %s should be kept: %v", kept, err)
		}
	}
	if entries, _ := os.ReadDir(store.dir); len(entries) != 3 {
		t.Fatalf("files on disk = %d, want 3", len(entries))
	}
}

func TestBench_SameSecondSameLabelGetsSuffix(t *testing.T) {
	store, _ := NewBenchStore(filepath.Join(t.TempDir(), "b"), 0, 0)
	fixed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return fixed }
	a, _ := store.Put(benchJSON("same", 1))
	b, err := store.Put(benchJSON("same", 1))
	if err != nil || a.ID == b.ID || !strings.HasSuffix(b.ID, "-same-2") {
		t.Fatalf("ids = %q, %q (err=%v)", a.ID, b.ID, err)
	}
}

func TestBench_IndexRebuiltFromDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "b")
	s1, _ := NewBenchStore(dir, 0, 0)
	meta, _ := s1.Put(benchJSON("persist", 1, 2))
	_ = os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o600)

	s2, err := NewBenchStore(dir, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	list := s2.List()
	if len(list) != 1 || list[0].ID != meta.ID || list[0].Conditions != 2 {
		t.Fatalf("list after reload = %+v", list)
	}
}

func TestSanitizeLabel(t *testing.T) {
	for in, want := range map[string]string{
		"authz-cached":           "authz-cached",
		"":                       "run",
		"../../x":                "x",
		"a b/c":                  "a-b-c",
		"한글 라벨":                  "run",
		strings.Repeat("a", 100): strings.Repeat("a", 40),
	} {
		if got := sanitizeLabel(in); got != want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func manyConcs(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i + 1
	}
	return out
}

func TestTraffic_WindowValidation(t *testing.T) {
	_, _, h := newTestService(t, 0, 0) // 보관 1분
	for path, want := range map[string]int{
		"/api/dashboard/traffic":            200,
		"/api/dashboard/traffic?window=30s": 200,
		"/api/dashboard/traffic?window=1m":  200,
		"/api/dashboard/traffic?window=5s":  400,
		"/api/dashboard/traffic?window=2h":  400,
		"/api/dashboard/traffic?window=abc": 400,
	} {
		if got := do(h, "GET", path, nil).Code; got != want {
			t.Errorf("GET %s = %d, want %d", path, got, want)
		}
	}
}
