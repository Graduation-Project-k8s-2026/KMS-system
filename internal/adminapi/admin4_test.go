package adminapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/jobs"
)

// /api/audit은 관리 감사와 Transit 감사를 한 모양으로 합쳐 준다 (키 이름, 출처, 리스너 포함).
func TestAuditMergesAdminAndTransitEvents(t *testing.T) {
	adminDir, coreDir, transitDir := t.TempDir(), t.TempDir(), t.TempDir()
	al, _ := audit.New(adminDir)
	al.Write(audit.Event{Subject: "alice", Action: "GET /v1/keys requested"})
	cl, _ := audit.New(coreDir)
	cl.Write(audit.Event{Subject: "tailnet-user", Action: "POST /v1/keys/disable completed", Key: "orders", Allowed: true, Success: true})
	tl, _ := audit.NewTransit(transitDir, 16, 10*time.Millisecond)
	tl.Record(audit.TransitEvent{RequestID: "t1", Subject: "system:serviceaccount:a:b", Action: "decrypt", Key: "team.k", Status: 200, LatencyMs: 1.5})
	tl.Record(audit.TransitEvent{RequestID: "t2", Subject: "system:serviceaccount:kms-external:u", Action: "encrypt", Key: "kms-external.k", Status: 403, Listener: "external", ClientIP: "203.0.113.9"})
	tl.Close()

	srv := httptest.NewServer(adminapi.NewRouter(adminapi.Deps{SocketPath: filepath.Join(t.TempDir(), "x.sock"), AuditDir: adminDir, CoreAuditDir: coreDir, TransitAuditDir: transitDir}))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/audit")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("audit: %v %v", resp, err)
	}
	var rows []map[string]any
	json.NewDecoder(resp.Body).Decode(&rows)
	by := map[string]map[string]any{}
	for _, r := range rows {
		by[r["request_id"].(string)] = r
		if r["source"] == nil {
			t.Fatalf("row without source: %v", r)
		}
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d, want 4", len(rows))
	}
	t1, t2 := by["t1"], by["t2"]
	if t1["source"] != "transit" || t1["listener"] != "internal" || t1["key"] != "team.k" || t1["success"] != true || t1["allowed"] != true || t1["status"] != float64(200) {
		t.Fatalf("t1 = %v", t1)
	}
	if t2["listener"] != "external" || t2["client_ip"] != "203.0.113.9" || t2["success"] != false || t2["allowed"] != false {
		t.Fatalf("t2 = %v", t2)
	}
	var adminKey bool
	for _, r := range rows {
		if r["source"] == "admin" && r["key"] == "orders" {
			adminKey = true
		}
	}
	if !adminKey {
		t.Fatal("admin audit key name missing from merged rows")
	}
	// Transit 디렉터리가 없으면 관리 기록만 나온다 (기존 동작)
	srv2 := httptest.NewServer(adminapi.NewRouter(adminapi.Deps{SocketPath: filepath.Join(t.TempDir(), "x.sock"), AuditDir: adminDir}))
	defer srv2.Close()
	r2, _ := http.Get(srv2.URL + "/api/audit")
	var rows2 []map[string]any
	json.NewDecoder(r2.Body).Decode(&rows2)
	if len(rows2) != 1 || rows2[0]["source"] != "admin" {
		t.Fatalf("rows without transit dir = %v", rows2)
	}
}

func TestInfoListsProtectedKeys(t *testing.T) {
	srv := httptest.NewServer(adminapi.NewRouter(adminapi.Deps{SocketPath: "x", Info: adminapi.Info{ProtectedKeys: []string{"k8s-secrets", "extra"}}}))
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/api/info")
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	pk, _ := m["protected_keys"].([]any)
	if len(pk) != 2 || pk[0] != "k8s-secrets" {
		t.Fatalf("protected_keys = %v", m["protected_keys"])
	}
}

// 대시보드 지표: 시간 범위는 허용 목록(15m/1h/6h/24h)만, step이 범위에 맞게 커진다.
func TestDashboardMetricsWindow(t *testing.T) {
	var gotQuery url.Values
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer prom.Close()
	srv := httptest.NewServer(adminapi.NewRouter(adminapi.Deps{SocketPath: "x", Jobs: &jobs.Service{}, PrometheusURL: prom.URL}))
	defer srv.Close()
	cases := map[string]struct {
		span time.Duration
		step string
	}{"": {15 * time.Minute, "15"}, "15m": {15 * time.Minute, "15"}, "1h": {time.Hour, "60"}, "6h": {6 * time.Hour, "300"}, "24h": {24 * time.Hour, "900"}}
	for win, want := range cases {
		resp, _ := http.Get(srv.URL + "/api/dashboard/metrics?metric=requests&range=1&window=" + win)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("window %q = %d", win, resp.StatusCode)
		}
		start, _ := time.Parse(time.RFC3339, gotQuery.Get("start"))
		end, _ := time.Parse(time.RFC3339, gotQuery.Get("end"))
		if d := end.Sub(start); d < want.span-2*time.Second || d > want.span+2*time.Second || gotQuery.Get("step") != want.step {
			t.Fatalf("window %q: span %v step %s, want %v / %s", win, end.Sub(start), gotQuery.Get("step"), want.span, want.step)
		}
	}
	for _, bad := range []string{"48h", "7d", "1y", "abc", "15m;drop"} {
		resp, _ := http.Get(srv.URL + "/api/dashboard/metrics?metric=requests&range=1&window=" + url.QueryEscape(bad))
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatalf("window %q = %d, want 400", bad, resp.StatusCode)
		}
	}
}
