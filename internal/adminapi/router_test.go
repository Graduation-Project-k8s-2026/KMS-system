package adminapi_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
)

// TestRouter_Console_ServesHTML은 /console이 200과 실제 console.html
// 콘텐츠(운영자 콘솔 특유의 문자열)를 반환하는지 확인한다. admin.sock은
// 이 페이지 자체를 서빙하는 데 필요 없으므로 존재하지 않는 경로로 충분하다.
func TestRouter_Console_ServesHTML(t *testing.T) {
	router := adminapi.NewRouter(adminapi.Deps{SocketPath: filepath.Join(t.TempDir(), "unused.sock")})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/console")
	if err != nil {
		t.Fatalf("GET /console failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html prefix", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body failed: %v", err)
	}
	if !strings.Contains(string(body), "seal-profile") {
		t.Fatalf("body does not look like console.html (missing expected marker)")
	}
}

// TestRouter_Root_RedirectsToConsole은 /가 /console로 안내하는지 확인한다 —
// /dashboard, /portal이 아직 등록되지 않아 기존 3장 카드 홈페이지를 그대로
// 쓰면 죽은 링크가 생기므로, 지금은 단순히 리다이렉트한다.
func TestRouter_Root_RedirectsToConsole(t *testing.T) {
	router := adminapi.NewRouter(adminapi.Deps{SocketPath: filepath.Join(t.TempDir(), "unused.sock")})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusFound)
	}
	if loc := resp.Header.Get("Location"); loc != "/console" {
		t.Fatalf("Location = %q, want %q", loc, "/console")
	}
}

// TestRouter_DashboardAndPortal_NotRegistered는 /dashboard와 /portal이
// 의도적으로 등록되지 않았음(404)을 확인한다 — 둘 다 Transit 평면 엔드포인트
// 에 의존하거나(dashboard) 별도 데모 앱으로 남을 예정이라(portal) 이번
// 범위에서 뺐다.
func TestRouter_DashboardAndPortal_NotRegistered(t *testing.T) {
	router := adminapi.NewRouter(adminapi.Deps{SocketPath: filepath.Join(t.TempDir(), "unused.sock")})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	for _, path := range []string{"/dashboard", "/portal"} {
		t.Run(path, func(t *testing.T) {
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s status = %d, want %d", path, resp.StatusCode, http.StatusNotFound)
			}
		})
	}
}

// TestRouter_ProxyStillWorksAlongsideConsole은 /console을 추가한 뒤에도
// 기존 /v1/* 프록시가 회귀 없이 그대로 동작하는지 확인한다.
func TestRouter_ProxyStillWorksAlongsideConsole(t *testing.T) {
	sockPath := newFakeAdminSocket(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/seal-status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"sealed":true,"seal_type":"dev"}`))
	})

	router := adminapi.NewRouter(adminapi.Deps{SocketPath: sockPath})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/v1/sys/seal-status")
	if err != nil {
		t.Fatalf("GET /v1/sys/seal-status failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"sealed":true,"seal_type":"dev"}` {
		t.Fatalf("body = %q, want proxied backend body", string(body))
	}
}
