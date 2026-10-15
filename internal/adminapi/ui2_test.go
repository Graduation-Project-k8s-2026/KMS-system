package adminapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newUI2Handler는 운영과 같은 구성(Security.Wrap으로 감싼 라우터)을 만든다.
func newUI2Handler(t *testing.T, defaultUI string) http.Handler {
	t.Helper()
	file := filepath.Join(t.TempDir(), "roles.json")
	roles := `{"version":1,"users":{"admin@example.test":"admin","viewer@example.test":"viewer"}}`
	if err := os.WriteFile(file, []byte(roles), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewSecurity(file, "https://kms.example.test")
	if err != nil {
		t.Fatal(err)
	}
	return s.Wrap(NewRouter(Deps{SocketPath: "/missing", DefaultUI: defaultUI}))
}

func getAs(h http.Handler, path, user, remote, host string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://"+host+path, nil)
	r.RemoteAddr = remote
	if user != "" {
		r.Header.Set("Tailscale-User-Login", user)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestUI2_RequiresAuthSameAsConsole(t *testing.T) {
	h := newUI2Handler(t, "")
	for _, path := range []string{"/v2/", "/v2/app.js", "/v2/app.css"} {
		for _, tc := range []struct {
			name, user, remote, host string
			want                     int
		}{
			{"no identity", "", "127.0.0.1:9", "kms.example.test", 401},
			{"unknown user", "nobody@example.test", "127.0.0.1:9", "kms.example.test", 403},
			{"untrusted peer", "admin@example.test", "10.0.0.5:9", "kms.example.test", 403},
			{"wrong host", "admin@example.test", "127.0.0.1:9", "evil.example", 403},
		} {
			if w := getAs(h, path, tc.user, tc.remote, tc.host); w.Code != tc.want {
				t.Errorf("%s %s: status=%d want %d", path, tc.name, w.Code, tc.want)
			}
		}
		// /console과 같은 규칙인지 비교용
		if w := getAs(h, "/console", "", "127.0.0.1:9", "kms.example.test"); w.Code != 401 {
			t.Fatalf("/console without identity = %d", w.Code)
		}
	}
}

func TestUI2_ServesPagesForAdminAndViewer(t *testing.T) {
	h := newUI2Handler(t, "")
	for _, user := range []string{"admin@example.test", "viewer@example.test"} {
		w := getAs(h, "/v2/", user, "127.0.0.1:9", "kms.example.test")
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "app.js") {
			t.Fatalf("%s: /v2/ = %d %q", user, w.Code, w.Header().Get("Content-Type"))
		}
		for path, prefix := range map[string]string{"/v2/app.js": "text/javascript", "/v2/app.css": "text/css", "/v2/page-home.js": "text/javascript", "/v2/page-keys.js": "text/javascript",
			"/v2/page-seal.js": "text/javascript", "/v2/page-ops.js": "text/javascript", "/v2/page-audit.js": "text/javascript", "/v2/boot.js": "text/javascript"} {
			w := getAs(h, path, user, "127.0.0.1:9", "kms.example.test")
			if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), prefix) {
				t.Fatalf("%s %s = %d %q", user, path, w.Code, w.Header().Get("Content-Type"))
			}
		}
	}
	if w := getAs(h, "/v2", "admin@example.test", "127.0.0.1:9", "kms.example.test"); w.Code != 302 || w.Header().Get("Location") != "/v2/" {
		t.Fatalf("/v2 = %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := getAs(h, "/v2/nope.js", "admin@example.test", "127.0.0.1:9", "kms.example.test"); w.Code != 404 {
		t.Fatalf("missing file = %d", w.Code)
	}
}

func TestUI2_SessionReportsUser(t *testing.T) {
	h := newUI2Handler(t, "")
	w := getAs(h, "/api/session", "viewer@example.test", "127.0.0.1:9", "kms.example.test")
	var s map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil || s["user"] != "viewer@example.test" || s["role"] != "viewer" {
		t.Fatalf("session = %d %v", w.Code, s)
	}
}

func TestHomeRedirect_FollowsDefaultUI(t *testing.T) {
	for defaultUI, want := range map[string]string{"": "/v2/", "v1": "/console", "v2": "/v2/", "bogus": "/v2/"} {
		h := newUI2Handler(t, defaultUI)
		w := getAs(h, "/", "admin@example.test", "127.0.0.1:9", "kms.example.test")
		if w.Code != 302 || w.Header().Get("Location") != want {
			t.Errorf("DefaultUI=%q: %d %q, want %q", defaultUI, w.Code, w.Header().Get("Location"), want)
		}
	}
}

func TestInfoAndConsoleUsers_AuthAndMasking(t *testing.T) {
	file := filepath.Join(t.TempDir(), "roles.json")
	os.WriteFile(file, []byte(`{"version":1,"users":{"administrator@example.test":"admin","bob@example.test":"viewer"}}`), 0600)
	s, err := NewSecurity(file, "https://kms.example.test")
	if err != nil {
		t.Fatal(err)
	}
	h := s.Wrap(NewRouter(Deps{SocketPath: "/missing", RolesFile: file, AuditDir: t.TempDir(),
		Info: Info{ServerVersion: "v9", SourceSHA: "abc", BenchImage: "img@sha256:x"}}))
	for _, path := range []string{"/api/info", "/api/console-users"} {
		if w := getAs(h, path, "", "127.0.0.1:9", "kms.example.test"); w.Code != 401 {
			t.Errorf("%s no identity = %d", path, w.Code)
		}
		if w := getAs(h, path, "nobody@example.test", "127.0.0.1:9", "kms.example.test"); w.Code != 403 {
			t.Errorf("%s unknown user = %d", path, w.Code)
		}
	}
	for _, user := range []string{"administrator@example.test", "bob@example.test"} {
		w := getAs(h, "/api/info", user, "127.0.0.1:9", "kms.example.test")
		var info map[string]any
		if json.Unmarshal(w.Body.Bytes(), &info) != nil || w.Code != 200 || info["server_version"] != "v9" || info["audit_enabled"] != true {
			t.Fatalf("info %s = %d %s", user, w.Code, w.Body)
		}
		w = getAs(h, "/api/console-users", user, "127.0.0.1:9", "kms.example.test")
		body := w.Body.String()
		if w.Code != 200 || !strings.Contains(body, "adm***@example.test") || !strings.Contains(body, "bob***@example.test") || strings.Contains(body, "administrator") {
			t.Fatalf("console-users %s = %d %s", user, w.Code, body)
		}
	}
}

func TestDenyHTMLOnlyForBrowserNavigation(t *testing.T) {
	h := newUI2Handler(t, "")
	get := func(accept, user string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://kms.example.test/v2/", nil)
		r.RemoteAddr = "127.0.0.1:9"
		r.Header.Set("Accept", accept)
		if user != "" {
			r.Header.Set("Tailscale-User-Login", user)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	w := get("text/html,application/xhtml+xml", "stranger<b>@example.test")
	if w.Code != 403 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || !strings.Contains(w.Body.String(), "등록되지 않은 계정") ||
		!strings.Contains(w.Body.String(), "stranger&lt;b&gt;@example.test") || strings.Contains(w.Body.String(), "<b>@") {
		t.Fatalf("browser 403 = %d %q", w.Code, w.Body)
	}
	if w := get("text/html", ""); w.Code != 401 || !strings.Contains(w.Body.String(), "로그인") {
		t.Fatalf("browser 401 = %d", w.Code)
	}
	w = get("application/json", "stranger@example.test")
	if w.Code != 403 || strings.Contains(w.Body.String(), "<html") || !strings.Contains(w.Body.String(), "role denied") {
		t.Fatalf("api 403 = %d %q", w.Code, w.Body)
	}
}
