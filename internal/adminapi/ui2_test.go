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
		for path, prefix := range map[string]string{"/v2/app.js": "text/javascript", "/v2/app.css": "text/css"} {
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
	for defaultUI, want := range map[string]string{"": "/console", "v1": "/console", "v2": "/v2/", "bogus": "/console"} {
		h := newUI2Handler(t, defaultUI)
		w := getAs(h, "/", "admin@example.test", "127.0.0.1:9", "kms.example.test")
		if w.Code != 302 || w.Header().Get("Location") != want {
			t.Errorf("DefaultUI=%q: %d %q, want %q", defaultUI, w.Code, w.Header().Get("Location"), want)
		}
	}
}
