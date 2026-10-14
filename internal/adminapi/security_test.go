package adminapi

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityCSRFRoleRevocationAndAllowlist(t *testing.T) {
	file := filepath.Join(t.TempDir(), "roles.json")
	roles := `{"version":1,"users":{"admin@example.test":"admin","viewer@example.test":"viewer"}}`
	os.WriteFile(file, []byte(roles), 0600)
	s, e := NewSecurity(file, "https://kms.example.test")
	if e != nil {
		t.Fatal(e)
	}
	h := s.Wrap(NewRouter(Deps{SocketPath: "/missing"}))
	request := func(method, path, user, origin, token string, cookie *http.Cookie, remote, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(`{}`))
		r.RemoteAddr = remote
		r.Header.Set("Tailscale-User-Login", user)
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", token)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		user, method, path, host, remote string
		want                             int
	}{{"", "GET", "/console", "kms.example.test", "127.0.0.1:9", 401}, {"viewer@example.test", "POST", "/v1/sys/init", "kms.example.test", "127.0.0.1:9", 403}, {"admin@example.test", "GET", "/console", "evil.test", "127.0.0.1:9", 403}, {"admin@example.test", "GET", "/console", "kms.example.test", "10.0.0.2:9", 403}, {"viewer@example.test", "GET", "/console", "kms.example.test", "127.0.0.1:9", 200}, {"admin@example.test", "GET", "/v1/not-allowed", "kms.example.test", "127.0.0.1:9", 404}} {
		w := request(tc.method, tc.path, tc.user, "", "", nil, tc.remote, tc.host)
		if w.Code != tc.want {
			t.Fatalf("%s %s got %d want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
	w := request("GET", "/api/session", "admin@example.test", "", "", nil, "127.0.0.1:9", "kms.example.test")
	var session map[string]string
	json.Unmarshal(w.Body.Bytes(), &session)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	for _, origin := range []string{"", "https://evil.test"} {
		if w = request("POST", "/v1/sys/seal", "admin@example.test", origin, session["csrf_token"], cookies[0], "127.0.0.1:9", "kms.example.test"); w.Code != 403 {
			t.Fatal("bad origin accepted")
		}
	}
	// A valid request reaches the absent UDS (503), proving the auth gate passed.
	w = request("POST", "/v1/sys/seal", "admin@example.test", "https://kms.example.test", session["csrf_token"], cookies[0], "127.0.0.1:9", "kms.example.test")
	if w.Code != 503 {
		t.Fatalf("valid CSRF did not reach backend: %d", w.Code)
	}
	os.WriteFile(file, []byte(`{"version":1,"users":{"admin@example.test":"viewer"}}`), 0600)
	w = request("POST", "/v1/sys/seal", "admin@example.test", "https://kms.example.test", session["csrf_token"], cookies[0], "127.0.0.1:9", "kms.example.test")
	if w.Code != 403 {
		t.Fatal("revoked role retained session rights")
	}
	os.WriteFile(file, []byte(`invalid`), 0600)
	w = request("GET", "/console", "admin@example.test", "", "", nil, "127.0.0.1:9", "kms.example.test")
	if w.Code != 503 {
		t.Fatal("malformed roles did not fail closed")
	}
}
func TestPrometheusUnavailableIsNotZero(t *testing.T) {
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/query" || r.URL.Query().Get("query") != "up" {
			t.Error("not PromQL query")
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	r := chiRouterForOperations(prom.URL)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/dashboard/metrics?metric=targets", nil))
	if w.Code != 200 {
		t.Fatal("Prometheus success failed")
	}
	prom.Close()
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/dashboard/metrics?metric=targets", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "N/A") {
		t.Fatal("outage represented as zero")
	}
}

func chiRouterForOperations(url string) http.Handler {
	r := chi.NewRouter()
	mountOperations(r, url)
	return r
}

func TestPrometheusRangeAllowlistAndMalformedResponse(t *testing.T) {
	calls := 0
	malformed := false
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/query_range" || r.URL.Query().Get("query") != "up" || r.URL.Query().Get("step") != "15" || r.URL.Query().Get("start") == "" || r.URL.Query().Get("end") == "" {
			t.Error("range query contract violated")
		}
		if malformed {
			w.Write([]byte(`{"status":"error"}`))
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer prom.Close()
	router := chiRouterForOperations(prom.URL)
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"targets&range=1", 200}, {"arbitrary_query&range=1", 400},
	} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/api/dashboard/metrics?metric="+tc.query, nil))
		if w.Code != tc.want {
			t.Fatalf("metric response: got %d want %d", w.Code, tc.want)
		}
	}
	if calls != 1 {
		t.Fatal("unlisted query reached Prometheus")
	}
	malformed = true
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/api/dashboard/metrics?metric=targets&range=1", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "N/A") {
		t.Fatal("Prometheus error hidden")
	}
}
