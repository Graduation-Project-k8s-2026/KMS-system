package demo

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

const testOrigin = "https://demo.test:30443"

// newDemo는 KMS를 흉내 내는 백엔드(요청 경로를 기록)와 포털 핸들러를 만든다.
func newDemo(t *testing.T, status *int, paths *[]string) http.Handler {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*paths = append(*paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer test-fixture" {
			t.Error("server token absent")
		}
		if *status != 200 {
			w.WriteHeader(*status)
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "/encrypt/"):
			json.NewEncoder(w).Encode(map[string]string{"ciphertext": "kms:v1:cipher-fixture"})
		case strings.Contains(r.URL.Path, "/rewrap/"):
			json.NewEncoder(w).Encode(map[string]string{"ciphertext": "kms:v2:rewrapped-fixture"})
		default:
			json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("public fixture"))})
		}
	}))
	t.Cleanup(backend.Close)
	return Handler(bench.NewClient(backend.URL, "test-fixture", backend.Client()), testOrigin,
		Config{Keys: []string{"demo", "campus-shipping"}, SALabel: "kms-demo/app-a"})
}

func post(h http.Handler, path, body, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", testOrigin+path, strings.NewReader(body))
	r.Header.Set("Origin", origin)
	r.Header.Set("X-Demo-Request", "1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRoundtripOriginAndNoBrowserToken(t *testing.T) {
	status, paths := 200, []string{}
	h := newDemo(t, &status, &paths)
	for _, op := range []string{"/encrypt", "/decrypt", "/rewrap"} {
		if w := post(h, op, `{"key":"demo","value":"public fixture"}`, testOrigin); w.Code != 200 {
			t.Fatalf("%s = %d", op, w.Code)
		}
	}
	if w := post(h, "/encrypt", `{"key":"demo","value":"x"}`, "https://evil.test"); w.Code != 403 {
		t.Fatal("origin bypass")
	}
	r := httptest.NewRequest("POST", testOrigin+"/encrypt", strings.NewReader(`{"key":"demo","value":"x"}`))
	r.Header.Set("Origin", testOrigin) // X-Demo-Request 헤더 없음
	if w := httptest.NewRecorder(); func() bool { h.ServeHTTP(w, r); return w.Code != 403 }() {
		t.Fatal("missing X-Demo-Request accepted")
	}
	for _, p := range []string{"/", "/portal.js", "/portal.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", testOrigin+p, nil))
		if w.Code != 200 || strings.Contains(w.Body.String(), "test-fixture") || strings.Contains(w.Body.String(), "localStorage") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("GET %s: status %d or credential/persistence leak", p, w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://evil.test/", nil))
	if w.Code != 403 {
		t.Fatal("host check bypass")
	}
	if len(paths) != 3 {
		t.Fatalf("backend calls = %v", paths)
	}
}

func TestKeyParameterAndRewrapPath(t *testing.T) {
	status, paths := 200, []string{}
	h := newDemo(t, &status, &paths)
	for _, tc := range []struct{ op, key, want string }{
		{"/encrypt", "campus-shipping", "/v1/encrypt/campus-shipping"},
		{"/decrypt", "demo", "/v1/decrypt/demo"},
		{"/rewrap", "campus-shipping", "/v1/rewrap/campus-shipping"},
	} {
		paths = paths[:0]
		w := post(h, tc.op, `{"key":"`+tc.key+`","value":"v"}`, testOrigin)
		if w.Code != 200 || len(paths) != 1 || paths[0] != tc.want {
			t.Fatalf("%s %s: code=%d backend paths=%v want %s", tc.op, tc.key, w.Code, paths, tc.want)
		}
	}
	var out map[string]string
	w := post(h, "/rewrap", `{"key":"demo","value":"kms:v1:old"}`, testOrigin)
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out["value"] != "kms:v2:rewrapped-fixture" {
		t.Fatalf("rewrap body = %s", w.Body)
	}
}

func TestKeyOutsideAllowListIsNotSentToKMS(t *testing.T) {
	status, paths := 200, []string{}
	h := newDemo(t, &status, &paths)
	for _, body := range []string{`{"key":"secret-key","value":"v"}`, `{"value":"v"}`, `{"key":"../demo","value":"v"}`, `{"key":"demo","value":"v","extra":1}`} {
		for _, op := range []string{"/encrypt", "/decrypt", "/rewrap"} {
			if w := post(h, op, body, testOrigin); w.Code != 400 {
				t.Errorf("%s %s = %d, want 400", op, body, w.Code)
			}
		}
	}
	if len(paths) != 0 {
		t.Fatalf("disallowed request reached KMS: %v", paths)
	}
}

func TestKMSDecisionsPassThrough(t *testing.T) {
	paths := []string{}
	for in, want := range map[int]int{403: 403, 401: 401, 404: 404, 500: 503, 503: 503} {
		status := in
		h := newDemo(t, &status, &paths)
		if w := post(h, "/encrypt", `{"key":"campus-shipping","value":"v"}`, testOrigin); w.Code != want {
			t.Errorf("KMS %d → portal %d, want %d", in, w.Code, want)
		}
	}
}

func TestConfigEndpointHasNoSecrets(t *testing.T) {
	status, paths := 200, []string{}
	h := newDemo(t, &status, &paths)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", testOrigin+"/api/config", nil))
	var c struct {
		Keys []string `json:"keys"`
		SA   string   `json:"service_account"`
	}
	if json.Unmarshal(w.Body.Bytes(), &c) != nil || len(c.Keys) != 2 || c.SA != "kms-demo/app-a" || strings.Contains(w.Body.String(), "test-fixture") {
		t.Fatalf("config = %d %s", w.Code, w.Body)
	}
}

func TestParseKeys(t *testing.T) {
	if k, err := ParseKeys(" demo, campus-shipping ,demo,"); err != nil || len(k) != 2 || k[1] != "campus-shipping" {
		t.Fatalf("keys = %v %v", k, err)
	}
	if k, _ := ParseKeys(""); len(k) != 1 || k[0] != "demo" {
		t.Fatalf("default = %v", k)
	}
	if _, err := ParseKeys("demo,../etc"); err == nil {
		t.Fatal("invalid key name accepted")
	}
}

func TestDatakeyRelay_AllowListOriginAndErrors(t *testing.T) {
	status, paths := 200, []string{}
	var gotBody string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ciphertext": "kms:v1:dk-fixture", "plaintext": base64.StdEncoding.EncodeToString(make([]byte, 32)), "key_version": 1})
	}))
	defer backend.Close()
	h := Handler(bench.NewClient(backend.URL, "test-fixture", backend.Client()), testOrigin, Config{Keys: []string{"demo"}, SALabel: "kms-demo/app-a"})

	w := post(h, "/datakey", `{"key":"demo"}`, testOrigin)
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if w.Code != 200 || resp["ciphertext"] != "kms:v1:dk-fixture" || len(resp["plaintext"]) != 44 || paths[0] != "/v1/datakey/demo" {
		t.Fatalf("datakey = %d %v %v", w.Code, resp, paths)
	}
	if !strings.Contains(gotBody, `"bits":256`) {
		t.Fatalf("upstream body = %s", gotBody)
	}
	if w := post(h, "/datakey", `{"key":"other"}`, testOrigin); w.Code != 400 || len(paths) != 1 {
		t.Fatal("key outside DEMO_KEYS reached the KMS")
	}
	if w := post(h, "/datakey", `{"key":"demo"}`, "https://evil.test"); w.Code != 403 {
		t.Fatal("origin bypass")
	}
	if w := post(h, "/datakey", `{"key":"demo","file":"x"}`, testOrigin); w.Code != 400 {
		t.Fatal("unknown fields accepted")
	}
	for upstream, want := range map[int]int{403: 403, 404: 404, 409: 409, 401: 401, 500: 503, 429: 503} {
		status = upstream
		if w := post(h, "/datakey", `{"key":"demo"}`, testOrigin); w.Code != want || strings.Contains(w.Body.String(), "dk-fixture") {
			t.Fatalf("upstream %d -> %d", upstream, w.Code)
		}
	}
}

// 파일은 서버로 오지 않는다: 업로드용 경로가 없고, 화면 코드는 파일 본문을 fetch로 보내지 않는다. 상단의 상시 권한 문구도 없다.
func TestPortalFileTabIsClientSideOnly(t *testing.T) {
	for _, path := range []string{"/upload", "/file", "/encrypt-file"} {
		status, paths := 200, []string{}
		h := newDemo(t, &status, &paths)
		if w := post(h, path, "x", testOrigin); w.Code != 404 && w.Code != 405 {
			t.Fatalf("%s = %d; the portal must not accept file uploads", path, w.Code)
		}
	}
	js, _ := uiFS.ReadFile("ui/portal.js")
	html, _ := uiFS.ReadFile("ui/index.html")
	if strings.Contains(string(js), "body: f") || strings.Contains(string(js), "FormData") {
		t.Fatal("portal.js seems to upload the file")
	}
	for _, s := range []string{"권한으로 동작해요"} {
		if strings.Contains(string(js), s) || strings.Contains(string(html), s) {
			t.Fatalf("persistent header text %q must be removed", s)
		}
	}
	if !strings.Contains(string(js), "(현재 ' + saName + ' 권한)") {
		t.Fatal("403 message should carry the current service account")
	}
	if strings.Contains(string(html), `id="sa"`) {
		t.Fatal("the persistent service-account banner element must be removed")
	}
	for _, p := range []string{"/", "/kmsfile.js", "/portal.js"} {
		status, paths := 200, []string{}
		h := newDemo(t, &status, &paths)
		r := httptest.NewRequest("GET", testOrigin+p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("GET %s = %d", p, w.Code)
		}
	}
}
