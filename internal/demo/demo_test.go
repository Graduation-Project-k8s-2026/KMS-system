package demo

import (
	"encoding/base64"
	"encoding/json"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFixedKeyRoundtripDenialAndNoBrowserToken(t *testing.T) {
	deny := false
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/demo") {
			t.Error("nonfixed key")
		}
		if r.Header.Get("Authorization") != "Bearer test-fixture" {
			t.Error("server token absent")
		}
		if deny {
			w.WriteHeader(403)
			return
		}
		if strings.Contains(r.URL.Path, "encrypt") {
			json.NewEncoder(w).Encode(map[string]string{"ciphertext": "cipher-fixture"})
		} else {
			json.NewEncoder(w).Encode(map[string]string{"plaintext": base64.StdEncoding.EncodeToString([]byte("public fixture"))})
		}
	}))
	defer backend.Close()
	h := Handler(bench.NewClient(backend.URL, "test-fixture", backend.Client()), "https://demo.test:30443")
	call := func(path, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "https://demo.test:30443"+path, strings.NewReader(`{"value":"public fixture"}`))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Demo-Request", "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, path := range []string{"/encrypt", "/decrypt"} {
		if w := call(path, "https://demo.test:30443"); w.Code != 200 {
			t.Fatal("roundtrip handler failed")
		}
	}
	deny = true
	if w := call("/encrypt", "https://demo.test:30443"); w.Code != 403 {
		t.Fatal("denial hidden")
	}
	if w := call("/encrypt", "https://evil.test"); w.Code != 403 {
		t.Fatal("origin bypass")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://demo.test:30443/", nil))
	if strings.Contains(w.Body.String(), "test-fixture") || strings.Contains(w.Body.String(), "localStorage") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("browser credential or persistence leak")
	}
	backend.Close()
	if w := call("/encrypt", "https://demo.test:30443"); w.Code != 503 {
		t.Fatal("outage hidden")
	}
}
