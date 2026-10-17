package admin_test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// 관리 평면 오류도 {"error","message"} 형식이다 (409/404/400/503).
func TestAdminErrorBodies(t *testing.T) {
	srv := newTestServer(t)
	check := func(resp *http.Response, status int, code string) {
		t.Helper()
		defer resp.Body.Close()
		var b map[string]any
		json.NewDecoder(resp.Body).Decode(&b)
		if resp.StatusCode != status || b["error"] != code || b["message"] == "" || b["message"] == nil {
			t.Fatalf("got %d %v, want %d %s", resp.StatusCode, b, status, code)
		}
	}
	check(doJSON(t, http.MethodGet, srv.URL+"/v1/keys", nil), 503, "sealed")
	doJSON(t, http.MethodPost, srv.URL+"/v1/sys/init", nil).Body.Close()
	doJSON(t, http.MethodPost, srv.URL+"/v1/sys/unseal", nil).Body.Close()
	doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]string{"name": "k"}).Body.Close()
	check(doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]string{"name": "k"}), 409, "key_exists")
	check(doJSON(t, http.MethodGet, srv.URL+"/v1/keys/nope", nil), 404, "key_not_found")
	check(doJSON(t, http.MethodPost, srv.URL+"/v1/keys", map[string]string{"name": "bad name!"}), 400, "invalid_key_name")
	check(doJSON(t, http.MethodPost, srv.URL+"/v1/sys/init", nil), 409, "conflict")
}
