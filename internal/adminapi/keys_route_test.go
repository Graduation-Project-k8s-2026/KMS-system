package adminapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
)

// 화면이 부르는 "/v1/keys"(끝 슬래시 없음)와 "/v1/keys/" 둘 다 관리 소켓으로 중계돼야 한다.
func TestRouter_KeysCollectionWithAndWithoutSlash(t *testing.T) {
	for _, path := range []string{"/v1/keys", "/v1/keys/"} {
		for _, method := range []string{"GET", "POST"} {
			var gotMethod string
			sock := newFakeAdminSocket(t, func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				w.WriteHeader(http.StatusOK)
			})
			srv := httptest.NewServer(adminapi.NewRouter(adminapi.Deps{SocketPath: sock}))
			req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(`{}`))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			srv.Close()
			if resp.StatusCode != 200 || gotMethod != method {
				t.Errorf("%s %s: status=%d (socket saw %q)", method, path, resp.StatusCode, gotMethod)
			}
		}
	}
}
