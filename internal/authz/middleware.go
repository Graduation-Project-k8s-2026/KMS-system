package authz

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/httputil"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
)

// Middleware는 verb(encrypt/decrypt/rewrap — 라우트 등록 시점에 고정으로
// 넘긴다) 하나에 대한 인가 미들웨어를 만든다. 키 이름은 요청 경로의 chi
// URL 파라미터("name")에서, 신원은 인증 미들웨어가 이미 컨텍스트에 실어둔
// 것에서 꺼낸다 — 그래서 이 미들웨어는 항상 authn.Middleware 뒤에서만
// 동작해야 한다.
func Middleware(a *Authorizer, verb string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := authn.IdentityFromContext(r.Context())
			if !ok {
				// KMS_AUTHZ=on이면 KMS_AUTHN=on이 항상 강제되므로(기동 시
				// 검증) 정상 배선에서는 여기 도달할 수 없다 — 도달했다면
				// 배선 실수다. 판단할 근거가 없으므로 안전하게 거부한다.
				slog.Error("authz: no identity in request context; authn middleware must run first", "path", r.URL.Path)
				httputil.WriteJSONError(w, http.StatusForbidden, "forbidden")
				return
			}

			name := chi.URLParam(r, "name")
			if !a.Allowed(r.Context(), identity, name, verb) {
				httputil.WriteJSONError(w, http.StatusForbidden, "forbidden")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
