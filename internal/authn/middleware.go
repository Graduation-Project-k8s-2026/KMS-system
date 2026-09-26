package authn

import (
	"log"
	"net/http"
	"strings"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/httputil"
)

const bearerPrefix = "Bearer "

// Middleware는 Authorization: Bearer <token> 헤더를 검증해 통과시키거나
// 401로 거부하는 미들웨어를 만든다. 실패 사유는 응답 본문에는 절대 담지
// 않는다(정보 노출 방지) — 서버 로그에만 남긴다. 로그에도 토큰 원문은
// 절대 남기지 않고, 성공 시의 신원 정보(namespace/SA명)만 남긴다.
func Middleware(v *Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			token, ok := strings.CutPrefix(header, bearerPrefix)
			if !ok || token == "" {
				log.Printf("authn: rejected %s %s: missing or malformed Authorization header", r.Method, r.URL.Path)
				httputil.WriteJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			identity, err := v.Verify(token)
			if err != nil {
				log.Printf("authn: rejected %s %s: %v", r.Method, r.URL.Path, err)
				httputil.WriteJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}

			log.Printf("authn: authenticated %s %s as %s", r.Method, r.URL.Path, identity.Subject)
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), identity)))
		})
	}
}
