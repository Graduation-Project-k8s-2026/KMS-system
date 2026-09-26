// Package transit은 KMS의 데이터 평면 API — 등록된 키를 "사용"하는 연산
// (암호화/복호화/rewrap)과, 그 사용을 비교·평가하는 데 쓰이는 읽기 전용
// 진단 엔드포인트(seal-profile/seal-benchmark)를 담당한다. 이 라우터는
// 네트워크(ClusterIP)로 열려 사용자 애플리케이션이 직접 호출한다 — 키
// 생성/삭제, init/unseal 같은 관리 연산은 여기 없다(그건
// internal/api/admin).
//
// seal-profile/seal-benchmark이 여기 있는 이유: 이 둘은 실제 barrier/seal/
// storage 상태를 전혀 바꾸지 않는 순수 조회·측정 엔드포인트다(각각
// internal/seal/profile.go, internal/seal/benchmark.go 참고 — benchmark는
// 매번 완전히 격리된 임시 인스턴스만 만들었다 버린다). 벤치마크를 실행하는
// 주체(예: 성능 측정용 Job)가 키 생성/삭제나 init/unseal 권한까지 가질
// 필요가 없으므로, admin.sock이 아니라 권한이 최소화된 네트워크 쪽에 둔다.
package transit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/httputil"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// sealBenchmarkTimeout: GET /v1/sys/seal-benchmark 한 요청이 허용하는 최대
// 시간. TPM 시뮬레이터 기동 등으로 시간이 걸릴 수 있어, 요청이 무한정
// 걸리지 않도록 상한을 둔다.
const sealBenchmarkTimeout = 30 * time.Second

// Deps는 Transit 라우터가 필요로 하는 상위 계층 서비스들을 모은 것이다.
type Deps struct {
	Barrier *barrier.Barrier
	Transit *transit.TransitService

	// Seal은 GET /v1/sys/seal-profile이 "지금 이 서버가 실제로 조립한 seal의
	// 특성"을 보여주기 위해서만 쓰인다 — admin 라우터의 init/unseal과 달리
	// 여기서는 구체 타입 단언 없이 seal.Profiler 인터페이스로만 다룬다.
	Seal seal.Seal

	// Verifier: 설정돼 있으면(KMS_AUTHN=on) 이 라우터의 모든 요청에
	// ServiceAccount 토큰 인증을 강제한다. nil이면(KMS_AUTHN=off, 기본값)
	// 인증 없이 통과시킨다 — 로컬 개발/테스트가 토큰 없는 curl로 이뤄지는
	// 현재 동작을 깨지 않기 위한 기본값이다.
	Verifier *authn.Verifier

	// Authorizer: 설정돼 있으면(KMS_AUTHZ=on) encrypt/decrypt/rewrap
	// 세 라우트에 SubjectAccessReview 기반 인가를 강제한다. nil이면
	// (KMS_AUTHZ=off, 기본값) 인증만 통과하면 모든 키에 접근할 수 있다.
	// seal-profile/seal-benchmark은 특정 키를 대상으로 하지 않는 진단용
	// 엔드포인트라 인가 대상에서 제외한다 — 이 둘을 Admin이 아니라 권한이
	// 최소화된 Transit에 둔 취지(벤치마크 실행기 같은 호출자가 키 관리
	// 권한을 가질 필요가 없게 하는 것)를 인가 요구로 다시 무색하게 만들지
	// 않기 위함이다.
	Authorizer *authz.Authorizer
}

// NewRouter는 Deps를 엮어 chi 라우터를 구성해 반환한다. 관리 라우트(키
// 생성/조회/목록/삭제, 회전, 정책 설정, init/unseal/seal-status)는 여기
// 없다 — internal/api/admin.NewRouter가 별도로 제공한다.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	// 인증은 이 라우터의 모든 라우트(seal-profile/seal-benchmark 포함)에
	// 적용한다 — Admin(유닉스 소켓)에는 적용하지 않는다(소켓 파일 권한과
	// 같은 노드 제약으로 이미 보호되며, 관리 API 인증은 별도 과제다).
	if deps.Verifier != nil {
		r.Use(authn.Middleware(deps.Verifier))
	}

	// seal-profile/seal-benchmark은 sealed 가드 밖에 둔다 — barrier가
	// 아직 sealed더라도(오히려 sealed 상태일 때 더) "이 환경에서 각 seal
	// 방식이 어떤 성격이고 어느 정도 시간이 걸리는지" 확인할 수 있어야
	// 한다. 실제 barrier/seal 상태를 바꾸지 않는 순수 조회·측정이므로
	// sealed 여부와 무관하게 항상 응답 가능하다.
	r.Get("/v1/sys/seal-profile", handleSealProfile(deps))
	r.Get("/v1/sys/seal-benchmark", handleSealBenchmark())

	// 암복호화는 Root Key가 메모리에 있어야만 의미가 있으므로 sealed 가드를
	// 적용한다. 인가는 라우트별로 다른 verb(encrypt/decrypt/rewrap)가
	// 필요해 r.Use로 그룹 전체에 걸 수 없으므로, 라우트마다 r.With로
	// 개별 적용한다.
	r.Group(func(r chi.Router) {
		r.Use(httputil.SealedGuard(deps.Barrier))

		r.With(authzMiddleware(deps.Authorizer, "encrypt")).Post("/v1/encrypt/{name}", handleEncrypt(deps))
		r.With(authzMiddleware(deps.Authorizer, "decrypt")).Post("/v1/decrypt/{name}", handleDecrypt(deps))
		r.With(authzMiddleware(deps.Authorizer, "rewrap")).Post("/v1/rewrap/{name}", handleRewrap(deps))
	})

	return r
}

// authzMiddleware는 authorizer가 nil이면(KMS_AUTHZ=off) 아무 것도 하지
// 않는 통과용 미들웨어를, 아니면 authz.Middleware(authorizer, verb)를
// 반환한다 — 호출부(NewRouter)가 매번 nil 체크를 반복하지 않게 한다.
func authzMiddleware(authorizer *authz.Authorizer, verb string) func(http.Handler) http.Handler {
	if authorizer == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return authz.Middleware(authorizer, verb)
}

// ---- 요청/응답 타입 ----

type encryptRequest struct {
	Plaintext string `json:"plaintext"` // base64
}

type encryptResponse struct {
	Ciphertext string `json:"ciphertext"`
}

type decryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type decryptResponse struct {
	Plaintext string `json:"plaintext"` // base64
}

type rewrapRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type rewrapResponse struct {
	Ciphertext string `json:"ciphertext"`
}

// ---- /v1/sys/seal-profile, /v1/sys/seal-benchmark ----

// handleSealProfile은 지금 서버가 실제로 조립한 seal의 특성(seal.SealProfile)을
// 반환한다. deps.Seal은 항상 4개 구현체(DevSeal/ShamirSeal/TPMSeal/K8sSeal)
// 중 하나이고, 이들은 모두 profile.go에서 Profile() 메서드를 갖고 있어
// seal.Profiler를 만족한다 — 그래서 구체 타입을 하나하나 나열하는 타입
// 스위치 대신, "Profile()이 있는가"만 확인하는 타입 단언 하나로 충분하다.
func handleSealProfile(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		profiler, ok := deps.Seal.(seal.Profiler)
		if !ok {
			httputil.WriteJSONError(w, http.StatusInternalServerError, fmt.Sprintf("seal type %T does not implement Profiler", deps.Seal))
			return
		}
		httputil.WriteJSON(w, http.StatusOK, profiler.Profile())
	}
}

// handleSealBenchmark은 4개 Seal 구현체를 전부 새로 고립된 인스턴스로 만들어
// Init/Unseal 시간을 측정한 결과(seal.RunBenchmark)를 반환한다. 지금 서버가
// 실제로 어떤 seal로 조립됐는지와 무관하게 항상 4개 전부를 측정한다 —
// RunBenchmark 자체의 설계 이유는 internal/seal/benchmark.go 참고.
func handleSealBenchmark() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), sealBenchmarkTimeout)
		defer cancel()

		results := seal.RunBenchmark(ctx)
		httputil.WriteJSON(w, http.StatusOK, results)
	}
}

// ---- /v1/encrypt, /v1/decrypt, /v1/rewrap ----

func handleEncrypt(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req encryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			httputil.WriteJSONError(w, http.StatusBadRequest, "plaintext must be base64-encoded: "+err.Error())
			return
		}

		ciphertext, err := deps.Transit.Encrypt(name, plaintext)
		if err != nil {
			httputil.WriteError(w, err, http.StatusInternalServerError)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, encryptResponse{Ciphertext: ciphertext})
	}
}

func handleDecrypt(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req decryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		plaintext, err := deps.Transit.Decrypt(name, req.Ciphertext)
		if err != nil {
			// fallback을 400으로 준다: 이 시점까지 온 에러는 KeyNotFoundError/
			// KeyPolicyError/ErrSealed로 분류되지 않은 나머지 — 대부분 ciphertext
			// 형식 오류이거나 GCM 인증 실패이며, 둘 다 서버 문제가 아니라
			// 클라이언트가 보낸 입력(ciphertext) 자체의 문제다.
			httputil.WriteError(w, err, http.StatusBadRequest)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, decryptResponse{Plaintext: base64.StdEncoding.EncodeToString(plaintext)})
	}
}

func handleRewrap(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req rewrapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		newCiphertext, err := deps.Transit.Rewrap(name, req.Ciphertext)
		if err != nil {
			// Decrypt와 동일한 이유로 fallback을 400으로 준다 — Rewrap 내부의
			// 첫 단계가 Decrypt이므로, 여기서 나오는 미분류 에러 역시 대부분
			// ciphertext 형식 오류이거나 인증 실패다.
			httputil.WriteError(w, err, http.StatusBadRequest)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, rewrapResponse{Ciphertext: newCiphertext})
	}
}
