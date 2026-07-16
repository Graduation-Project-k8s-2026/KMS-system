// Package api: HTTP 핸들러/라우팅.
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// Deps는 라우터가 필요로 하는 상위 계층 서비스들을 모은 것이다. 스케줄러
// (rotation.RotationScheduler)는 백그라운드로만 동작하고 HTTP로 제어하지
// 않으므로 여기 포함하지 않는다.
type Deps struct {
	Barrier *barrier.Barrier
	Keys    *keys.KeyManager
	Transit *transit.TransitService
}

// NewRouter는 Deps를 엮어 chi 라우터를 구성해 반환한다.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	// /v1/sys/*는 sealed 가드를 적용하지 않는다 — unseal 자체를 sealed 상태에서
	// 호출해야 하므로, 여길 막으면 봉인을 영영 풀 수 없게 된다.
	r.Route("/v1/sys", func(r chi.Router) {
		r.Get("/seal-status", handleSealStatus(deps))
		r.Post("/unseal", handleUnseal(deps))
	})

	// 나머지 API(키 관리, 암복호화)는 Root Key가 메모리에 있어야만 의미가 있으므로
	// r.Group으로 별도 스코프를 묶고 sealedGuard 미들웨어를 그 안에서만 적용한다.
	// r.Group은 URL 경로를 바꾸지 않고 "이 블록 안의 라우트에만 적용할 미들웨어"를
	// 지역적으로 추가하는 chi의 기능이다.
	r.Group(func(r chi.Router) {
		r.Use(sealedGuard(deps.Barrier))

		r.Route("/v1/keys", func(r chi.Router) {
			r.Post("/", handleCreateKey(deps))
			r.Get("/", handleListKeys(deps))
			r.Get("/{name}", handleGetKey(deps))
			r.Post("/{name}/rotate", handleRotateKey(deps))
			r.Post("/{name}/config", handleUpdateConfig(deps))
		})

		r.Post("/v1/encrypt/{name}", handleEncrypt(deps))
		r.Post("/v1/decrypt/{name}", handleDecrypt(deps))
		r.Post("/v1/rewrap/{name}", handleRewrap(deps))
	})

	return r
}

// sealedGuard는 barrier가 잠긴 상태면 503으로 즉시 응답하고 다음 핸들러를
// 호출하지 않는 미들웨어를 만든다.
func sealedGuard(b *barrier.Barrier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if b.IsSealed() {
				writeJSONError(w, http.StatusServiceUnavailable, "kms is sealed; call POST /v1/sys/unseal first")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ---- 요청/응답 타입 ----

type sealStatusResponse struct {
	Sealed   bool   `json:"sealed"`
	SealType string `json:"seal_type"`
}

type unsealResponse struct {
	Sealed bool `json:"sealed"`
}

type createKeyRequest struct {
	Name                string `json:"name"`
	AutoRotatePeriodSec *int   `json:"auto_rotate_period_sec"`
}

type listKeysResponse struct {
	Keys []string `json:"keys"`
}

type updateConfigRequest struct {
	MinDecryptionVersion *int `json:"min_decryption_version"`
	AutoRotatePeriodSec  *int `json:"auto_rotate_period_sec"`
}

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

// ---- /v1/sys ----

func handleSealStatus(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, sealStatusResponse{
			Sealed:   deps.Barrier.IsSealed(),
			SealType: deps.Barrier.SealType(),
		})
	}
}

func handleUnseal(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := deps.Barrier.Unseal(); err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, unsealResponse{Sealed: deps.Barrier.IsSealed()})
	}
}

// ---- /v1/keys ----

func handleCreateKey(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		autoRotate := 0
		if req.AutoRotatePeriodSec != nil {
			autoRotate = *req.AutoRotatePeriodSec
		}

		meta, err := deps.Keys.CreateKey(req.Name, autoRotate)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, meta)
	}
}

func handleListKeys(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		names, err := deps.Keys.ListKeys()
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		if names == nil {
			names = []string{}
		}
		writeJSON(w, http.StatusOK, listKeysResponse{Keys: names})
	}
}

func handleGetKey(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		meta, err := deps.Keys.GetKeyMeta(name)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, meta)
	}
}

func handleRotateKey(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		meta, err := deps.Keys.RotateKey(name)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, meta)
	}
}

func handleUpdateConfig(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req updateConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		meta, err := deps.Keys.UpdateConfig(name, req.MinDecryptionVersion, req.AutoRotatePeriodSec)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, meta)
	}
}

// ---- /v1/encrypt, /v1/decrypt ----

func handleEncrypt(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req encryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "plaintext must be base64-encoded: "+err.Error())
			return
		}

		ciphertext, err := deps.Transit.Encrypt(name, plaintext)
		if err != nil {
			writeError(w, err, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, encryptResponse{Ciphertext: ciphertext})
	}
}

func handleDecrypt(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req decryptRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		plaintext, err := deps.Transit.Decrypt(name, req.Ciphertext)
		if err != nil {
			// fallback을 400으로 준다: 이 시점까지 온 에러는 KeyNotFoundError/
			// KeyPolicyError/ErrSealed로 분류되지 않은 나머지 — 대부분 ciphertext
			// 형식 오류이거나 GCM 인증 실패이며, 둘 다 서버 문제가 아니라
			// 클라이언트가 보낸 입력(ciphertext) 자체의 문제다.
			writeError(w, err, http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, decryptResponse{Plaintext: base64.StdEncoding.EncodeToString(plaintext)})
	}
}

func handleRewrap(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req rewrapRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		newCiphertext, err := deps.Transit.Rewrap(name, req.Ciphertext)
		if err != nil {
			// Decrypt와 동일한 이유로 fallback을 400으로 준다 — Rewrap 내부의
			// 첫 단계가 Decrypt이므로, 여기서 나오는 미분류 에러 역시 대부분
			// ciphertext 형식 오류이거나 인증 실패다.
			writeError(w, err, http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, rewrapResponse{Ciphertext: newCiphertext})
	}
}

// ---- 응답/에러 헬퍼 ----

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// writeError는 도메인 에러를 HTTP 상태 코드로 매핑하는 유일한 지점이다 —
// 이 매핑 규칙을 여러 핸들러에 흩어놓지 않고 여기 한 곳에 모아, "이 에러가
// 어떤 상태 코드가 되는지"를 항상 여기서만 확인하면 되게 한다.
//
//   - keys.KeyNotFoundError -> 404 (요청한 키가 없음)
//   - keys.KeyPolicyError   -> 400 (요청이 정책 위반: 이름 형식, 중복, 버전 범위 등)
//   - barrier.ErrSealed     -> 503 (아직 unseal되지 않음)
//   - 그 외                -> 호출부가 지정한 fallbackStatus
//     (핸들러 성격에 따라 다르다: 예를 들어 decrypt 핸들러는 분류 안 된 에러도
//     보통 잘못된 ciphertext 탓이므로 400을, 그 외 핸들러는 예상 밖 에러이므로
//     500을 fallback으로 준다.)
func writeError(w http.ResponseWriter, err error, fallbackStatus int) {
	var notFound *keys.KeyNotFoundError
	var policyErr *keys.KeyPolicyError

	switch {
	case errors.As(err, &notFound):
		writeJSONError(w, http.StatusNotFound, err.Error())
	case errors.As(err, &policyErr):
		writeJSONError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, barrier.ErrSealed):
		writeJSONError(w, http.StatusServiceUnavailable, err.Error())
	default:
		writeJSONError(w, fallbackStatus, err.Error())
	}
}
