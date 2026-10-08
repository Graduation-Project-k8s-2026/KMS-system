// Package httputil은 internal/api/transit과 internal/api/admin이 공통으로
// 쓰는 것들(JSON 응답 헬퍼, 도메인 에러 -> HTTP 상태 코드 매핑, sealed 가드
// 미들웨어)을 모아둔다. 두 평면 모두 같은 도메인 에러(keys/barrier/seal
// 패키지가 반환하는 에러)를 같은 규칙으로 HTTP 상태 코드에 매핑해야 하므로,
// 이 매핑을 한 곳에만 두어 두 평면이 서로 다른 상태 코드를 반환하는 일이
// 없게 한다.
package httputil

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
)

func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func WriteJSONError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, map[string]string{"error": message})
}

// WriteError는 도메인 에러를 HTTP 상태 코드로 매핑하는 유일한 지점이다 —
// 이 매핑 규칙을 여러 핸들러에 흩어놓지 않고 여기 한 곳에 모아, "이 에러가
// 어떤 상태 코드가 되는지"를 항상 여기서만 확인하면 되게 한다.
//
//   - keys.KeyNotFoundError                            -> 404 (요청한 키가 없음)
//   - keys.KeyPolicyError                               -> 400 (요청이 정책 위반: 이름 형식, 중복, 버전 범위 등)
//   - barrier.ErrSealed                                 -> 503 (아직 unseal되지 않음)
//   - seal.ErrTPMAlreadyInitialized/ErrK8sAlreadyInitialized -> 409 (이미 init됨)
//   - 그 외                                             -> 호출부가 지정한 fallbackStatus
//     (핸들러 성격에 따라 다르다: 예를 들어 decrypt 핸들러는 분류 안 된 에러도
//     보통 잘못된 ciphertext 탓이므로 400을, 그 외 핸들러는 예상 밖 에러이므로
//     500을 fallback으로 준다.)
func WriteError(w http.ResponseWriter, err error, fallbackStatus int) {
	var notFound *keys.KeyNotFoundError
	var policyErr *keys.KeyPolicyError

	switch {
	case errors.As(err, &notFound):
		WriteJSONError(w, http.StatusNotFound, err.Error())
	case errors.As(err, &policyErr):
		WriteJSONError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, barrier.ErrSealed):
		WriteJSONError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, seal.ErrTPMAlreadyInitialized), errors.Is(err, seal.ErrK8sAlreadyInitialized):
		WriteJSONError(w, http.StatusConflict, err.Error())
	default:
		WriteJSONError(w, fallbackStatus, err.Error())
	}
}

// SealedGuard는 barrier가 잠긴 상태면 503으로 즉시 응답하고 다음 핸들러를
// 호출하지 않는 미들웨어를 만든다. Transit(암복호화)과 Admin(키 관리)
// 라우터 양쪽에서 다 쓰인다 — Root Key가 메모리에 없으면 둘 다 의미가 없기
// 때문이다. /v1/sys/*(init/unseal 자체)와 seal-profile/seal-benchmark에는
// 이 가드를 적용하지 않는다.
func SealedGuard(b *barrier.Barrier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if b.IsSealed() {
				WriteJSONError(w, http.StatusServiceUnavailable, "kms is sealed; call POST /v1/sys/unseal first")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
