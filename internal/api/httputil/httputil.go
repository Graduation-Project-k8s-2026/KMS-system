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

// APIError는 모든 오류 응답의 본문 형식이다 (상태 코드는 그대로, 본문만 일관되게).
//
//	{"error":"<기계용 코드>","message":"<사람용 설명>","hint":"<선택>"}
//
// error는 클라이언트가 분기에 쓰는 안정적인 코드, message는 사람이 읽는 설명이다. 키 이름·버전
// 숫자·내부 오류 문구처럼 정보를 노출할 수 있는 값은 message/hint에 넣지 않는다.
type APIError struct {
	Error      string `json:"error"`
	Message    string `json:"message"`
	Hint       string `json:"hint,omitempty"`
	LimitBytes int64  `json:"limit_bytes,omitempty"`
}

// WriteAPIError는 코드/설명/힌트를 지정해 오류 본문을 쓴다.
func WriteAPIError(w http.ResponseWriter, status int, code, message, hint string) {
	WriteJSON(w, status, APIError{Error: code, Message: message, Hint: hint})
}

// codeForStatus: 코드를 따로 지정하지 않은 오류에 상태 코드별 기본 코드를 붙인다.
func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return "payload_too_large"
	case http.StatusNotImplemented:
		return "not_implemented"
	case http.StatusServiceUnavailable:
		return "unavailable"
	}
	if status >= 500 {
		return "internal_error"
	}
	return "error"
}

// WriteJSONError는 상태 코드별 기본 코드로 오류 본문을 쓴다 (message는 호출자가 준 문구).
func WriteJSONError(w http.ResponseWriter, status int, message string) {
	WriteAPIError(w, status, codeForStatus(status), message, "")
}

// WriteError는 도메인 에러를 HTTP 상태 코드와 오류 본문으로 매핑하는 유일한 지점이다 —
// 이 매핑 규칙을 여러 핸들러에 흩어놓지 않고 여기 한 곳에 모아, "이 에러가
// 어떤 상태 코드가 되는지"를 항상 여기서만 확인하면 되게 한다.
//
//   - keys.ErrAlreadyExists                             -> 409 key_exists
//   - keys.ErrKeyNotActive                              -> 409 key_not_active
//   - keys.ErrKeyProtected / keys.ErrInvalidState       -> 409 key_protected / invalid_state
//   - keys.ErrBackend                                   -> 503 backend_unavailable
//   - barrier.ErrRootVerification                       -> 400 root_verification_failed
//   - barrier.ErrInitialized                            -> 409 already_initialized
//   - keys.KeyNotFoundError                             -> 404 key_not_found
//   - keys.KeyPolicyError                               -> 400 <정책 코드> (최소 복호화 버전 등)
//   - barrier.ErrSealed                                 -> 503 sealed
//   - seal.ErrTPMAlreadyInitialized/ErrK8sAlreadyInitialized -> 409 already_initialized
//   - 그 외                                             -> 호출부가 지정한 fallbackStatus
//
// 정보 노출 규칙: 응답 message에는 키 이름·버전 숫자·내부 오류 문구를 넣지 않는다. 상세(err.Error())는
// 호출자가 서버 로그/감사에 남긴다(Transit은 AnnotateAudit).
func WriteError(w http.ResponseWriter, err error, fallbackStatus int) {
	var notFound *keys.KeyNotFoundError
	var policyErr *keys.KeyPolicyError

	switch {
	case errors.Is(err, keys.ErrAlreadyExists):
		WriteAPIError(w, http.StatusConflict, "key_exists", "key already exists", "")
	case errors.Is(err, keys.ErrKeyNotActive):
		WriteAPIError(w, http.StatusConflict, "key_not_active", "the key is not active", "enable the key or use another key")
	case errors.Is(err, keys.ErrKeyProtected):
		WriteAPIError(w, http.StatusConflict, "key_protected", "the key is protected and cannot be disabled or deleted", "protected keys are required by the KMS v2 path or KMS_PROTECTED_KEYS")
	case errors.Is(err, keys.ErrInvalidState):
		WriteAPIError(w, http.StatusConflict, "invalid_state", "the key state does not allow this operation", "")
	case errors.Is(err, keys.ErrBackend):
		WriteAPIError(w, http.StatusServiceUnavailable, "backend_unavailable", "key backend unavailable", "retry later")
	case errors.Is(err, barrier.ErrRootVerification):
		WriteAPIError(w, 400, "root_verification_failed", "root verification failed", "")
	case errors.Is(err, barrier.ErrInitialized):
		WriteAPIError(w, 409, "already_initialized", "already initialized", "")
	case errors.As(err, &notFound):
		WriteAPIError(w, http.StatusNotFound, "key_not_found", "key not found", "")
	case errors.As(err, &policyErr):
		code, msg := policyErr.Code, policyErr.Public
		if code == "" {
			code = "invalid_request"
		}
		if msg == "" {
			msg = "request violates the key policy"
		}
		WriteAPIError(w, http.StatusBadRequest, code, msg, "")
	case errors.Is(err, barrier.ErrSealed):
		WriteAPIError(w, http.StatusServiceUnavailable, "sealed", "kms is sealed", "an operator must unseal the service")
	case errors.Is(err, seal.ErrTPMAlreadyInitialized), errors.Is(err, seal.ErrK8sAlreadyInitialized):
		WriteAPIError(w, http.StatusConflict, "already_initialized", "already initialized", "")
	default:
		// 분류되지 않은 오류의 원문은 내부 정보를 담을 수 있어 그대로 보여주지 않는다.
		msg := "internal error"
		code := codeForStatus(fallbackStatus)
		switch {
		case fallbackStatus == http.StatusServiceUnavailable:
			msg = "service temporarily unavailable"
		case fallbackStatus < 500:
			msg = "the request could not be processed"
		}
		WriteAPIError(w, fallbackStatus, code, msg, "")
	}
}

// IsDomainError는 WriteError가 전용 코드로 매핑하는 도메인 에러인지 알려준다. false인 에러(예: 암호문 형식
// 오류·GCM 인증 실패)는 호출자가 자기 문맥에 맞는 코드로 응답할 수 있다.
func IsDomainError(err error) bool {
	var notFound *keys.KeyNotFoundError
	var policyErr *keys.KeyPolicyError
	return errors.Is(err, keys.ErrAlreadyExists) || errors.Is(err, keys.ErrKeyNotActive) || errors.Is(err, keys.ErrKeyProtected) || errors.Is(err, keys.ErrInvalidState) || errors.Is(err, keys.ErrBackend) ||
		errors.Is(err, barrier.ErrRootVerification) || errors.Is(err, barrier.ErrInitialized) || errors.Is(err, barrier.ErrSealed) ||
		errors.As(err, &notFound) || errors.As(err, &policyErr)
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
				WriteAPIError(w, http.StatusServiceUnavailable, "sealed", "kms is sealed", "an operator must unseal the service")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
