// Package admin은 KMS의 관리 평면 API — 키와 서버 자체를 "관리"하는 연산
// (키 생성/조회/목록/회전/정책 설정, init/unseal/seal-status)을 담당한다.
// 이 라우터는 같은 노드의 admin.sock(유닉스 도메인 소켓)으로만 제공되고,
// 네트워크로는 열리지 않는다 — 키 사용(암호화/복호화/rewrap)은 여기 없다
// (그건 internal/api/transit).
package admin

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/httputil"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
)

// Deps는 Admin 라우터가 필요로 하는 상위 계층 서비스들을 모은 것이다.
type Deps struct {
	Barrier *barrier.Barrier
	Keys    *keys.KeyManager

	// Seal은 barrier가 감싸고 있는 것과 같은 seal 인스턴스를 구체 타입까지
	// 다룰 수 있게 그대로 노출한다. barrier는 Seal 인터페이스(Unseal/Type/
	// IsConfigured)로만 seal을 다루지만, /v1/sys/init과 /v1/sys/unseal은
	// seal 종류별로 다른 함수(InitShamir/InitTPM/InitK8s, SubmitShare)를
	// 호출해야 해서 구체 타입으로 타입 단언(type assertion)이 필요하다.
	Seal seal.Seal

	// ShamirParts/ShamirThreshold: Seal.Type() == "shamir"일 때만 의미가
	// 있다. main.go가 ShamirSeal을 만들 때 정한 값을 그대로 받아, InitShamir
	// 호출과 진행 상황("2/3") 표시에 쓴다.
	ShamirParts     int
	ShamirThreshold int
}

// NewRouter는 Deps를 엮어 chi 라우터를 구성해 반환한다. 데이터 평면
// 라우트(암호화/복호화/rewrap, seal-profile/seal-benchmark)는 여기 없다 —
// internal/api/transit.NewRouter가 별도로 제공한다.
func NewRouter(deps Deps) http.Handler {
	r := chi.NewRouter()

	// shamirProgress는 "지금까지 몇 개의 조각이 제출됐는지"를 GET
	// seal-status에서도 보여주기 위한 상태다. ShamirSeal 자체는 이 숫자를
	// 조회하는 방법을 제공하지 않는다(SubmitShare 호출 시 반환값으로만 알 수
	// 있다) — 그래서 라우터가 그 반환값을 옆에서 별도로 기억해둔다. 이
	// 라우터 인스턴스가 살아있는 동안만 유효한 지역 상태이므로 NewRouter
	// 안에서 만들어 handleUnseal/handleSealStatus 클로저에 공유한다.
	progress := &shamirProgress{}

	// /v1/sys/*는 sealed 가드를 적용하지 않는다 — init/unseal 자체를 sealed
	// 상태에서 호출해야 하므로, 여길 막으면 봉인을 영영 풀 수 없게 된다.
	r.Route("/v1/sys", func(r chi.Router) {
		r.Get("/seal-status", handleSealStatus(deps, progress))
		r.Post("/init", handleInit(deps))
		r.Post("/unseal", handleUnseal(deps, progress))
	})

	// 키 관리는 Root Key가 메모리에 있어야만 의미가 있으므로 sealed 가드를
	// 적용한다.
	r.Group(func(r chi.Router) {
		r.Use(httputil.SealedGuard(deps.Barrier))

		r.Route("/v1/keys", func(r chi.Router) {
			r.Post("/", handleCreateKey(deps))
			r.Get("/", handleListKeys(deps))
			r.Get("/{name}", handleGetKey(deps))
			r.Post("/{name}/rotate", handleRotateKey(deps))
			r.Post("/{name}/config", handleUpdateConfig(deps))
		})
	})

	return r
}

// ---- 요청/응답 타입 ----

type sealStatusResponse struct {
	Sealed   bool   `json:"sealed"`
	SealType string `json:"seal_type"`
	// Progress: sealed=true이고 seal_type이 "shamir"일 때만 채워진다.
	// "1/3" 형태로 지금까지 제출된 조각 수/threshold를 보여준다.
	Progress string `json:"progress,omitempty"`
}

type initResponse struct {
	Message string `json:"message"`
	Sealed  bool   `json:"sealed"`
	// Shares: seal_type이 "shamir"일 때만 채워진다. base64로 인코딩된 조각들 —
	// 이 응답이 이 조각들을 보여주는 유일한 순간이며, 서버는 이후 이 값을
	// 어디에도 저장하지 않는다.
	Shares []string `json:"shares,omitempty"`
}

type unsealRequest struct {
	// Share: seal_type이 "shamir"일 때만 사용한다(base64). 나머지 seal
	// 타입은 body 없이 호출해도 된다.
	Share string `json:"share,omitempty"`
}

type unsealResponse struct {
	Sealed bool `json:"sealed"`
	// Progress: 아직 sealed(=true)이고 shamir일 때만 채워진다. "2/3" 형태.
	Progress string `json:"progress,omitempty"`
}

// shamirProgress는 ShamirSeal에 지금까지 제출된 조각 수를 기억해둔다.
// ShamirSeal.SubmitShare가 제출할 때마다 그 개수를 반환하기는 하지만, "지금
// 몇 개가 모여있는지"를 아무 제출 없이 조회하는 방법은 제공하지 않는다 —
// 그래서 GET seal-status가 그 값을 보여주려면 이 라우터가 옆에서 값을
// 기억해두는 수밖에 없다.
type shamirProgress struct {
	mu        sync.Mutex
	collected int
}

func (p *shamirProgress) set(n int) {
	p.mu.Lock()
	p.collected = n
	p.mu.Unlock()
}

func (p *shamirProgress) get() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.collected
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

// ---- /v1/sys ----

func handleSealStatus(deps Deps, progress *shamirProgress) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := sealStatusResponse{
			Sealed:   deps.Barrier.IsSealed(),
			SealType: deps.Barrier.SealType(),
		}
		if resp.Sealed && resp.SealType == "shamir" {
			resp.Progress = fmt.Sprintf("%d/%d", progress.get(), deps.ShamirThreshold)
		}
		httputil.WriteJSON(w, http.StatusOK, resp)
	}
}

// handleInit은 seal 종류별로 다른 "최초 1회 초기화" 함수를 호출한다.
//   - dev: 별도 init 개념이 없다(패스프레이즈에서 결정론적으로 유도되므로) —
//     그냥 barrier.Unseal()을 호출해 즉시 unseal 처리한다.
//   - shamir: seal.InitShamir로 새 Root Key와 조각들을 만든다. 조각은 이
//     응답에서 딱 한 번만 보여주고 서버는 저장하지 않는다 — 운영자가 각자
//     받아가서 나중에 POST /v1/sys/unseal로 threshold개를 제출해야 한다.
//   - tpm/k8s: 각각 InitTPM/InitK8s를 호출해 sealed blob/Secret을 만든다.
//     조각 같은 건 없고, 이후 POST /v1/sys/unseal 한 번으로 봉인이 풀린다.
//
// 이미 unseal된 상태에서 다시 init을 호출하면(=barrier가 이미 잘 동작하고
// 있다는 뜻) 409로 거부한다 — 지금 동작 중인 것과 무관한 새 Root Key를
// 또 만들어버리면 혼란만 생기기 때문이다. tpm/k8s는 여기에 더해, barrier가
// 아직 sealed더라도 이전 실행에서 이미 blob/Secret을 만들어둔 상태라면
// InitTPM/InitK8s 자체가 각자의 "이미 존재" 에러를 반환하고, 그 역시 409로
// 매핑된다.
func handleInit(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !deps.Barrier.IsSealed() {
			httputil.WriteJSONError(w, http.StatusConflict, "kms is already unsealed; refusing to re-initialize")
			return
		}

		switch sealer := deps.Seal.(type) {
		case *seal.DevSeal:
			if err := deps.Barrier.Unseal(); err != nil {
				httputil.WriteError(w, err, http.StatusInternalServerError)
				return
			}
			httputil.WriteJSON(w, http.StatusOK, initResponse{
				Message: "dev seal has no separate init step (root key is derived deterministically from KMS_MASTER_KEY); unsealed immediately",
				Sealed:  false,
			})

		case *seal.ShamirSeal:
			_, shares, err := seal.InitShamir(deps.ShamirParts, deps.ShamirThreshold)
			if err != nil {
				httputil.WriteError(w, err, http.StatusInternalServerError)
				return
			}
			encoded := make([]string, len(shares))
			for i, share := range shares {
				encoded[i] = base64.StdEncoding.EncodeToString(share)
			}
			httputil.WriteJSON(w, http.StatusCreated, initResponse{
				Message: fmt.Sprintf(
					"shamir seal initialized: %d shares generated, %d required to unseal. "+
						"these shares are shown only once and are not stored by the server — record and distribute them now.",
					len(shares), deps.ShamirThreshold,
				),
				Sealed: true,
				Shares: encoded,
			})

		case *seal.TPMSeal:
			if _, err := sealer.InitTPM(); err != nil {
				httputil.WriteError(w, err, http.StatusInternalServerError)
				return
			}
			httputil.WriteJSON(w, http.StatusCreated, initResponse{
				Message: "tpm seal initialized: root key sealed to this TPM. call POST /v1/sys/unseal to unseal.",
				Sealed:  true,
			})

		case *seal.K8sSeal:
			if _, err := sealer.InitK8s(r.Context()); err != nil {
				httputil.WriteError(w, err, http.StatusInternalServerError)
				return
			}
			httputil.WriteJSON(w, http.StatusCreated, initResponse{
				Message: "k8s seal initialized: root key stored in a Secret. call POST /v1/sys/unseal to unseal.",
				Sealed:  true,
			})

		default:
			httputil.WriteJSONError(w, http.StatusInternalServerError, fmt.Sprintf("unknown seal type %T", deps.Seal))
		}
	}
}

// handleUnseal은 POST /v1/sys/unseal의 멱등적 진입점이다. dev/tpm/k8s는 한 번
// 호출하면 그걸로 끝나는 특수 케이스가 되고, shamir는 자연스럽게 여러 번(각
// 운영자가 한 번씩) 호출하는 케이스가 된다 — 이 하나의 API로 두 방식의 차이를
// 흡수한다.
//
// 이미 unseal된 상태면 seal 종류와 무관하게 즉시 {sealed:false}만 반환하고
// 아무 것도 더 하지 않는다 — 그래야 이 API를 몇 번을 호출해도(멱등) 안전하다.
func handleUnseal(deps Deps, progress *shamirProgress) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !deps.Barrier.IsSealed() {
			httputil.WriteJSON(w, http.StatusOK, unsealResponse{Sealed: false})
			return
		}

		sealer, isShamir := deps.Seal.(*seal.ShamirSeal)
		if !isShamir {
			// dev/tpm/k8s: 한 번의 Unseal 호출로 끝난다. body는 아예 안 쓴다.
			if err := deps.Barrier.Unseal(); err != nil {
				httputil.WriteError(w, err, http.StatusInternalServerError)
				return
			}
			httputil.WriteJSON(w, http.StatusOK, unsealResponse{Sealed: false})
			return
		}

		var req unsealRequest
		_ = json.NewDecoder(r.Body).Decode(&req) // body가 없어도(EOF) 조용히 무시

		if req.Share == "" {
			httputil.WriteJSONError(w, http.StatusBadRequest, "share is required for shamir seal")
			return
		}
		shareBytes, err := base64.StdEncoding.DecodeString(req.Share)
		if err != nil {
			httputil.WriteJSONError(w, http.StatusBadRequest, "share must be base64-encoded: "+err.Error())
			return
		}

		collected, err := sealer.SubmitShare(shareBytes)
		if err != nil {
			// 중복 제출/threshold 초과 제출 등은 전부 클라이언트 쪽 문제이므로 400.
			httputil.WriteError(w, err, http.StatusBadRequest)
			return
		}
		progress.set(collected)

		if collected < deps.ShamirThreshold {
			httputil.WriteJSON(w, http.StatusOK, unsealResponse{
				Sealed:   true,
				Progress: fmt.Sprintf("%d/%d", collected, deps.ShamirThreshold),
			})
			return
		}

		// threshold에 막 도달한 순간 — barrier.Unseal()이 내부적으로
		// sealer.Unseal()(shamir.Combine)을 호출해 Root Key를 복원한다.
		if err := deps.Barrier.Unseal(); err != nil {
			httputil.WriteError(w, err, http.StatusInternalServerError)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, unsealResponse{Sealed: false})
	}
}

// ---- /v1/keys ----

func handleCreateKey(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req createKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		autoRotate := 0
		if req.AutoRotatePeriodSec != nil {
			autoRotate = *req.AutoRotatePeriodSec
		}

		meta, err := deps.Keys.CreateKey(req.Name, autoRotate)
		if err != nil {
			httputil.WriteError(w, err, http.StatusInternalServerError)
			return
		}
		httputil.WriteJSON(w, http.StatusCreated, meta)
	}
}

func handleListKeys(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		names, err := deps.Keys.ListKeys()
		if err != nil {
			httputil.WriteError(w, err, http.StatusInternalServerError)
			return
		}
		if names == nil {
			names = []string{}
		}
		httputil.WriteJSON(w, http.StatusOK, listKeysResponse{Keys: names})
	}
}

func handleGetKey(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		meta, err := deps.Keys.GetKeyMeta(name)
		if err != nil {
			httputil.WriteError(w, err, http.StatusInternalServerError)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, meta)
	}
}

func handleRotateKey(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		meta, err := deps.Keys.RotateKey(name)
		if err != nil {
			httputil.WriteError(w, err, http.StatusInternalServerError)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, meta)
	}
}

func handleUpdateConfig(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")

		var req updateConfigRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httputil.WriteJSONError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}

		meta, err := deps.Keys.UpdateConfig(name, req.MinDecryptionVersion, req.AutoRotatePeriodSec)
		if err != nil {
			httputil.WriteError(w, err, http.StatusInternalServerError)
			return
		}
		httputil.WriteJSON(w, http.StatusOK, meta)
	}
}
