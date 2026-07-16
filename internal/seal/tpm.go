// tpm.go: TPM(Trusted Platform Module) 기반 Seal 구현체.
//
// TPM이 무엇이고 Seal/Unseal이 하드웨어에서 어떻게 동작하는가:
// TPM은 메인보드나 CPU에 내장된 별도의 보안 칩이다. 자체 저장 공간, 난수
// 발생기, 그리고 "이 칩 밖으로는 절대 못 나가는" 고유 키(Endorsement Key,
// Storage Root Key 등)를 갖고 있다. TPM의 Seal 연산은 "이 데이터를, 오직
// 이 TPM만 열 수 있는 형태로 암호화해 달라"는 요청이다 — 실제 암호화 연산과
// 그 암호화에 쓰이는 키(SRK, Storage Root Key)가 전부 TPM 칩 내부에서만
// 다뤄지고, 그 키 자체는 한 번도 칩 밖으로 나오지 않는다. Unseal은 반대로
// "이 데이터를 열어 달라"는 요청이며, 같은 TPM(정확히는 같은 SRK를 가진
// TPM)에서만 성공한다. 그래서 sealed blob을 디스크째 복사해서 다른 서버로
// 옮겨도, 그 서버의 TPM은 열 수 없다.
//
// ShamirSeal(internal/seal/shamir.go)과의 대비 — [결정 3] 비교 실험의
// 핵심 관찰 대상:
//   - Shamir: Root Key를 M개의 조각으로 쪼개 여러 "사람"에게 분산한다.
//     Unseal하려면 그중 threshold명이 실제로 조각을 들고 모여야 한다 —
//     자동화가 원천적으로 불가능하지만(사람이 개입해야 하므로), 서버
//     하드웨어 자체가 고장 나거나 교체돼도 Root Key 복원과는 무관하다
//     (조각은 사람들이 따로 들고 있으므로).
//   - TPM: Unseal 한 번(TPM에 명령 한 번 보내는 것)이면 끝난다 — 사람
//     개입이 전혀 필요 없어 KMS_AUTO_UNSEAL 같은 완전 자동 복구가
//     가능하다. 그 대신 신뢰가 "이 서버의 이 TPM 칩 하나"에 못박힌다 —
//     그 TPM이 고장나면(메인보드 고장, 칩 자체의 결함 등) sealed blob은
//     영원히 못 열리고 Root Key는 복구 불가능하게 사라진다. 사람에게
//     분산된 비밀은 애초에 없기 때문이다.
//     즉 Shamir는 "가용성(사람이 없으면 못 연다)을 낮추는 대신 단일 장애점을
//     없애고", TPM은 "단일 장애점(이 TPM 하나)을 감수하는 대신 완전 자동화된
//     가용성을 얻는다" — 정반대의 트레이드오프를 택한 두 구현체다.
//
// PCR 정책의 트레이드오프:
// TPM은 부팅 과정의 각 단계(BIOS, 부트로더, 커널 등)를 거칠 때마다 그 단계의
// 해시를 PCR(Platform Configuration Register)이라는 내부 레지스터에 "누적"
// 기록한다(한 번 기록되면 리셋 전까지는 덮어쓸 수 없고 더 섞을 수만 있다).
// Seal할 때 특정 PCR들의 "현재 값"에 봉인을 걸어두면, Unseal 시점에 그
// PCR들의 값이 봉인 당시와 다르면(=부팅 과정 중 무언가 바뀌었으면) TPM이
// 자체적으로 Unseal을 거부한다.
//   - 켰을 때: 누군가 서버를 조작해 부팅 체인을 변조했다면(예: 부팅 디스크를
//     빼내 변조된 커널로 다시 부팅시키는 "evil maid" 공격) PCR 값이 달라져
//     Unseal이 실패한다. 안정성(무결성 보장)은 올라간다.
//   - 켰을 때의 대가: 정상적인 BIOS/커널 보안 업데이트만 해도 PCR 값이
//     바뀌어서 Unseal이 실패한다. 패치를 할 때마다 재봉인이 필요해지고,
//     잘못하면 정상적인 유지보수 중에도 KMS가 못 열리는 상황이 생긴다.
//     가용성은 내려간다.
//     그래서 기본값은 PCR 미사용(끔)이고, WithPCRs 옵션으로 켤 수 있게만
//     해뒀다 — "PCR on/off"를 그대로 비교 실험 항목으로 쓸 수 있도록.
//
// 시뮬레이터의 한계:
// 테스트(tpm_test.go)는 실제 TPM 칩 대신 github.com/google/go-tpm-tools/
// simulator(Microsoft의 TPM 2.0 레퍼런스 구현을 그대로 빌드한 소프트웨어
// 시뮬레이터)를 쓴다. 이건 CPU 위에서 도는 일반 프로그램이라 실제 TPM
// 칩보다 훨씬 빠르고, 매 테스트마다 깨끗한 상태로 새로 켤 수 있어 "기능이
// 맞게 동작하는가"를 검증하기엔 충분하고 훨씬 편리하다. 하지만 실제 TPM
// 칩은 전용 하드웨어라 명령 처리 속도가 훨씬 느리다(보통 밀리초~수십
// 밀리초 단위) — 이건 시뮬레이터로는 재현되지 않는다. 그래서 [결정 3]
// 비교 실험에서 "속도"를 비교하려면 반드시 실제 TPM(또는 최소한 vTPM)에서
// 다시 측정해야 하고, 이 시뮬레이터 기반 테스트는 어디까지나 "정확성"만
// 검증한다는 걸 분명히 해둬야 한다.
package seal

import (
	"crypto/rand"
	"errors"
	"io"
	"sync"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/proto"
)

// tpmBlobStorageKey: sealed blob을 저장할 storage key. keys 패키지가 쓰는
// "keys/..." 네임스페이스와 겹치지 않도록 seal 전용 네임스페이스를 쓴다.
const tpmBlobStorageKey = "seal/tpm/rootkey"

var (
	// ErrTPMNotInitialized: InitTPM을 아직 실행하지 않은 상태에서 Unseal을
	// 호출했을 때 반환.
	ErrTPMNotInitialized = errors.New("seal: TPM not initialized; call InitTPM first")

	// ErrTPMAlreadyInitialized: 이미 sealed blob이 저장돼 있는 상태에서
	// InitTPM을 다시 호출했을 때 반환.
	//
	// 왜 덮어쓰면 안 되는가: InitTPM은 완전히 새로운 무작위 Root Key를
	// 만든다. 이미 blob이 있는데도 그냥 덮어써버리면, 기존 Root Key로
	// 암호화된 모든 데이터(barrier 아래 저장된 모든 KEK/데이터)를 영원히
	// 복호화할 수 없게 된다 — 실수로 InitTPM을 한 번 더 눌렀을 뿐인데 KMS
	// 전체가 복구 불가능해지는 사고를 막는 방어선이다.
	ErrTPMAlreadyInitialized = errors.New("seal: TPM seal already initialized; refusing to overwrite existing sealed blob")

	// ErrTPMInvalidRootKeyLength: TPM이 복원한 Root Key의 길이가
	// crypto.KeyLen과 다를 때 반환한다 (정상적으로는 절대 발생하지 않아야
	// 하는 데이터 불일치 상태).
	ErrTPMInvalidRootKeyLength = errors.New("seal: TPM unsealed a root key with an unexpected length")
)

// TPMSeal은 TPM의 Seal/Unseal 명령으로 Root Key를 보호하는 Seal 구현체다.
type TPMSeal struct {
	// tpm은 go-tpm이 TPM과 통신할 때 쓰는 인터페이스다. TPM과의 통신은
	// 본질적으로 "명령 바이트열을 쓰고(Write), 응답 바이트열을 읽는(Read)"
	// 것뿐이라 io.ReadWriteCloser로 충분히 표현된다. 이렇게 인터페이스로
	// 받아두면, 개발 중엔 소프트웨어 시뮬레이터, 성능/신뢰성 측정은 실제
	// TPM 디바이스(예: /dev/tpmrm0), 클라우드 환경에선 vTPM — 이 셋 중
	// 무엇을 넘기든 TPMSeal의 나머지 코드는 단 한 줄도 바뀌지 않는다. Seal
	// 인터페이스가 "루트 키 보호 방식"을 barrier로부터 분리했던 것과 같은
	// 이유로, 여기서는 "TPM과의 통신 채널"을 이 구현체 내부 로직으로부터
	// 분리한 것이다.
	tpm io.ReadWriteCloser

	// store는 sealed blob(TPM으로 암호화된 Root Key)을 저장한다.
	//
	// 왜 barrier가 아니라 storage를 직접 쓰는가: barrier는 Root Key가
	// 있어야만 열 수 있는데, Root Key는 바로 이 seal이 공급하는 값이다 —
	// barrier로 sealed blob을 저장하려 하면 "Root Key를 얻기 위해 먼저
	// Root Key가 있어야 한다"는 순환(닭과 달걀 문제)이 생긴다. 하지만
	// sealed blob은 이미 TPM이 자체적으로 암호화해 내놓은 결과물이라,
	// barrier로 한 번 더 암호화할 실익이 없다 — 그래서 barrier를 거치지
	// 않고 storage에 직접 쓴다.
	store storage.StorageBackend

	// pcrSelection: Seal 시점에 어떤 PCR들에 봉인을 걸지. 비어 있으면
	// (기본값) PCR을 전혀 쓰지 않는다 — 즉 이 TPM이기만 하면 부팅 상태와
	// 무관하게 항상 Unseal이 가능하다.
	pcrSelection tpm2.PCRSelection

	mu sync.Mutex
}

// TPMOption은 NewTPMSeal의 선택적 설정을 표현한다. internal/rotation의
// functional options 패턴과 동일한 관례를 따른다.
type TPMOption func(*TPMSeal)

// WithPCRs는 Seal 시점에 봉인을 걸 PCR 인덱스들을 지정한다. 지정하지 않으면
// PCR을 쓰지 않는다(기본값) — 그 트레이드오프는 파일 상단 주석 참고.
func WithPCRs(pcrs []int) TPMOption {
	return func(s *TPMSeal) {
		s.pcrSelection = tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrs}
	}
}

// NewTPMSeal은 tpm(시뮬레이터/실제TPM/vTPM)과 sealed blob을 저장할 store로
// TPMSeal을 만든다.
func NewTPMSeal(tpm io.ReadWriteCloser, store storage.StorageBackend, opts ...TPMOption) *TPMSeal {
	s := &TPMSeal{tpm: tpm, store: store}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// storageRootKey는 이 TPM의 SRK(Storage Root Key)를 로드한다. SRK는 "이
// TPM에 항상 결정적으로 존재하는" 비대칭키다 — TPM이 켜져 있는 한 몇 번을
// 다시 불러와도 같은 키이므로, Seal 때 쓴 SRK와 Unseal 때 쓴 SRK가 같은
// TPM에서 왔다면 항상 같은 키다. 그때그때 새로 로드해서 쓰면 된다.
func (s *TPMSeal) storageRootKey() (*client.Key, error) {
	return client.StorageRootKeyECC(s.tpm)
}

// InitTPM은 최초 1회 실행하는 초기화 함수다(ShamirSeal.InitShamir와 같은
// 역할). crypto/rand로 새 Root Key(32바이트)를 만들고, TPM의 Seal 명령으로
// 그 키를 이 TPM에 묶어 봉인한 뒤, 그 결과(sealed blob)를 store에 저장한다.
//
// TPM에 Seal을 요청하면 내부적으로(client.Key.Seal 안에서) 다음이 일어난다:
//  1. SRK 아래에 "이 데이터만 담는" 새 오브젝트를 하나 만든다
//     (tpm2.CreateKeyWithSensitive) — Root Key 32바이트가 이 오브젝트의
//     private area에 들어가고, 그 private area는 SRK로만 복호화할 수 있는
//     형태로 TPM 내부에서 암호화된다.
//  2. PCR을 지정했다면(WithPCRs), 그 PCR들의 "봉인 시점 값"을 오브젝트의
//     인증 정책(AuthPolicy)에 새겨 넣는다 — 나중에 Unseal할 때 PCR이
//     달라져 있으면 이 정책 검사에서 걸린다.
//  3. TPM은 "이 오브젝트가 실제로 이 TPM에서, 이 PCR 상태로 만들어졌다"는
//     증명(creation ticket)도 함께 만들어 돌려준다 — 조작 여부를 나중에
//     검증할 수 있게.
//  4. 결과로 private/public 두 부분(둘 다 이 오브젝트를 나중에 다시 불러
//     오는 데 필요)과 창조 관련 메타데이터를 담은 pb.SealedBytes를 받는다.
//     proto.Marshal로 그대로 직렬화해 store에 저장한다 — 직접 길이
//     프리픽스 포맷을 만드는 대신, 라이브러리가 이미 protobuf 메시지로
//     정의해둔 걸 그대로 쓴다.
func (s *TPMSeal) InitTPM() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.store.Get(tpmBlobStorageKey)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrTPMAlreadyInitialized
	}

	rootKey := make([]byte, kmscrypto.KeyLen)
	if _, err := rand.Read(rootKey); err != nil {
		return nil, err
	}

	srk, err := s.storageRootKey()
	if err != nil {
		zeroBytesTPM(rootKey)
		return nil, err
	}
	defer srk.Close()

	blob, err := srk.Seal(rootKey, client.SealOpts{Current: s.pcrSelection})
	if err != nil {
		zeroBytesTPM(rootKey)
		return nil, err
	}

	data, err := proto.Marshal(blob)
	if err != nil {
		zeroBytesTPM(rootKey)
		return nil, err
	}

	if err := s.store.Put(tpmBlobStorageKey, data); err != nil {
		zeroBytesTPM(rootKey)
		return nil, err
	}

	return rootKey, nil
}

// Unseal은 store에서 sealed blob을 불러와 TPM에 Unseal을 요청해 Root Key를
// 복원한다.
//
// PCR을 지정해 Seal했다면(WithPCRs), 이 호출 안에서 TPM이 자동으로 PCR
// 검증도 함께 수행한다 — blob 자체에 "봉인 당시 PCR 값"이 기록돼 있고, TPM은
// 그 값과 현재 PCR 값이 일치해야만 실제로 오브젝트를 복호화하는 정책 세션을
// 통과시킨다. 즉 "PCR이 맞는지 확인하는 코드"를 우리가 따로 짤 필요가 없다 —
// TPM 자체가 그 검증을 거부/승인의 형태로 대신 해준다.
func (s *TPMSeal) Unseal() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.store.Get(tpmBlobStorageKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, ErrTPMNotInitialized
	}

	var blob pb.SealedBytes
	if err := proto.Unmarshal(data, &blob); err != nil {
		return nil, err
	}

	srk, err := s.storageRootKey()
	if err != nil {
		return nil, err
	}
	defer srk.Close()

	rootKey, err := srk.Unseal(&blob, client.UnsealOpts{})
	if err != nil {
		return nil, err
	}
	if len(rootKey) != kmscrypto.KeyLen {
		zeroBytesTPM(rootKey)
		return nil, ErrTPMInvalidRootKeyLength
	}

	return rootKey, nil
}

// IsConfigured는 store에 sealed blob이 이미 존재하는지(InitTPM이 이미
// 실행됐는지) 반환한다.
func (s *TPMSeal) IsConfigured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.store.Get(tpmBlobStorageKey)
	return err == nil && data != nil
}

// Type은 이 seal 구현의 이름 "tpm"을 반환한다.
func (s *TPMSeal) Type() string {
	return "tpm"
}

// zeroBytesTPM은 슬라이스를 0으로 덮어써서, 더 이상 필요 없는 키 material이
// 메모리에 평문으로 남는 시간을 최소화한다.
//
// (shamir.go에도 같은 기능의 zeroBytes가 있다. 두 구현체가 각각 다른 브랜치에서
//  개발되어 서로 의존하지 않도록 이름을 분리해뒀다. 둘 다 main에 머지된 뒤
//  하나로 합치는 게 좋다.)
func zeroBytesTPM(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
