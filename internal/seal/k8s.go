// k8s.go: Kubernetes Secret 위임 기반 Seal 구현체.
//
//  1. 이 방식이 하는 일: Root Key 보호를 우리가 직접 하지 않고 쿠버네티스에
//     통째로 위임한다. Root Key를 그냥 K8s Secret 오브젝트 하나에 담아두고,
//     "그 Secret을 저장/보호하는 책임"은 K8s(그리고 그 아래 etcd)에게 맡긴다.
//     구현이 극도로 단순한 대신(Secret 하나 만들고 읽는 게 전부), 보안 수준은
//     우리 코드가 아니라 전적으로 클러스터가 어떻게 설정되어 있는지에 달려있다.
//
//  2. ★ 가장 중요한 사실: K8s Secret은 기본적으로 "암호화"가 아니라 그냥
//     base64 인코딩이다. base64는 누구나 즉시 디코딩할 수 있는 인코딩일 뿐
//     암호가 아니다. 그래서 이 방식의 실제 보안 수준은 클러스터 설정에 따라
//     완전히 달라진다:
//     - 로컬 kind/minikube(기본 설정): etcd에 Secret이 base64로만 저장된다
//     → 사실상 평문이나 다름없다. etcd 파일을 열어보면 누구나 Root Key를
//     읽을 수 있다.
//     - etcd encryption at rest를 켠 자체 호스팅 클러스터: etcd가 디스크에
//     쓰기 전에 암호화한다 → 그런데 "그 암호화에 쓰는 키는 어디에
//     보관하나?"라는 문제가 고스란히 다시 발생한다(우리가 지금 KMS를
//     만드는 이유와 똑같은 문제가 한 단계 아래로 옮겨갈 뿐이다).
//     - 매니지드 K8s(EKS/GKE/AKS): 보통 클라우드 제공자의 KMS로 etcd
//     암호화를 건다 → 이 경우 "K8s에 위임"이 실질적으로는 "클라우드
//     KMS에 위임"이 되는 셈이다.
//     즉 "KMS를 만드는 프로젝트인데, 그 KMS의 Root Key 보호를 다시 다른
//     KMS(클라우드 KMS)에 의존하게 될 수 있다"는 구조적 아이러니가 있다 —
//     이건 이 구현의 버그가 아니라 "위임"이라는 접근 자체가 갖는 근본적인
//     특성이다.
//
//  3. 그래서 실질적인 접근 제어는 K8s RBAC이 담당한다: 이 Secret을 get/list
//     할 수 있는 ServiceAccount/사용자가 누구인지가 곧 "누가 Root Key를 얻을
//     수 있는가"와 정확히 같은 질문이 된다. RBAC 설정이 느슨하면(예: 같은
//     네임스페이스의 아무 Pod나 이 Secret을 읽을 수 있게 해두면) 이 Seal의
//     보안은 그 즉시 무너진다.
//
// 4. 다른 구현체와의 대비 — [결정 3] 비교 실험의 핵심:
//   - Shamir: Root Key를 사람들에게 분산. 자동 unseal 불가(사람이 모여야
//     함). 구현이 셋 중 가장 복잡(직접 유한체 산술까지 구현).
//   - TPM: Root Key를 하드웨어(TPM 칩)에 묶음. 자동 unseal 가능. 그
//     하드웨어가 고장 나면 Root Key 영구 소실.
//   - K8s: Root Key 보호를 클러스터에 위임. 자동 unseal 가능. 구현이
//     셋 중 가장 단순(TPM처럼 하드웨어 프로토콜을 다루지도, Shamir처럼
//     수학을 구현하지도 않는다). 그 대신 보안이 "우리가 만든 것"이
//     아니라 전적으로 "클러스터가 어떻게 설정되어 있는가"에 달려있다 —
//     구현 난이도와 보안의 성격이 서로 완전히 다른 곳에 있는 구현체다.
package seal

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// rootKeySecretDataKey: Secret.Data 맵에서 Root Key를 담는 키 이름.
const rootKeySecretDataKey = "rootkey"

// k8sDefaultTimeout: Unseal()/IsConfigured()처럼 ctx를 받지 못하는 Seal
// 인터페이스 메서드 안에서 K8s API를 호출할 때 쓰는 기본 타임아웃.
const k8sDefaultTimeout = 10 * time.Second

var (
	// ErrK8sNotInitialized: InitK8s를 아직 실행하지 않은 상태(Secret이 없음)에서
	// Unseal을 호출했을 때 반환.
	ErrK8sNotInitialized = errors.New("seal: K8s secret not initialized; call InitK8s first")

	// ErrK8sAlreadyInitialized: 이미 Secret이 존재하는 상태에서 InitK8s를
	// 다시 호출했을 때 반환.
	//
	// 왜 덮어쓰면 안 되는가: InitK8s는 완전히 새로운 무작위 Root Key를
	// 만든다. 이미 Secret이 있는데도 그냥 덮어써버리면, 기존 Root Key로
	// 암호화된 모든 데이터를 영원히 복호화할 수 없게 된다 — 실수로 InitK8s를
	// 한 번 더 실행했을 뿐인데 KMS 전체가 복구 불가능해지는 사고를 막는
	// 방어선이다(ShamirSeal.InitShamir, TPMSeal.InitTPM과 같은 이유).
	ErrK8sAlreadyInitialized = errors.New("seal: K8s secret already initialized; refusing to overwrite existing secret")

	// ErrK8sInvalidRootKeyLength: Secret에 담긴 값이 없거나 길이가
	// crypto.KeyLen과 다를 때 반환한다(Secret이 이 seal이 아닌 다른 방법으로
	// 조작됐거나 손상된 경우).
	ErrK8sInvalidRootKeyLength = errors.New("seal: K8s secret contains a root key with an unexpected length")
)

// K8sSeal은 Root Key를 K8s Secret 오브젝트 하나에 저장해 보호를 클러스터에
// 위임하는 Seal 구현체다.
type K8sSeal struct {
	// client는 K8s API 서버와 통신하는 인터페이스다. TPMSeal이
	// io.ReadWriteCloser로 "TPM과의 통신 채널"을 추상화했던 것과 같은
	// 발상이다 — kubernetes.Interface로 받아두면, 테스트에서는
	// k8s.io/client-go/kubernetes/fake의 가짜 clientset(진짜 클러스터 없이
	// 메모리에서 API 호출을 흉내낸다)을, 실제 운영에서는 진짜 클러스터에
	// 연결된 clientset을 넘길 수 있다. K8sSeal의 나머지 코드는 어느 쪽이든
	// 한 줄도 바뀌지 않는다.
	client kubernetes.Interface

	namespace  string
	secretName string

	// timeout: Unseal()/IsConfigured()처럼 Seal 인터페이스 시그니처상 ctx를
	// 받을 수 없는 메서드 안에서 K8s API 호출에 쓸 기본 타임아웃.
	timeout time.Duration

	mu sync.Mutex
}

// NewK8sSeal은 client로 namespace/secretName Secret에 Root Key를 보관/조회하는
// K8sSeal을 만든다.
func NewK8sSeal(client kubernetes.Interface, namespace, secretName string) *K8sSeal {
	return &K8sSeal{
		client:     client,
		namespace:  namespace,
		secretName: secretName,
		timeout:    k8sDefaultTimeout,
	}
}

// NewK8sClientFromEnv는 실행 환경에 맞는 K8s 클라이언트를 만든다.
//
// in-cluster 설정을 먼저 시도하는 이유: KMS가 실제로 K8s Pod 안에서 동작할
// 때는, 그 Pod에 자동으로 마운트되는 ServiceAccount 토큰과 CA 인증서로 별도
// 자격증명 없이 API 서버에 접속할 수 있다(rest.InClusterConfig). 이게
// 실패하면(=Pod 안이 아니라 로컬 머신에서 돌고 있다는 뜻) KUBECONFIG
// 환경변수나 기본 경로(~/.kube/config)의 kubeconfig 파일로 폴백한다 — 로컬
// 개발 중 kind/minikube 클러스터에 접속해 테스트하는 흔한 워크플로우를
// 지원하기 위해서다. 즉 "Pod로 배포됐을 때"와 "로컬에서 개발할 때" 둘 다
// 코드 변경 없이 동작하게 하려면 이 두 경로가 모두 필요하다.
func NewK8sClientFromEnv() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			home, homeErr := os.UserHomeDir()
			if homeErr != nil {
				return nil, fmt.Errorf("seal: not running in-cluster and could not determine home directory for kubeconfig: %w", homeErr)
			}
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}

		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("seal: failed to load in-cluster config or kubeconfig at %q: %w", kubeconfigPath, err)
		}
	}

	return kubernetes.NewForConfig(cfg)
}

// InitK8s는 최초 1회 실행하는 초기화 함수다(ShamirSeal.InitShamir,
// TPMSeal.InitTPM과 같은 역할). crypto/rand로 새 Root Key(32바이트)를 만들고,
// 그 값을 담은 K8s Secret을 생성한다.
//
// Secret.Data에 raw 바이트를 그대로 넣으면 client-go가 base64 인코딩을 알아서
// 처리해준다(Secret의 JSON 표현에서 Data 필드는 base64 문자열이지만, Go
// 구조체 레벨에서는 그냥 []byte다) — 우리가 직접 인코딩할 필요가 없다. 다만
// 파일 상단 주석에서 설명했듯, 이 인코딩은 암호화가 아니라는 점이 이 방식의
// 핵심 특성이다.
func (s *K8sSeal) InitK8s(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	_, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err == nil {
		return nil, ErrK8sAlreadyInitialized
	}
	if !apierrors.IsNotFound(err) {
		return nil, err
	}

	rootKey := make([]byte, kmscrypto.KeyLen)
	if _, err := rand.Read(rootKey); err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s.secretName,
			Namespace: s.namespace,
			Labels: map[string]string{
				// 이 Secret이 KMS가 관리하는 Root Key라는 걸 나타낸다 —
				// 클러스터 운영자가 kubectl로 훑어볼 때, 또는 RBAC/네트워크
				// 정책을 이 라벨 기준으로 별도 취급하고 싶을 때 식별 근거가
				// 된다.
				"app.kubernetes.io/managed-by": "kms-system",
				"kms-system/purpose":           "root-key",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			rootKeySecretDataKey: rootKey,
		},
	}

	if _, err := s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		zeroBytesK8s(rootKey)
		return nil, err
	}

	return rootKey, nil
}

// UnsealContext는 ctx를 받는 버전의 Unseal이다. Secret을 읽어 Root Key를
// 반환한다.
//
// 왜 Unseal()과 따로 두었는가: Seal 인터페이스의 Unseal() ([]byte, error)은
// DevSeal/ShamirSeal/TPMSeal과 시그니처를 맞추기 위해 ctx를 받지 않는다 —
// K8sSeal 하나 때문에 인터페이스를 바꾸면 나머지 구현체와 그걸 호출하는
// barrier까지 전부 손대야 한다. 하지만 K8s API 호출은 취소/타임아웃 전파를
// 위해 ctx가 반드시 필요하다(client-go의 기본 계약). 그래서 "ctx를 받는 실제
// 구현"(UnsealContext)과 "인터페이스를 만족시키기 위해 기본 타임아웃으로 ctx를
// 만들어 호출만 위임하는 겉면"(Unseal)으로 나눴다 — 나중에 API 핸들러가 요청의
// ctx를 그대로 흘려보내고 싶을 때는 UnsealContext를 직접 쓸 수 있고, barrier
// 처럼 Seal 인터페이스로만 다루는 코드는 Unseal()을 그대로 쓰면 된다.
func (s *K8sSeal) UnsealContext(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	secret, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrK8sNotInitialized
		}
		return nil, err
	}

	rootKey := secret.Data[rootKeySecretDataKey]
	if len(rootKey) != kmscrypto.KeyLen {
		return nil, ErrK8sInvalidRootKeyLength
	}

	out := make([]byte, len(rootKey))
	copy(out, rootKey)
	return out, nil
}

// Unseal은 Seal 인터페이스가 요구하는 시그니처를 만족시키는 얇은 래퍼다 —
// context.Background()에 기본 타임아웃을 적용해 UnsealContext를 호출한다.
// 자세한 이유는 UnsealContext 주석 참고.
func (s *K8sSeal) Unseal() ([]byte, error) {
	return s.UnsealContext(context.Background())
}

// IsConfigured는 Secret이 이미 존재하는지(InitK8s가 이미 실행됐는지) 반환한다.
// Unseal과 같은 이유로 ctx를 받지 못하므로, 내부에서 기본 타임아웃으로 ctx를
// 만들어 쓴다.
func (s *K8sSeal) IsConfigured() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	_, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName, metav1.GetOptions{})
	return err == nil
}

// Type은 이 seal 구현의 이름 "k8s"를 반환한다.
func (s *K8sSeal) Type() string {
	return "k8s"
}

// zeroBytesK8s는 슬라이스를 0으로 덮어쓴다.
//
// (tpm.go의 zeroBytesTPM, shamir.go의 zeroBytes와 같은 기능이다. 세 구현체가
//
//	각각 다른 브랜치에서 개발되어 서로 의존하지 않도록 이름을 분리해뒀다.
//	모두 main에 머지된 뒤 하나로 합치는 게 좋다.)
func zeroBytesK8s(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
