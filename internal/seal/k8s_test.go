package seal

import (
	"bytes"
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// 컴파일 타임에 "*K8sSeal이 Seal 인터페이스를 만족하는가"를 확인한다.
// var _ Seal = (*ShamirSeal)(nil)/(*TPMSeal)(nil)과 같은 관용구다.
var _ Seal = (*K8sSeal)(nil)

func newTestK8sSeal() *K8sSeal {
	client := fake.NewSimpleClientset()
	return NewK8sSeal(client, "kms-system", "kms-root-key")
}

func TestK8sSeal_InitThenUnseal_RoundTrip(t *testing.T) {
	s := newTestK8sSeal()

	rootKey, err := s.InitK8s(context.Background())
	if err != nil {
		t.Fatalf("InitK8s failed: %v", err)
	}

	got, err := s.Unseal()
	if err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if !bytes.Equal(got, rootKey) {
		t.Fatalf("Unseal = %x, want %x", got, rootKey)
	}
}

func TestK8sSeal_RootKeyIs32Bytes(t *testing.T) {
	s := newTestK8sSeal()

	rootKey, err := s.InitK8s(context.Background())
	if err != nil {
		t.Fatalf("InitK8s failed: %v", err)
	}
	if len(rootKey) != 32 {
		t.Fatalf("len(rootKey) = %d, want 32", len(rootKey))
	}
}

func TestK8sSeal_Unconfigured_IsConfiguredFalse_UnsealErrors(t *testing.T) {
	s := newTestK8sSeal()

	if s.IsConfigured() {
		t.Fatal("IsConfigured() = true before InitK8s")
	}
	if _, err := s.Unseal(); err != ErrK8sNotInitialized {
		t.Fatalf("Unseal err = %v, want ErrK8sNotInitialized", err)
	}
}

func TestK8sSeal_IsConfiguredTrueAfterInit(t *testing.T) {
	s := newTestK8sSeal()

	if _, err := s.InitK8s(context.Background()); err != nil {
		t.Fatalf("InitK8s failed: %v", err)
	}
	if !s.IsConfigured() {
		t.Fatal("IsConfigured() = false after InitK8s")
	}
}

func TestK8sSeal_InitTwice_SecondRejected(t *testing.T) {
	s := newTestK8sSeal()

	if _, err := s.InitK8s(context.Background()); err != nil {
		t.Fatalf("InitK8s (1st) failed: %v", err)
	}
	if _, err := s.InitK8s(context.Background()); err != ErrK8sAlreadyInitialized {
		t.Fatalf("InitK8s (2nd) err = %v, want ErrK8sAlreadyInitialized", err)
	}
}

func TestK8sSeal_Type(t *testing.T) {
	s := newTestK8sSeal()
	if s.Type() != "k8s" {
		t.Fatalf("Type() = %q, want %q", s.Type(), "k8s")
	}
}

// TestK8sSeal_SecretStoresRootKeyAsPlaintext는 barrier_test.go의
// TestBarrier_StoredBytesAreCiphertext와 정반대되는 테스트다. 그 테스트는
// "barrier를 거친 데이터는 암호문으로만 저장된다"는 걸 증명하지만, 이
// 테스트는 그 반대 — "K8sSeal이 저장하는 Secret에는 Root Key가 그냥 평문
// 그대로 들어있다"는 걸 보여준다.
//
// 이건 버그가 아니라 이 방식의 근본적인 특성이다: K8sSeal은 Root Key를
// 암호화하지 않는다. "보호"를 K8s에 위임했을 뿐, 우리 코드는 암호화 연산을
// 한 번도 거치지 않는다. 그래서 이 Secret의 실제 보안은 전적으로 클러스터가
// 이 Secret을 어떻게 저장하느냐(파일 상단 주석의 etcd encryption-at-rest
// 여부 등)에 달려있다 — fake clientset으로 만든 이 Secret도, 실제 클러스터의
// 기본 설정에서도, Data["rootkey"]는 그냥 Root Key 그 자체다.
func TestK8sSeal_SecretStoresRootKeyAsPlaintext(t *testing.T) {
	client := fake.NewSimpleClientset()
	s := NewK8sSeal(client, "kms-system", "kms-root-key")

	rootKey, err := s.InitK8s(context.Background())
	if err != nil {
		t.Fatalf("InitK8s failed: %v", err)
	}

	secret, err := client.CoreV1().Secrets("kms-system").Get(context.Background(), "kms-root-key", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get Secret failed: %v", err)
	}

	stored := secret.Data[rootKeySecretDataKey]
	if !bytes.Equal(stored, rootKey) {
		t.Fatalf("Secret.Data[%q] = %x, want exactly the plaintext root key %x", rootKeySecretDataKey, stored, rootKey)
	}
}
