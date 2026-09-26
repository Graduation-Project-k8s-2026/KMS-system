package authz

import (
	"fmt"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClientFromEnv는 KMS_KUBECONFIG로 kube-apiserver 클라이언트를 만든다.
//
// KMS는 static pod로 배포되므로 ServiceAccount 토큰이 자동 마운트되지
// 않는다(kubelet이 매니페스트를 직접 읽어 생성하므로 admission
// controller를 거치지 않는다 — internal/authn 패키지 주석 참고). 그래서
// in-cluster config를 무조건 먼저 시도하는 대신, KMS_KUBECONFIG가
// 설정돼 있으면 그 kubeconfig 파일을 우선 쓴다 — static pod에 자격
// 증명을 명시적으로 마운트해줄 방법(예: hostPath로 kubeconfig 파일 마운트)
// 이 실제 배포 경로가 될 것이기 때문이다. KMS_KUBECONFIG가 비어 있을
// 때만 in-cluster config를 시도한다(일반 Deployment로 재배치되거나,
// 나중에 static pod가 아니게 되는 경우를 대비).
func NewClientFromEnv(kubeconfigPath string) (kubernetes.Interface, error) {
	var (
		cfg *rest.Config
		err error
	)

	if kubeconfigPath != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("authz: failed to load kubeconfig at %q (from KMS_KUBECONFIG): %w", kubeconfigPath, err)
		}
	} else {
		cfg, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("authz: KMS_KUBECONFIG is not set and in-cluster config is unavailable: %w", err)
		}
	}

	return kubernetes.NewForConfig(cfg)
}
