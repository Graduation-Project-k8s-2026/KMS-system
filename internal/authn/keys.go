package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// SplitKeyPaths는 KMS_SA_PUBLIC_KEY 값을 쉼표로 나눈 경로 목록으로
// 바꾼다. 여러 개를 지원하는 이유: apiserver 서명키 회전(rotation) 중에는
// 새 키/이전 키 두 개가 동시에 유효할 수 있어, 아직 이전 키로 서명된
// 토큰도 검증할 수 있어야 한다.
//
// 디렉터리를 통째로 읽는 방식 대신 쉼표 구분 목록을 택한 이유: 디렉터리
// 스캔은 K8s의 ConfigMap/Secret 볼륨 마운트 특유의 심볼릭 링크(..data),
// PEM이 아닌 파일 혼입 등을 걸러내는 로직이 추가로 필요하다. 쉼표 목록은
// 환경변수 값만 보면 정확히 무엇이 로드되는지 알 수 있고 구현도 단순하다.
func SplitKeyPaths(v string) []string {
	var paths []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// LoadPublicKeys는 주어진 경로들에서 PEM 인코딩된 공개키를 전부 읽어
// 반환한다. RSA/ECDSA 공개키만 지원한다 — kube-apiserver의 ServiceAccount
// 서명키가 실제로 이 두 종류뿐이기 때문이다(RS256 또는 ES256).
func LoadPublicKeys(paths []string) ([]crypto.PublicKey, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no public key paths given")
	}

	keys := make([]crypto.PublicKey, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading public key %q: %w", path, err)
		}

		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no PEM block found in %q", path)
		}

		var pub crypto.PublicKey
		if block.Type == "RSA PUBLIC KEY" {
			pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		} else {
			pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("parsing public key %q: %w", path, err)
		}

		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			keys = append(keys, pub)
		default:
			return nil, fmt.Errorf("unsupported public key type %T in %q (want RSA or ECDSA)", pub, path)
		}
	}

	return keys, nil
}
