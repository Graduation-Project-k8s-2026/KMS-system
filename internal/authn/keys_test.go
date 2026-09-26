package authn_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
)

func writePublicKeyPEM(t *testing.T, path string, pub any) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshaling public key failed: %v", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o644); err != nil {
		t.Fatalf("writing PEM file failed: %v", err)
	}
}

// TestLoadPublicKeys_RSAAndECDSA는 RSA/ECDSA PEM 공개키 파일을 각각
// 정확한 타입으로 로드하는지 확인한다.
func TestLoadPublicKeys_RSAAndECDSA(t *testing.T) {
	keys := newTestKeys(t)
	dir := t.TempDir()

	rsaPath := filepath.Join(dir, "rsa.pub")
	ecPath := filepath.Join(dir, "ec.pub")
	writePublicKeyPEM(t, rsaPath, keys.rsaKey.Public())
	writePublicKeyPEM(t, ecPath, keys.ecKey.Public())

	loaded, err := authn.LoadPublicKeys([]string{rsaPath, ecPath})
	if err != nil {
		t.Fatalf("LoadPublicKeys failed: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("len(loaded) = %d, want 2", len(loaded))
	}
	if _, ok := loaded[0].(*rsa.PublicKey); !ok {
		t.Fatalf("loaded[0] type = %T, want *rsa.PublicKey", loaded[0])
	}
	if _, ok := loaded[1].(*ecdsa.PublicKey); !ok {
		t.Fatalf("loaded[1] type = %T, want *ecdsa.PublicKey", loaded[1])
	}
}

// TestLoadPublicKeys_MissingFile_ReturnsError는 존재하지 않는 경로가 주어지면
// 명확한 에러로 실패하는지 확인한다 — 기동 시 KMS_AUTHN=on인데 키를 못
// 읽으면 서버가 곧바로 종료해야 하므로, 이 에러가 정확히 나야 한다.
func TestLoadPublicKeys_MissingFile_ReturnsError(t *testing.T) {
	if _, err := authn.LoadPublicKeys([]string{"/does/not/exist.pub"}); err == nil {
		t.Fatal("LoadPublicKeys succeeded for a missing file, want error")
	}
}

// TestLoadPublicKeys_NoPaths_ReturnsError는 경로가 하나도 주어지지 않으면
// 에러를 반환하는지 확인한다.
func TestLoadPublicKeys_NoPaths_ReturnsError(t *testing.T) {
	if _, err := authn.LoadPublicKeys(nil); err == nil {
		t.Fatal("LoadPublicKeys succeeded with no paths, want error")
	}
}

// TestSplitKeyPaths는 쉼표 구분 값을 트리밍하고 빈 항목을 버리는지 확인한다.
func TestSplitKeyPaths(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"/a/sa.pub", []string{"/a/sa.pub"}},
		{"/a/sa.pub,/b/sa-old.pub", []string{"/a/sa.pub", "/b/sa-old.pub"}},
		{" /a/sa.pub , /b/sa-old.pub ", []string{"/a/sa.pub", "/b/sa-old.pub"}},
		{"", nil},
		{",,", nil},
	}
	for _, c := range cases {
		got := authn.SplitKeyPaths(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitKeyPaths(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
