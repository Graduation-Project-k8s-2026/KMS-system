package demo

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/pkg/kmsfile"
)

// 브라우저 구현(ui/kmsfile.js, WebCrypto)과 Go 구현(pkg/kmsfile)이 서로의 파일을 풀 수 있는지 Node로 확인한다.
// Node가 없으면 건너뛴다.
func TestBrowserAndGoImplementationsInteroperate(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	key := make([]byte, 32)
	rand.Read(key)
	for _, size := range []int{0, 1, kmsfile.DefaultChunkSize, kmsfile.DefaultChunkSize + 1, 3*kmsfile.DefaultChunkSize + 77} {
		data := make([]byte, size)
		rand.Read(data)
		// Go로 암호화 → Node로 복호화
		var enc bytes.Buffer
		if err := kmsfile.Encrypt(&enc, bytes.NewReader(data), kmsfile.Params{KeyName: "team.k", DataKeyCiphertext: "kms:v1:fixture", DataKey: append([]byte(nil), key...)}); err != nil {
			t.Fatal(err)
		}
		in, out := filepath.Join(dir, "go.kmsf"), filepath.Join(dir, "plain.out")
		os.WriteFile(in, enc.Bytes(), 0o600)
		runNode(t, node, "dec", in, hex.EncodeToString(key), out)
		if got, _ := os.ReadFile(out); !bytes.Equal(got, data) {
			t.Fatalf("size %d: Go-encrypted file not decrypted correctly by the browser implementation", size)
		}
		// Node로 암호화 → Go로 복호화
		plainIn, nodeOut := filepath.Join(dir, "plain.in"), filepath.Join(dir, "node.kmsf")
		os.WriteFile(plainIn, data, 0o600)
		runNode(t, node, "enc", plainIn, hex.EncodeToString(key), nodeOut)
		raw, _ := os.ReadFile(nodeOut)
		d, err := kmsfile.NewDecoder(bytes.NewReader(raw))
		if err != nil || d.Header.KeyName != "team.k" || d.Header.DataKeyCiphertext != "kms:v1:fixture" {
			t.Fatalf("size %d: browser header unreadable by Go: %v %+v", size, err, d)
		}
		var back bytes.Buffer
		if err := d.Decrypt(&back, append([]byte(nil), key...), "team.k"); err != nil || !bytes.Equal(back.Bytes(), data) {
			t.Fatalf("size %d: browser-encrypted file not decrypted by Go: %v", size, err)
		}
		// 브라우저 구현도 변조를 탐지한다
		if size > 0 {
			bad := append([]byte(nil), raw...)
			bad[len(bad)-1] ^= 1
			os.WriteFile(in, bad, 0o600)
			if c := exec.Command(node, "testdata/interop.js", "dec", in, hex.EncodeToString(key), out); c.Run() == nil {
				t.Fatalf("size %d: browser implementation accepted a tampered file", size)
			}
		}
	}
}

func runNode(t *testing.T, node string, args ...string) {
	t.Helper()
	cmd := exec.Command(node, append([]string{"testdata/interop.js"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("node %v: %v\n%s", args, err, out)
	}
}
