package tlsreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair는 새 자체 서명 인증서(시리얼 지정)를 임시 이름에 쓰고 mv로 교체한다 (원자적 교체).
func writePair(t *testing.T, dir string, serial int64) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	kder, _ := x509.MarshalECPrivateKey(key)
	for name, blk := range map[string]*pem.Block{"tls.crt": {Type: "CERTIFICATE", Bytes: der}, "tls.key": {Type: "EC PRIVATE KEY", Bytes: kder}} {
		tmp := filepath.Join(dir, "."+name+".new")
		if err := os.WriteFile(tmp, pem.EncodeToMemory(blk), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// serialSeenByClient는 실제 TLS 핸드셰이크로 서버가 내미는 인증서의 시리얼을 읽는다.
func serialSeenByClient(t *testing.T, r *Reloader) int64 {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	go func() {
		srv := tls.Server(s, r.Config())
		_ = srv.Handshake()
		srv.Close()
	}()
	cli := tls.Client(c, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	return cli.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
}

func newReloader(t *testing.T) (*Reloader, string, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	writePair(t, dir, 1)
	r, err := New(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r.now = func() time.Time { return now }
	r.lastCheck = now
	return r, dir, &now
}

func TestReload_NewCertUsedAfterIntervalOnly(t *testing.T) {
	r, dir, now := newReloader(t)
	if got := serialSeenByClient(t, r); got != 1 {
		t.Fatalf("initial serial = %d", got)
	}
	writePair(t, dir, 2)
	// 30초 이내에는 파일을 다시 보지 않는다 (핸드셰이크마다 stat하지 않음)
	*now = now.Add(29 * time.Second)
	if got := serialSeenByClient(t, r); got != 1 {
		t.Fatalf("serial before interval = %d, want 1", got)
	}
	*now = now.Add(2 * time.Second)
	if got := serialSeenByClient(t, r); got != 2 {
		t.Fatalf("serial after interval = %d, want 2", got)
	}
}

func TestReload_BrokenFileKeepsPreviousThenRecovers(t *testing.T) {
	r, dir, now := newReloader(t)
	// 반쯤 쓴 파일
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("-----BEGIN CERTIFICATE-----\nMIIB"), 0o600); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(31 * time.Second)
	if got := serialSeenByClient(t, r); got != 1 {
		t.Fatalf("broken file must keep the previous cert, got serial %d", got)
	}
	// 인증서와 키가 서로 다른 쌍이어도 유지
	writePair(t, dir, 3)
	other := t.TempDir()
	writePair(t, other, 9)
	b, _ := os.ReadFile(filepath.Join(other, "tls.key"))
	os.WriteFile(filepath.Join(dir, "tls.key"), b, 0o600)
	*now = now.Add(31 * time.Second)
	if got := serialSeenByClient(t, r); got != 1 {
		t.Fatalf("mismatched pair must keep the previous cert, got %d", got)
	}
	// 정상 파일로 복구되면 다음 확인에서 새 인증서
	writePair(t, dir, 4)
	*now = now.Add(31 * time.Second)
	if got := serialSeenByClient(t, r); got != 4 {
		t.Fatalf("after recovery serial = %d, want 4", got)
	}
}

func TestNew_FailsOnMissingFiles(t *testing.T) {
	if _, err := New("/nonexistent/a", "/nonexistent/b"); err == nil {
		t.Fatal("expected error")
	}
}
