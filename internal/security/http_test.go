package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSVerificationAndRenewal(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.crt")
	os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	client, e := TLSClient(p)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name    string
		expired bool
		want    bool
	}{{"localhost", false, true}, {"wrong.invalid", false, false}, {"localhost", true, false}, {"localhost", false, true}} {
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{tc.name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if tc.expired {
			leaf.NotBefore = time.Now().Add(-2 * time.Hour)
			leaf.NotAfter = time.Now().Add(-time.Hour)
		}
		cert, _ := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}}}
		srv.StartTLS()
		url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
		resp, e := client.Get(url)
		if (e == nil) != tc.want {
			t.Fatalf("TLS validation %s expired=%v", tc.name, tc.expired)
		}
		if resp != nil {
			resp.Body.Close()
		}
		if _, e = http.Get(url); e == nil {
			t.Fatal("untrusted CA accepted")
		}
		srv.Close()
	}
}
func TestBodyLimitAndRotatedToken(t *testing.T) {
	w := httptest.NewRecorder()
	Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })).ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(strings.Repeat("x", (2<<20)+1))))
	if w.Code != 413 {
		t.Fatal("oversize accepted")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = append(seen, r.Header.Get("Authorization")) }))
	defer srv.Close()
	client := &http.Client{Transport: FileToken{Base: http.DefaultTransport, Path: path}}
	for _, v := range []string{"fixture-one", "fixture-two"} {
		os.WriteFile(path, []byte(v), 0600)
		res, e := client.Get(srv.URL)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
	}
	if len(seen) != 2 || seen[0] == seen[1] {
		t.Fatal("projected token not refreshed")
	}
	os.Remove(path)
	if _, e := client.Get(srv.URL); e == nil {
		t.Fatal("missing token accepted")
	}
}

// 동시 요청이 많아도 keep-alive 연결이 재사용되어야 한다.
// Go 기본값(MaxIdleConnsPerHost=2)이면 초과 연결이 매 요청 닫히고 TLS 핸드셰이크를 반복한다.
func TestTLSClientReusesConnectionsUnderConcurrency(t *testing.T) {
	const workers, perWorker = 16, 50
	var newConns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()

	p := filepath.Join(t.TempDir(), "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if e := os.WriteFile(p, pemBytes, 0600); e != nil {
		t.Fatal(e)
	}
	client, e := TLSClient(p)
	if e != nil {
		t.Fatal(e)
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				resp, e := client.Get(srv.URL)
				if e != nil {
					t.Error(e)
					return
				}
				io.Copy(io.Discard, resp.Body) // 본문을 끝까지 읽어야 연결이 풀로 돌아간다
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	if got := newConns.Load(); got > workers*2 {
		t.Fatalf("new connections = %d, want <= %d (connection reuse broken)", got, workers*2)
	}
}
