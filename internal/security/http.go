package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: Limit(h), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}
func Limit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Body != nil {
			b, e := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
			r.Body.Close()
			if e != nil {
				http.Error(w, "invalid body", 400)
				return
			}
			if len(b) > 2<<20 {
				http.Error(w, "body too large", 413)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(b)))
		}
		h.ServeHTTP(w, r)
	})
}
func TLSClient(ca string) (*http.Client, error) {
	b, e := os.ReadFile(ca)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("invalid CA file")
	}
	// DefaultTransport를 복제해 keep-alive/HTTP2 등 합리적인 기본값을 상속한다.
	// 그냥 &http.Transport{}를 쓰면 MaxIdleConnsPerHost=2라서 동시 요청이 3개 이상일 때
	// 초과 연결이 매번 닫히고 TLS 핸드셰이크를 반복한다.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // 기존 동작 유지: 환경변수 프록시를 쓰지 않는다
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	tr.MaxIdleConns = 256
	tr.MaxIdleConnsPerHost = 64
	tr.IdleConnTimeout = 90 * time.Second
	return &http.Client{Timeout: 30 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}, nil
}

// FileToken rereads projected credentials on every request and never follows redirects.
type FileToken struct {
	Base http.RoundTripper
	Path string
}

func (t FileToken) RoundTrip(r *http.Request) (*http.Response, error) {
	b, e := os.ReadFile(t.Path)
	if e != nil {
		return nil, errors.New("token file unavailable")
	}
	if strings.TrimSpace(string(b)) == "" {
		return nil, errors.New("empty token")
	}
	c := r.Clone(r.Context())
	c.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(b)))
	return t.Base.RoundTrip(c)
}
