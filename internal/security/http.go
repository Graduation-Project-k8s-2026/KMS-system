package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: Limit(h), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}

// bodyLimit: 요청 본문 상한(바이트).
const bodyLimit = 2 << 20

func writeLimitError(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body + "\n"))
}

func Limit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Body != nil {
			b, e := io.ReadAll(io.LimitReader(r.Body, bodyLimit+1))
			r.Body.Close()
			if e != nil {
				writeLimitError(w, 400, `{"error":"bad_request","message":"invalid request body"}`)
				return
			}
			if len(b) > bodyLimit {
				// 다운로드 주소 같은 외부 링크는 넣지 않는다 (힌트는 사용 방법만).
				writeLimitError(w, 413, fmt.Sprintf(`{"error":"payload_too_large","message":"request body exceeds the limit","limit_bytes":%d,"hint":"use the datakey API or the kms CLI"}`, bodyLimit))
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
