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
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}, nil
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
