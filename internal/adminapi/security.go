package adminapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Security struct {
	RolesFile, Origin, Host string
	key                     []byte
}

func NewSecurity(roles, origin string) (*Security, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil {
		return nil, errors.New("public origin must be an HTTPS origin")
	}
	s := &Security{RolesFile: roles, Origin: origin, Host: u.Host, key: make([]byte, 32)}
	if _, e = rand.Read(s.key); e != nil {
		return nil, e
	}
	if _, e = s.roles(); e != nil {
		return nil, e
	}
	return s, nil
}
func (s *Security) roles() (map[string]string, error) {
	b, e := os.ReadFile(s.RolesFile)
	if e != nil {
		return nil, e
	}
	var doc struct {
		Version int               `json:"version"`
		Users   map[string]string `json:"users"`
	}
	if e = json.Unmarshal(b, &doc); e != nil {
		return nil, e
	}
	r := doc.Users
	if doc.Version != 1 {
		return nil, errors.New("unsupported roles version")
	}
	if len(r) == 0 {
		return nil, errors.New("roles empty")
	}
	for who, role := range r {
		if who == "" || (role != "admin" && role != "viewer") {
			return nil, errors.New("invalid role entry")
		}
	}
	return r, nil
}
func (s *Security) sign(who, nonce string) string {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(who + "\x00" + nonce))
	return hex.EncodeToString(m.Sum(nil))
}
func (s *Security) token(who string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	v := strconv.FormatInt(time.Now().Add(30*time.Minute).Unix(), 10) + "." + hex.EncodeToString(b)
	return v + "." + s.sign(who, v)
}
func (s *Security) valid(who, v string) bool {
	p := strings.Split(v, ".")
	if len(p) != 3 {
		return false
	}
	exp, e := strconv.ParseInt(p[0], 10, 64)
	return e == nil && time.Now().Unix() < exp && hmac.Equal([]byte(p[2]), []byte(s.sign(who, p[0]+"."+p[1])))
}
func (s *Security) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == "GET" && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") {
			next.ServeHTTP(w, r)
			return
		}
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "untrusted proxy peer", 403)
			return
		}
		if r.Host != s.Host {
			http.Error(w, "invalid host", 403)
			return
		}
		who := r.Header.Get("Tailscale-User-Login")
		if who == "" || len(r.Header.Values("Tailscale-User-Login")) != 1 {
			http.Error(w, "identity required", 401)
			return
		}
		roles, e := s.roles()
		if e != nil {
			http.Error(w, "roles unavailable", 503)
			return
		}
		role, ok := roles[who]
		if !ok {
			http.Error(w, "role denied", 403)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/api/session" {
			token := s.token(who)
			http.SetCookie(w, &http.Cookie{Name: "kms-csrf", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Path: "/", MaxAge: 1800})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"role": role, "csrf_token": token})
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if role != "admin" {
				http.Error(w, "admin required", 403)
				return
			}
			cookie, e := r.Cookie("kms-csrf")
			token := r.Header.Get("X-CSRF-Token")
			if r.Header.Get("Origin") != s.Origin || e != nil || !hmac.Equal([]byte(cookie.Value), []byte(token)) || !s.valid(who, token) {
				http.Error(w, "CSRF rejected", 403)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Subject returns only an explicitly configured human identity from the trusted peer.
func (s *Security) Subject(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || r.Host != s.Host {
		return "anonymous"
	}
	roles, e := s.roles()
	if e != nil {
		return "anonymous"
	}
	who := r.Header.Get("Tailscale-User-Login")
	if _, ok := roles[who]; !ok {
		return "anonymous"
	}
	return who
}
