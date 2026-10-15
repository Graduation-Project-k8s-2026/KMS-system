package adminapi

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
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

// deny는 401/403 응답을 만든다. 상태 코드는 그대로 두고, 브라우저가 화면을 열려는 요청(Accept에
// text/html)일 때만 한국어 안내 HTML을 준다. API 호출(fetch 등)은 기존처럼 짧은 텍스트다.
func deny(w http.ResponseWriter, r *http.Request, code int, msg, guide string, showUser bool) {
	if r.Method != "GET" || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Error(w, msg, code)
		return
	}
	who := ""
	if vals := r.Header.Values("Tailscale-User-Login"); showUser && len(vals) == 1 {
		who = vals[0]
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	page := `<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>접근할 수 없어요</title>` +
		`<style>body{font:18px system-ui,"Noto Sans KR","Malgun Gothic",sans-serif;color:#1b2430;background:#fff;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}` +
		`main{max-width:34rem;padding:2rem;border:1px solid #dfe3e8;border-radius:10px}h1{font-size:1.4rem;margin:0 0 .75rem}p{line-height:1.6}small{color:#66707d}</style>` +
		`<main><h1>` + html.EscapeString(guide) + `</h1>`
	if who != "" {
		page += `<p>접속한 계정: <b>` + html.EscapeString(who) + `</b></p>`
	}
	page += `<p><small>HTTP ` + strconv.Itoa(code) + `</small></p></main></html>`
	_, _ = w.Write([]byte(page))
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
			deny(w, r, 403, "untrusted proxy peer", "허용되지 않은 경로로 접속했어요", false)
			return
		}
		if r.Host != s.Host {
			deny(w, r, 403, "invalid host", "올바른 주소로 접속해 주세요", false)
			return
		}
		who := r.Header.Get("Tailscale-User-Login")
		if who == "" || len(r.Header.Values("Tailscale-User-Login")) != 1 {
			deny(w, r, 401, "identity required", "로그인 정보를 확인할 수 없어요. Tailscale에 로그인한 상태로 접속했는지 확인하세요", false)
			return
		}
		roles, e := s.roles()
		if e != nil {
			http.Error(w, "roles unavailable", 503)
			return
		}
		role, ok := roles[who]
		if !ok {
			deny(w, r, 403, "role denied", "이 콘솔에 등록되지 않은 계정이에요. 관리자에게 역할 등록을 요청하세요", true)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/api/session" {
			token := s.token(who)
			http.SetCookie(w, &http.Cookie{Name: "kms-csrf", Value: token, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, Path: "/", MaxAge: 1800})
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"role": role, "user": who, "csrf_token": token})
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
