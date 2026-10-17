package demo

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/security"
)

// 포털 화면(HTML/CSS/JS)은 바이너리 안에 넣는다(go:embed). 외부 CDN·폰트는 쓰지 않는다.
//
//go:embed ui
var uiFS embed.FS

// Config는 포털이 쓸 수 있는 키와 화면에 보여 줄 서비스 계정 이름이다.
type Config struct {
	// Keys: 요청에서 받을 수 있는 키 이름 허용 목록(DEMO_KEYS). 목록에 없는 키는 KMS로 보내지 않고 400.
	// "이 계정이 이 키를 써도 되는가"는 포털이 판단하지 않는다 — KMS(SAR)가 403으로 답한다.
	Keys []string
	// SALabel: "이 포털은 <이름> 권한으로 동작해요"에 쓰는 표시용 이름(DEMO_SA_LABEL). 토큰이 아니다.
	SALabel string
}

var keyNameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// ParseKeys는 DEMO_KEYS(쉼표 목록)를 검사해 키 이름 목록으로 바꾼다. 비어 있으면 기본 "demo".
func ParseKeys(csv string) ([]string, error) {
	var keys []string
	seen := map[string]bool{}
	for _, k := range strings.Split(csv, ",") {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		if !keyNameRE.MatchString(k) {
			return nil, errors.New("invalid key name in DEMO_KEYS")
		}
		seen[k] = true
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		keys = []string{"demo"}
	}
	return keys, nil
}

func Handler(client *bench.Client, origin string, cfg Config) http.Handler {
	allowed := map[string]bool{}
	for _, k := range cfg.Keys {
		allowed[k] = true
	}
	m := http.NewServeMux()
	for _, path := range []string{"/healthz", "/readyz"} {
		m.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	}
	ui, err := fs.Sub(uiFS, "ui")
	if err != nil {
		panic(err) // 빌드 때 embed된 경로라 런타임에 실패할 수 없다
	}
	files := http.FileServerFS(ui)
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
	m.Handle("GET /portal.css", files)
	m.Handle("GET /portal.js", files)
	m.Handle("GET /kmsfile.js", files)
	// 화면이 키 목록과 서비스 계정 이름을 가져가는 곳. 토큰·주소 같은 비밀은 없다.
	m.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"keys": cfg.Keys, "service_account": cfg.SALabel})
	})
	for _, op := range []string{"encrypt", "decrypt", "rewrap"} {
		m.HandleFunc("POST /"+op, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Origin") != origin || r.Header.Get("X-Demo-Request") != "1" {
				http.Error(w, "origin denied", 403)
				return
			}
			var req struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			}
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&req) != nil || len(req.Value) > 1<<20 {
				http.Error(w, "invalid input", 400)
				return
			}
			if !allowed[req.Key] { // 허용 목록 밖의 키는 KMS까지 보내지 않는다
				http.Error(w, "key not allowed", 400)
				return
			}
			var value string
			var status int
			var err error
			switch op {
			case "encrypt":
				value, status, _, err = client.Encrypt(r.Context(), req.Key, []byte(req.Value))
			case "decrypt":
				var p []byte
				p, status, _, err = client.Decrypt(r.Context(), req.Key, req.Value)
				value = base64.StdEncoding.EncodeToString(p)
				clear(p)
			case "rewrap":
				value, status, _, err = client.Rewrap(r.Context(), req.Key, req.Value)
			}
			if err != nil {
				// 401/403(인증·권한), 404(KMS에 그 키가 없음)는 그대로 알려 주고, 나머지는 503으로 뭉갠다.
				if status != 401 && status != 403 && status != 404 && status != 409 {
					status = 503
				}
				http.Error(w, "Transit request failed", status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"value": value})
		})
	}
	// 파일 암호화 탭용 data key 중계. 파일 자체는 서버로 오지 않는다 — 브라우저가 이 키로 직접 암호화한다(KMSF 형식).
	// 기존 허용 목록(DEMO_KEYS)과 Origin 검사를 그대로 적용한다. 응답의 평문 키는 이 요청의 브라우저만 받으며
	// 서버는 저장·로그하지 않는다. 복호화는 기존 /decrypt(헤더의 data key 암호문 → 평문 키)를 그대로 쓴다.
	m.HandleFunc("POST /datakey", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != origin || r.Header.Get("X-Demo-Request") != "1" {
			http.Error(w, "origin denied", 403)
			return
		}
		var req struct {
			Key string `json:"key"`
		}
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil {
			http.Error(w, "invalid input", 400)
			return
		}
		if !allowed[req.Key] {
			http.Error(w, "key not allowed", 400)
			return
		}
		ct, plain, status, err := client.DataKey(r.Context(), req.Key)
		if err != nil {
			if status != 401 && status != 403 && status != 404 && status != 409 {
				status = 503
			}
			http.Error(w, "Transit request failed", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"ciphertext": ct, "plaintext": plain})
	})
	return security.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && r.Host != strings.TrimPrefix(origin, "https://") {
			http.Error(w, "host denied", 403)
			return
		}
		w.Header().Set("Referrer-Policy", "no-referrer")
		m.ServeHTTP(w, r)
	}))
}
