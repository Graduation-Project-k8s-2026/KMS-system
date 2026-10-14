package demo

import (
	"encoding/base64"
	"encoding/json"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/security"
	"net/http"
	"strings"
)

func Handler(client *bench.Client, origin string) http.Handler {
	m := http.NewServeMux()
	for _, path := range []string{"/healthz", "/readyz"} {
		m.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	}
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
	for _, op := range []string{"encrypt", "decrypt"} {
		m.HandleFunc("POST /"+op, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Origin") != origin || r.Header.Get("X-Demo-Request") != "1" {
				http.Error(w, "origin denied", 403)
				return
			}
			var req struct {
				Value string `json:"value"`
			}
			d := json.NewDecoder(r.Body)
			d.DisallowUnknownFields()
			if d.Decode(&req) != nil || len(req.Value) > 1<<20 {
				http.Error(w, "invalid input", 400)
				return
			}
			var value string
			var status int
			var err error
			if op == "encrypt" {
				value, status, _, err = client.Encrypt(r.Context(), "demo", []byte(req.Value))
			} else {
				var p []byte
				p, status, _, err = client.Decrypt(r.Context(), "demo", req.Value)
				value = base64.StdEncoding.EncodeToString(p)
				clear(p)
			}
			if err != nil {
				if status != 401 && status != 403 {
					status = 503
				}
				http.Error(w, "Transit request failed", status)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"value": value})
		})
	}
	return security.Limit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && r.URL.Path != "/readyz" && r.Host != strings.TrimPrefix(origin, "https://") {
			http.Error(w, "host denied", 403)
			return
		}
		w.Header().Set("Referrer-Policy", "no-referrer")
		m.ServeHTTP(w, r)
	}))
}

const page = `<!doctype html><html lang="ko"><meta charset="utf-8"><title>Transit 데모</title><h1>Transit 암호화 데모</h1><p>고정 demo 키를 사용합니다. 복호화 결과는 Base64입니다.</p><textarea id="value" autocomplete="off" placeholder="시험 문자열 또는 암호문"></textarea><button data-op="encrypt">암호화</button><button data-op="decrypt">복호화</button><button id="clear">지우기</button><pre id="output" role="status"></pre><script>const value=document.getElementById('value'),output=document.getElementById('output');document.querySelectorAll('[data-op]').forEach(b=>b.onclick=async()=>{try{const r=await fetch('/'+b.dataset.op,{method:'POST',headers:{'Content-Type':'application/json','X-Demo-Request':'1'},body:JSON.stringify({value:value.value})});if(!r.ok)throw Error('요청 실패 HTTP '+r.status);output.textContent=(await r.json()).value;value.value=''}catch(e){output.textContent=e.message}});document.getElementById('clear').onclick=()=>{value.value='';output.textContent=''};window.addEventListener('pagehide',()=>{value.value='';output.textContent=''})</script></html>`
