package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const goodToken = "TEST-TOKEN-FIXTURE-1234567890"

// fakeKMS는 외부 리스너의 encrypt/decrypt/datakey를 흉내 낸 TLS 서버다 (암호는 가짜: base64 + 접두사).
type fakeKMS struct {
	srv           *httptest.Server
	mu            sync.Mutex
	datakeys      int
	lastPlainFlag *bool
	fail          func(path string) (int, string, string) // status, code, Retry-After
}

func newFake(t *testing.T) (*fakeKMS, string) {
	t.Helper()
	f := &fakeKMS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"status":"ok"}`)) })
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+goodToken {
			writeErr(w, 401, "unauthorized", "")
			return
		}
		if f.fail != nil {
			if st, code, ra := f.fail(r.URL.Path); st != 0 {
				writeErr(w, st, code, ra)
				return
			}
		}
		var req map[string]any
		json.NewDecoder(r.Body).Decode(&req)
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/encrypt/"):
			json.NewEncoder(w).Encode(map[string]string{"ciphertext": "kms:v1:" + req["plaintext"].(string)})
		case strings.HasPrefix(r.URL.Path, "/v1/decrypt/"):
			ct := req["ciphertext"].(string)
			if !strings.HasPrefix(ct, "kms:v1:") {
				writeErr(w, 400, "invalid_ciphertext", "")
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"plaintext": strings.TrimPrefix(ct, "kms:v1:")})
		case strings.HasPrefix(r.URL.Path, "/v1/datakey/"):
			f.mu.Lock()
			f.datakeys++
			if p, ok := req["plaintext"].(bool); ok {
				f.lastPlainFlag = &p
			}
			f.mu.Unlock()
			k := make([]byte, 32)
			rand.Read(k)
			b64 := base64.StdEncoding.EncodeToString(k)
			resp := map[string]any{"ciphertext": "kms:v1:" + b64, "key_version": 1}
			if p, ok := req["plaintext"].(bool); !ok || p {
				resp["plaintext"] = b64
			}
			json.NewEncoder(w).Encode(resp)
		}
	})
	f.srv = httptest.NewTLSServer(mux)
	t.Cleanup(f.srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}), 0o644)
	return f, ca
}

func writeErr(w http.ResponseWriter, status int, code, retryAfter string) {
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code, "message": "english message"})
}

type env map[string]string

func (e env) get(k string) string { return e[k] }

func runCLI(t *testing.T, e env, stdin string, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, er bytes.Buffer
	code = run(args, strings.NewReader(stdin), &o, &er, e.get)
	return code, o.String(), er.String()
}

// setup: login까지 끝낸 상태의 환경 (토큰은 KMS_TOKEN 환경변수로)
func setup(t *testing.T) (*fakeKMS, env, string) {
	t.Helper()
	f, ca := newFake(t)
	dir := t.TempDir()
	e := env{"KMS_CONFIG": filepath.Join(dir, "cfg", "config.json"), "KMS_TOKEN": goodToken}
	if code, _, er := runCLI(t, e, "", "login", "--addr", f.srv.URL, "--ca", ca); code != 0 {
		t.Fatalf("login failed: %s", er)
	}
	return f, e, dir
}

func TestLogin_SavesConfig0600_WithoutTokenByDefault(t *testing.T) {
	f, ca := newFake(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "cfg", "config.json")
	e := env{"KMS_CONFIG": cfgPath}
	tokFile := filepath.Join(dir, "tok")
	os.WriteFile(tokFile, []byte(goodToken+"\n"), 0o600)

	code, out, er := runCLI(t, e, "", "login", "--addr", f.srv.URL, "--ca", ca, "--token-file", tokFile)
	if code != 0 {
		t.Fatalf("login: %s", er)
	}
	st, _ := os.Stat(cfgPath)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(cfgPath))
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("config dir mode = %v", dst.Mode().Perm())
	}
	raw, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(raw), goodToken) {
		t.Fatal("token was written to the config without --save-token")
	}
	if !strings.Contains(string(raw), tokFile) || strings.Contains(out+er, goodToken) {
		t.Fatalf("config = %s", raw)
	}
	// 저장된 token_file로 바로 동작한다
	if code, _, er := runCLI(t, env{"KMS_CONFIG": cfgPath}, "hello", "encrypt", "k"); code != 0 {
		t.Fatalf("encrypt via saved token_file: %s", er)
	}
}

func TestLogin_SaveTokenIsExplicit(t *testing.T) {
	f, ca := newFake(t)
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	e := env{"KMS_CONFIG": cfgPath}
	// --token-stdin 만: 저장 안 함
	if code, _, er := runCLI(t, e, goodToken+"\n", "login", "--addr", f.srv.URL, "--ca", ca, "--token-stdin"); code != 0 {
		t.Fatal(er)
	}
	if raw, _ := os.ReadFile(cfgPath); strings.Contains(string(raw), goodToken) {
		t.Fatal("stdin token saved without --save-token")
	}
	if code, _, er := runCLI(t, e, "x", "encrypt", "k"); code == 0 || !strings.Contains(er, "KMS_TOKEN") {
		t.Fatalf("expected a token hint, code=%d err=%s", code, er)
	}
	// --save-token 명시: 0600으로 저장
	if code, _, er := runCLI(t, e, goodToken, "login", "--addr", f.srv.URL, "--ca", ca, "--token-stdin", "--save-token"); code != 0 {
		t.Fatal(er)
	}
	st, _ := os.Stat(cfgPath)
	raw, _ := os.ReadFile(cfgPath)
	if st.Mode().Perm() != 0o600 || !strings.Contains(string(raw), goodToken) {
		t.Fatalf("mode=%v", st.Mode().Perm())
	}
	if code, out, er := runCLI(t, e, "hi", "encrypt", "k"); code != 0 || !strings.HasPrefix(out, "kms:v1:") {
		t.Fatalf("encrypt with saved token: %d %s %s", code, out, er)
	}
	// --save-token 만으로는 거부
	if code, _, _ := runCLI(t, e, "", "login", "--addr", f.srv.URL, "--ca", ca, "--save-token"); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

func TestLogin_RejectsBadInputsAndDoesNotSaveOnConnectionFailure(t *testing.T) {
	f, ca := newFake(t)
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	e := env{"KMS_CONFIG": cfgPath}
	for _, args := range [][]string{
		{"login", "--addr", "http://x:9443", "--ca", ca},
		{"login", "--addr", f.srv.URL},
		{"login", "--addr", "https://127.0.0.1:1", "--ca", ca}, // 접속 불가
	} {
		if code, _, _ := runCLI(t, e, "", args...); code == 0 {
			t.Fatalf("%v accepted", args)
		}
	}
	if _, err := os.Stat(cfgPath); err == nil {
		t.Fatal("config saved despite failures")
	}
	// CA 없이(시스템 신뢰 저장소) 자체 서명 서버에 접속하면 인증서 안내
	bad := filepath.Join(t.TempDir(), "other.pem")
	os.WriteFile(bad, []byte("not pem"), 0o600)
	if code, _, er := runCLI(t, e, "", "login", "--addr", f.srv.URL, "--ca", bad); code == 0 || !strings.Contains(er, "PEM") {
		t.Fatalf("bad CA: %d %s", code, er)
	}
}

func TestSmallInputUsesTransitAndRoundTrips(t *testing.T) {
	_, e, dir := setup(t)
	in, out, back := filepath.Join(dir, "in"), filepath.Join(dir, "out"), filepath.Join(dir, "back")
	os.WriteFile(in, []byte("hello kms"), 0o600)
	if code, _, er := runCLI(t, e, "", "encrypt", "mykey", "-i", in, "-o", out); code != 0 {
		t.Fatal(er)
	}
	ct, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(ct), "kms:v1:") {
		t.Fatalf("small input should be a transit string, got %q", ct)
	}
	if code, _, er := runCLI(t, e, "", "decrypt", "mykey", "-i", out, "-o", back); code != 0 {
		t.Fatal(er)
	}
	if b, _ := os.ReadFile(back); string(b) != "hello kms" {
		t.Fatalf("round trip = %q", b)
	}
	// 키 이름 없이 transit 문자열을 풀려 하면 사용법 오류
	if code, _, er := runCLI(t, e, "", "decrypt", "-i", out); code != 2 || !strings.Contains(er, "키 이름") {
		t.Fatalf("decrypt without key: %d %s", code, er)
	}
}

func TestLargeInputAutoSelectsFileModeAndRoundTrips(t *testing.T) {
	f, e, dir := setup(t)
	big := make([]byte, transitMaxBytes+12345)
	rand.Read(big)
	in, enc, dec := filepath.Join(dir, "big"), filepath.Join(dir, "big.kmsf"), filepath.Join(dir, "big.dec")
	os.WriteFile(in, big, 0o600)
	if code, _, er := runCLI(t, e, "", "encrypt", "team.k", "-i", in, "-o", enc); code != 0 {
		t.Fatal(er)
	}
	head, _ := os.ReadFile(enc)
	if string(head[:4]) != "KMSF" || f.datakeys != 1 {
		t.Fatalf("expected KMSF file + 1 datakey call, got %q / %d", head[:4], f.datakeys)
	}
	// decrypt는 입력 앞부분으로 형식을 판별한다 (키 이름은 헤더에서)
	if code, _, er := runCLI(t, e, "", "decrypt", "-i", enc, "-o", dec); code != 0 {
		t.Fatal(er)
	}
	if b, _ := os.ReadFile(dec); !bytes.Equal(b, big) {
		t.Fatal("file round trip mismatch")
	}
	// 다른 키 이름을 지정하면 거부
	if code, _, er := runCLI(t, e, "", "decrypt", "other.k", "-i", enc, "-o", filepath.Join(dir, "x")); code == 0 || !strings.Contains(er, "다른 키") {
		t.Fatalf("key mismatch: %d %s", code, er)
	}
	// 표준 입력도 같은 판단 (큰 입력)
	var o bytes.Buffer
	var er bytes.Buffer
	if c := run([]string{"encrypt", "team.k", "-o", filepath.Join(dir, "s.kmsf")}, bytes.NewReader(big), &o, &er, e.get); c != 0 {
		t.Fatal(er.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "s.kmsf")); string(b[:4]) != "KMSF" {
		t.Fatal("stdin big input should be file mode")
	}
}

func TestModeFlagForcesFormat(t *testing.T) {
	f, e, dir := setup(t)
	out := filepath.Join(dir, "o")
	// 작은 입력도 --mode file
	if code, _, er := runCLI(t, e, "tiny", "encrypt", "k", "--mode", "file", "-o", out); code != 0 {
		t.Fatal(er)
	}
	if b, _ := os.ReadFile(out); string(b[:4]) != "KMSF" || f.datakeys != 1 {
		t.Fatal("--mode file ignored")
	}
	// 큰 입력도 --mode transit 이면 서버 한도에 맡긴다: 1MiB 초과는 CLI가 먼저 거절
	big := strings.Repeat("a", transitMaxBytes+1)
	if code, _, er := runCLI(t, e, big, "encrypt", "k", "--mode", "transit"); code == 0 || !strings.Contains(er, "--mode file") {
		t.Fatalf("big transit: %d %s", code, er)
	}
	if code, _, _ := runCLI(t, e, "x", "encrypt", "k", "--mode", "bogus"); code != 2 {
		t.Fatal("bad mode accepted")
	}
}

func TestTamperedFileFailsAndLeavesNoOutput(t *testing.T) {
	_, e, dir := setup(t)
	in, enc, dec := filepath.Join(dir, "in"), filepath.Join(dir, "enc"), filepath.Join(dir, "dec")
	os.WriteFile(in, bytes.Repeat([]byte("z"), 200000), 0o600)
	runCLI(t, e, "", "encrypt", "k", "--mode", "file", "-i", in, "-o", enc)
	b, _ := os.ReadFile(enc)
	b[len(b)-5] ^= 1
	os.WriteFile(enc, b, 0o600)
	code, _, er := runCLI(t, e, "", "decrypt", "-i", enc, "-o", dec)
	if code == 0 || !strings.Contains(er, "변조") {
		t.Fatalf("tamper: %d %s", code, er)
	}
	if _, err := os.Stat(dec); err == nil {
		t.Fatal("failed decryption left an output file")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".kms-out-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestServerErrorsAreExplainedInKoreanWithoutSecrets(t *testing.T) {
	f, e, _ := setup(t)
	cases := []struct {
		status int
		code   string
		retry  string
		want   string
	}{
		{403, "forbidden", "", "권한이 없어요"},
		{404, "key_not_found", "", "키를 찾을 수 없어요"},
		{409, "key_not_active", "", "사용 중지"},
		{413, "payload_too_large", "", "--mode file"},
		{429, "rate_limited", "7", "7초 뒤"},
		{503, "sealed", "", "봉인"},
		{401, "unauthorized", "", "토큰"},
	}
	secretPlain := "PLAINTEXT-SECRET-FIXTURE"
	for _, c := range cases {
		c := c
		f.fail = func(string) (int, string, string) { return c.status, c.code, c.retry }
		code, out, er := runCLI(t, e, secretPlain, "encrypt", "k")
		if code != 1 || !strings.Contains(er, c.want) || !strings.Contains(er, c.code) {
			t.Errorf("%d %s: code=%d err=%q", c.status, c.code, code, er)
		}
		for _, leak := range []string{goodToken, secretPlain, base64.StdEncoding.EncodeToString([]byte(secretPlain))} {
			if strings.Contains(out+er, leak) {
				t.Errorf("%s: output leaks secret material", c.code)
			}
		}
	}
	f.fail = nil
	// 토큰이 틀리면 401 안내 (토큰 값은 출력하지 않음)
	e["KMS_TOKEN"] = "WRONG-TOKEN-VALUE"
	code, out, er := runCLI(t, e, "x", "encrypt", "k")
	if code != 1 || !strings.Contains(er, "인증") || strings.Contains(out+er, "WRONG-TOKEN-VALUE") {
		t.Fatalf("wrong token: %d %s", code, er)
	}
}

func TestUntrustedCertificateGivesHint(t *testing.T) {
	f, _ := newFake(t)
	cfgPath := filepath.Join(t.TempDir(), "c.json")
	// 서버와 무관한 다른 자체 서명 인증서를 CA로 지정 → 신뢰 불가 안내
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	otherCA := filepath.Join(t.TempDir(), "other.crt")
	os.WriteFile(otherCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	e := env{"KMS_CONFIG": cfgPath, "KMS_TOKEN": goodToken}
	if code, _, er := runCLI(t, e, "", "login", "--addr", f.srv.URL, "--ca", otherCA); code == 0 || !strings.Contains(er, "신뢰") {
		t.Fatalf("untrusted: %d %s", code, er)
	}
}

func TestDatakeyCommand(t *testing.T) {
	f, e, _ := setup(t)
	code, out, er := runCLI(t, e, "", "datakey", "team.k")
	if code != 0 || !strings.Contains(out, `"plaintext"`) || !strings.Contains(out, "kms:v1:") {
		t.Fatalf("datakey: %d %s %s", code, out, er)
	}
	code, out, _ = runCLI(t, e, "", "datakey", "team.k", "--no-plaintext")
	if code != 0 || strings.Contains(out, `"plaintext"`) || f.lastPlainFlag == nil || *f.lastPlainFlag {
		t.Fatalf("--no-plaintext: %d %s", code, out)
	}
	if code, _, _ := runCLI(t, e, "", "datakey"); code != 2 {
		t.Fatal("missing key accepted")
	}
}

func TestVersionAndUsage(t *testing.T) {
	if code, out, _ := runCLI(t, env{}, "", "version"); code != 0 || !strings.HasPrefix(out, "kms ") {
		t.Fatalf("version: %d %s", code, out)
	}
	if code, _, er := runCLI(t, env{}, ""); code != 2 || !strings.Contains(er, "사용법") {
		t.Fatalf("no args: %d", code)
	}
	if code, _, _ := runCLI(t, env{}, "", "bogus"); code != 2 {
		t.Fatal("unknown command")
	}
}
