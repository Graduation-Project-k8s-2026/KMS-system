package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/pkg/kmsfile"
)

// transitMaxBytes: 이 크기 이하의 입력은 Transit encrypt(문자열 `kms:v..`), 넘으면 datakey + kmsfile 형식.
// 서버의 요청 본문 상한(2 MiB)에 base64 확장(4/3)을 감안한 값이다.
const transitMaxBytes = 1 << 20

type config struct {
	Addr      string `json:"addr"`
	CAFile    string `json:"ca_file"`
	TokenFile string `json:"token_file,omitempty"` // 토큰이 든 파일의 경로 (토큰 자체가 아님)
	Token     string `json:"token,omitempty"`      // --save-token 을 명시했을 때만
}

func configPath(getenv func(string) string) string {
	if p := getenv("KMS_CONFIG"); p != "" {
		return p
	}
	home := getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return filepath.Join(home, ".config", "kms", "config.json")
}

func loadConfig(getenv func(string) string) (config, error) {
	var c config
	b, err := os.ReadFile(configPath(getenv))
	if err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return c, errors.New("설정 파일을 읽을 수 없어요. `kms login`을 다시 실행해 주세요")
		}
	} else if !os.IsNotExist(err) {
		return c, err
	}
	if v := getenv("KMS_ADDR"); v != "" {
		c.Addr = v
	}
	if v := getenv("KMS_CA"); v != "" {
		c.CAFile = v
	}
	if c.Addr == "" {
		return c, errors.New("서버 주소가 없어요. 먼저 `kms login --addr https://<주소>:9443 --ca <CA 인증서 파일>`을 실행하세요")
	}
	return c, nil
}

// resolveToken: KMS_TOKEN 환경변수 > --token-file > 설정의 token_file > 설정에 저장된 token.
func resolveToken(c config, flagFile string, getenv func(string) string) (string, error) {
	if t := strings.TrimSpace(getenv("KMS_TOKEN")); t != "" {
		return t, nil
	}
	for _, f := range []string{flagFile, c.TokenFile} {
		if f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return "", fmt.Errorf("토큰 파일을 읽을 수 없어요: %s", f)
			}
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, nil
			}
			return "", fmt.Errorf("토큰 파일이 비어 있어요: %s", f)
		}
	}
	if c.Token != "" {
		return c.Token, nil
	}
	return "", errors.New("토큰이 없어요. 환경변수 KMS_TOKEN을 설정하거나 --token-file <파일>을 주세요 (토큰은 관리자에게 발급받으세요)")
}

func newHTTPClient(c config) (*http.Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("CA 인증서 파일을 읽을 수 없어요: %s", c.CAFile)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA 인증서 형식이 올바르지 않아요 (PEM이어야 해요): %s", c.CAFile)
		}
		tc.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = tc
	return &http.Client{Timeout: 60 * time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("리다이렉트는 따르지 않아요")
	}}, nil
}

// apiError는 서버의 {error,message,hint} 오류 본문이다.
type apiError struct {
	Status     int
	Code       string `json:"error"`
	Message    string `json:"message"`
	Hint       string `json:"hint"`
	RetryAfter string
}

func (e *apiError) Error() string { return friendly(e) }

var koCode = map[string]string{
	"unauthorized":        "인증에 실패했어요. 토큰이 없거나 만료되었거나 잘못됐어요. 새 토큰을 발급받으세요",
	"forbidden":           "권한이 없어요. 이 키를 쓸 수 있는 계정인지, 키 이름이 `kms-external.<이름>` 형식인지 확인하세요",
	"key_not_found":       "키를 찾을 수 없어요. 키 이름을 확인하세요",
	"key_not_active":      "키가 사용 중지(또는 삭제 예약) 상태예요. 관리자에게 문의하세요",
	"version_not_allowed": "이 암호문을 만든 키 버전은 더 이상 복호화할 수 없어요 (관리자가 차단했어요)",
	"version_not_found":   "이 암호문을 만든 키 버전이 없어요",
	"invalid_ciphertext":  "암호문이 올바르지 않거나 손상되었어요, 또는 다른 키로 만든 것이에요",
	"payload_too_large":   "보내는 데이터가 너무 커요. 큰 파일은 `--mode file`(data key 방식)을 쓰세요",
	"sealed":              "서버가 봉인(sealed) 상태예요. 관리자가 해제해야 해요",
	"rate_limited":        "요청이 너무 많아요",
	"bad_request":         "요청 형식이 올바르지 않아요",
	"unavailable":         "서버가 요청을 처리할 수 없는 상태예요",
}

func friendly(e *apiError) string {
	msg, ok := koCode[e.Code]
	if !ok {
		msg = fmt.Sprintf("서버가 요청을 거절했어요 (HTTP %d)", e.Status)
	}
	if e.Status == http.StatusTooManyRequests {
		if n, err := strconv.Atoi(e.RetryAfter); err == nil && n > 0 {
			msg += fmt.Sprintf(" — %d초 뒤에 다시 시도하세요", n)
		} else {
			msg += " — 잠시 뒤에 다시 시도하세요"
		}
		if e.Message == "too many requests" || e.Message == "" {
			// 서버 문구는 영어이므로 한국어 안내만 쓴다
		}
	}
	out := msg
	if e.Code != "" {
		out += " [" + e.Code + "]"
	}
	return out
}

type client struct {
	cfg   config
	token string
	http  *http.Client
}

// call은 JSON POST 한 번. 토큰·요청 본문은 에러 메시지에 절대 넣지 않는다.
func (c *client) call(path string, body any, out any) error {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(body); err != nil {
		return err
	}
	u := strings.TrimRight(c.cfg.Addr, "/") + path
	req, err := http.NewRequest(http.MethodPost, u, &buf)
	if err != nil {
		return errors.New("서버 주소 형식이 올바르지 않아요")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return netError(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		ae := &apiError{Status: resp.StatusCode, RetryAfter: resp.Header.Get("Retry-After")}
		_ = json.Unmarshal(data, ae)
		return ae
	}
	return json.Unmarshal(data, out)
}

// netError: 연결 실패 원인을 한국어로. 원본 에러 문자열에는 URL 외 민감값이 없지만 토큰은 애초에 URL에 없다.
func netError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	switch {
	case errors.As(err, &ua):
		return errors.New("서버 인증서를 신뢰할 수 없어요. 관리자에게 받은 CA 인증서를 `kms login --ca`로 지정했는지 확인하세요")
	case errors.As(err, &hn):
		return errors.New("서버 인증서가 이 주소에 발급되지 않았어요 (SAN 불일치). 관리자에게 문의하세요")
	}
	return fmt.Errorf("서버에 연결하지 못했어요: %v", err)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stderr)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "version":
		fmt.Fprintf(stdout, "kms %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "login":
		err = cmdLogin(rest, stdin, stdout, stderr, getenv)
	case "encrypt":
		err = cmdEncrypt(rest, stdin, stdout, stderr, getenv)
	case "decrypt":
		err = cmdDecrypt(rest, stdin, stdout, stderr, getenv)
	case "datakey":
		err = cmdDatakey(rest, stdout, stderr, getenv)
	default:
		fmt.Fprintf(stderr, "알 수 없는 명령: %s\n\n", cmd)
		usage(stderr)
		return 2
	}
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(stderr, "오류:", err)
			return 2
		}
		fmt.Fprintln(stderr, "오류:", err)
		return 1
	}
	return 0
}

type usageError struct{ msg string }

func (u usageError) Error() string { return u.msg }

func usage(w io.Writer) {
	fmt.Fprint(w, `kms — KMS 명령줄 도구

사용법:
  kms login --addr https://<주소>:9443 --ca <CA 인증서 파일> [--token-file <파일> | --token-stdin] [--save-token]
  kms encrypt <키> [-i 입력] [-o 출력] [--mode auto|transit|file]
  kms decrypt [<키>] [-i 입력] [-o 출력] [--mode auto|transit|file]
  kms datakey <키> [--no-plaintext] [--bits 128|256]
  kms version

토큰: 환경변수 KMS_TOKEN 또는 --token-file(없으면 설정의 token_file)을 쓰세요. 설정 파일에 토큰을 저장하려면 login에 --save-token을 명시해야 해요.
`)
}

// parseMixed: 플래그와 위치 인자가 섞여 있어도 파싱한다 (예: `kms encrypt mykey -i a.txt`).
func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, usageError{err.Error()}
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// ---- login ----

func cmdLogin(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) error {
	fs := newFlagSet("login", stderr)
	addr := fs.String("addr", "", "")
	ca := fs.String("ca", "", "")
	tokenFile := fs.String("token-file", "", "")
	tokenStdin := fs.Bool("token-stdin", false, "")
	save := fs.Bool("save-token", false, "")
	skip := fs.Bool("skip-check", false, "")
	if _, err := parseMixed(fs, args); err != nil {
		return err
	}
	u, err := url.Parse(*addr)
	if *addr == "" || err != nil || u.Scheme != "https" || u.Host == "" {
		return usageError{"--addr 는 https://<주소>:9443 형식이어야 해요"}
	}
	if *ca == "" {
		return usageError{"--ca <CA 인증서 파일>이 필요해요 (관리자에게 받은 공개 인증서)"}
	}
	absCA, err := filepath.Abs(*ca)
	if err != nil {
		return err
	}
	cfg := config{Addr: strings.TrimRight(*addr, "/"), CAFile: absCA}
	hc, err := newHTTPClient(cfg)
	if err != nil {
		return err
	}
	if *tokenFile != "" && *tokenStdin {
		return usageError{"--token-file 과 --token-stdin 은 함께 쓸 수 없어요"}
	}
	if *tokenFile != "" {
		abs, _ := filepath.Abs(*tokenFile)
		if _, err := os.Stat(abs); err != nil {
			return fmt.Errorf("토큰 파일을 찾을 수 없어요: %s", *tokenFile)
		}
		cfg.TokenFile = abs
	}
	var stdinToken string
	if *tokenStdin {
		b, _ := io.ReadAll(io.LimitReader(stdin, 64<<10))
		stdinToken = strings.TrimSpace(string(b))
		if stdinToken == "" {
			return errors.New("표준 입력에서 토큰을 읽지 못했어요")
		}
	}
	if *save {
		switch {
		case stdinToken != "":
			cfg.Token = stdinToken
		case cfg.TokenFile != "":
			b, err := os.ReadFile(cfg.TokenFile)
			if err != nil || strings.TrimSpace(string(b)) == "" {
				return errors.New("저장할 토큰을 읽지 못했어요")
			}
			cfg.Token, cfg.TokenFile = strings.TrimSpace(string(b)), ""
		default:
			return usageError{"--save-token 은 --token-file 또는 --token-stdin 과 함께 써야 해요"}
		}
	}
	if !*skip { // 접속 확인: 인증 없는 /healthz
		resp, err := hc.Get(cfg.Addr + "/healthz")
		if err != nil {
			return fmt.Errorf("%w (저장하지 않았어요. 주소·CA를 확인하거나 --skip-check 로 건너뛸 수 있어요)", netError(err))
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("서버 상태 확인이 실패했어요 (HTTP %d). 저장하지 않았어요", resp.StatusCode)
		}
	}
	p := configPath(getenv)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "설정을 저장했어요: %s (권한 0600)\n", p)
	switch {
	case cfg.Token != "":
		fmt.Fprintln(stdout, "토큰도 설정 파일에 저장했어요 (--save-token). 토큰은 수명이 짧으니 만료되면 다시 login 하세요.")
	case cfg.TokenFile != "":
		fmt.Fprintln(stdout, "토큰 파일 경로만 기억해요 (토큰 자체는 저장하지 않아요).")
	default:
		fmt.Fprintln(stdout, "토큰은 저장하지 않았어요. 사용할 때 환경변수 KMS_TOKEN을 설정하거나 --token-file 을 주세요.")
	}
	return nil
}

// ---- 공통: 클라이언트 만들기 ----

func newClient(getenv func(string) string, tokenFile string) (*client, error) {
	cfg, err := loadConfig(getenv)
	if err != nil {
		return nil, err
	}
	tok, err := resolveToken(cfg, tokenFile, getenv)
	if err != nil {
		return nil, err
	}
	hc, err := newHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	return &client{cfg: cfg, token: tok, http: hc}, nil
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// openIn/openOut: 파일 또는 표준 입출력. 출력 파일은 임시 파일에 쓰고 성공했을 때만 이름을 바꾼다 (실패한 복호화 결과를 남기지 않음).
func openIn(path string, stdin io.Reader) (io.Reader, func(), error) {
	if path == "" || path == "-" {
		return stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("입력 파일을 열 수 없어요: %s", path)
	}
	return f, func() { f.Close() }, nil
}

type outFile struct {
	w      io.Writer
	commit func() error
	abort  func()
}

func openOut(path string, stdout io.Writer, binary bool) (*outFile, error) {
	if path == "" || path == "-" {
		if f, ok := stdout.(*os.File); ok && binary && isTerminal(f) {
			return nil, usageError{"암호화된 파일(바이너리)은 터미널에 출력할 수 없어요. -o <출력 파일>을 주세요"}
		}
		return &outFile{w: stdout, commit: func() error { return nil }, abort: func() {}}, nil
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".kms-out-*")
	if err != nil {
		return nil, fmt.Errorf("출력 파일을 만들 수 없어요: %s", path)
	}
	return &outFile{w: tmp,
		commit: func() error {
			if err := tmp.Close(); err != nil {
				return err
			}
			if err := os.Chmod(tmp.Name(), 0o600); err != nil {
				return err
			}
			return os.Rename(tmp.Name(), path)
		},
		abort: func() { tmp.Close(); os.Remove(tmp.Name()) }}, nil
}

// ---- encrypt ----

func cmdEncrypt(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) error {
	fs := newFlagSet("encrypt", stderr)
	in := fs.String("i", "", "")
	out := fs.String("o", "", "")
	mode := fs.String("mode", "auto", "")
	tokenFile := fs.String("token-file", "", "")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageError{"사용법: kms encrypt <키> [-i 입력] [-o 출력] [--mode auto|transit|file]"}
	}
	if *mode != "auto" && *mode != "transit" && *mode != "file" {
		return usageError{"--mode 는 auto, transit, file 중 하나예요"}
	}
	key := pos[0]
	c, err := newClient(getenv, *tokenFile)
	if err != nil {
		return err
	}
	src, closeIn, err := openIn(*in, stdin)
	if err != nil {
		return err
	}
	defer closeIn()

	useFile := *mode == "file"
	var prefix []byte
	if *mode == "auto" {
		// transitMaxBytes+1 바이트까지만 읽어 크기를 판단한다 (큰 입력을 통째로 메모리에 올리지 않음)
		prefix, err = io.ReadAll(io.LimitReader(src, transitMaxBytes+1))
		if err != nil {
			return err
		}
		useFile = len(prefix) > transitMaxBytes
		src = io.MultiReader(bytes.NewReader(prefix), src)
	}
	o, err := openOut(*out, stdout, useFile)
	if err != nil {
		return err
	}
	if err := doEncrypt(c, key, src, o.w, useFile); err != nil {
		o.abort()
		return err
	}
	return o.commit()
}

func doEncrypt(c *client, key string, src io.Reader, dst io.Writer, useFile bool) error {
	if !useFile {
		data, err := io.ReadAll(io.LimitReader(src, transitMaxBytes+1))
		if err != nil {
			return err
		}
		if len(data) > transitMaxBytes {
			return fmt.Errorf("입력이 %d바이트를 넘어요. --mode file 을 쓰세요", transitMaxBytes)
		}
		var resp struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := c.call("/v1/encrypt/"+url.PathEscape(key), map[string]string{"plaintext": base64.StdEncoding.EncodeToString(data)}, &resp); err != nil {
			return err
		}
		_, err = fmt.Fprintln(dst, resp.Ciphertext)
		return err
	}
	var dk struct {
		Ciphertext string `json:"ciphertext"`
		Plaintext  string `json:"plaintext"`
	}
	if err := c.call("/v1/datakey/"+url.PathEscape(key), map[string]any{"bits": 256}, &dk); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(dk.Plaintext)
	if err != nil || len(raw) != kmsfile.DataKeyLen {
		return errors.New("서버가 올바르지 않은 data key를 돌려줬어요")
	}
	return kmsfile.Encrypt(dst, src, kmsfile.Params{KeyName: key, DataKeyCiphertext: dk.Ciphertext, DataKey: raw})
}

// ---- decrypt ----

func cmdDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) error {
	fs := newFlagSet("decrypt", stderr)
	in := fs.String("i", "", "")
	out := fs.String("o", "", "")
	mode := fs.String("mode", "auto", "")
	tokenFile := fs.String("token-file", "", "")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 || (*mode != "auto" && *mode != "transit" && *mode != "file") {
		return usageError{"사용법: kms decrypt [<키>] [-i 입력] [-o 출력] [--mode auto|transit|file]"}
	}
	key := ""
	if len(pos) == 1 {
		key = pos[0]
	}
	c, err := newClient(getenv, *tokenFile)
	if err != nil {
		return err
	}
	src, closeIn, err := openIn(*in, stdin)
	if err != nil {
		return err
	}
	defer closeIn()
	br := bufio.NewReaderSize(src, 64<<10)
	head, _ := br.Peek(4)
	isFile := *mode == "file" || (*mode == "auto" && kmsfile.IsKMSFile(head))
	o, err := openOut(*out, stdout, false)
	if err != nil {
		return err
	}
	if isFile {
		err = decryptFile(c, key, br, o.w)
	} else {
		err = decryptTransit(c, key, br, o.w)
	}
	if err != nil {
		o.abort()
		return err
	}
	return o.commit()
}

func decryptTransit(c *client, key string, src io.Reader, dst io.Writer) error {
	if key == "" {
		return usageError{"`kms:v..` 암호문을 풀려면 키 이름이 필요해요: kms decrypt <키> -i <파일>"}
	}
	data, err := io.ReadAll(io.LimitReader(src, 4<<20))
	if err != nil {
		return err
	}
	ct := strings.TrimSpace(string(data))
	if !strings.HasPrefix(ct, "kms:v") {
		return errors.New("입력이 KMS 암호문(`kms:v..` 문자열 또는 KMSF 파일)이 아니에요")
	}
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.call("/v1/decrypt/"+url.PathEscape(key), map[string]string{"ciphertext": ct}, &resp); err != nil {
		return err
	}
	plain, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return errors.New("서버 응답을 해석하지 못했어요")
	}
	_, err = dst.Write(plain)
	for i := range plain {
		plain[i] = 0
	}
	return err
}

func decryptFile(c *client, expectKey string, src io.Reader, dst io.Writer) error {
	d, err := kmsfile.NewDecoder(src)
	if err != nil {
		if errors.Is(err, kmsfile.ErrNotKMSFile) {
			return errors.New("KMSF 파일이 아니에요")
		}
		return errors.New("파일 헤더가 손상되었어요")
	}
	if expectKey != "" && expectKey != d.Header.KeyName {
		return errors.New("이 파일은 다른 키로 암호화되었어요 (파일에 기록된 키와 지정한 키가 달라요)")
	}
	var resp struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.call("/v1/decrypt/"+url.PathEscape(d.Header.KeyName), map[string]string{"ciphertext": d.Header.DataKeyCiphertext}, &resp); err != nil {
		return err
	}
	dk, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return errors.New("서버 응답을 해석하지 못했어요")
	}
	if err := d.Decrypt(dst, dk, expectKey); err != nil {
		if errors.Is(err, kmsfile.ErrAuthFailed) {
			return errors.New("파일이 변조되었거나 잘렸어요 (인증 실패). 복호화 결과를 저장하지 않았어요")
		}
		return err
	}
	return nil
}

// ---- datakey ----

func cmdDatakey(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	fs := newFlagSet("datakey", stderr)
	noPlain := fs.Bool("no-plaintext", false, "")
	bits := fs.Int("bits", 256, "")
	tokenFile := fs.String("token-file", "", "")
	pos, err := parseMixed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || (*bits != 128 && *bits != 256) {
		return usageError{"사용법: kms datakey <키> [--no-plaintext] [--bits 128|256]"}
	}
	c, err := newClient(getenv, *tokenFile)
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := c.call("/v1/datakey/"+url.PathEscape(pos[0]), map[string]any{"bits": *bits, "plaintext": !*noPlain}, &raw); err != nil {
		return err
	}
	var pretty bytes.Buffer
	json.Indent(&pretty, raw, "", "  ")
	fmt.Fprintln(stdout, pretty.String())
	return nil
}
