package adminapi_test

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/adminapi"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/dashboard"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/jobs"
)

// 허용 경로 전수 점검: 관리 화면(ui2/*.js)이 호출하는 모든 경로를 뽑아 관리 API 허용 목록(라우터에 등록된 /v1, /api 경로)과 대조한다.
//   - 화면이 호출하는데 허용 목록에 없는 경로 → 실패 (화면이 운영에서 404/405가 된다)
//   - 허용 목록에 있는데 화면이 안 쓰는 경로 → 아래 knownUnusedByUI에 이유와 함께 적혀 있어야 한다 (새로 생기면 실패해서 사람이 판단하게 한다)

// 화면이 안 쓰지만 허용 목록에 둔 경로와 이유.
var knownUnusedByUI = map[string]string{
	"POST /v1/sys/init":             "최초 초기화는 화면에서 하지 않는다(서버에서 사람이 조각을 받아야 함). 기존 콘솔(/console)과 스크립트가 쓴다",
	"GET /v1/keys/":                 "GET /v1/keys의 슬래시 변형(별칭)",
	"POST /v1/keys/":                "POST /v1/keys의 슬래시 변형(별칭)",
	"GET /api/dashboard/status":     "기존 대시보드(/dashboard, internal/dashboard)가 쓴다 (v2 화면은 /api/dashboard/metrics를 쓴다)",
	"GET /api/dashboard/traffic":    "기존 대시보드(/dashboard)가 쓴다",
	"DELETE /api/bench/results/{p}": "기존 대시보드/콘솔의 결과 삭제. v2 화면에는 삭제 버튼이 없다",
	"GET /api/bench/results":        "기존 콘솔이 목록으로 쓴다 (v2는 개별 결과만 사용)",
	"POST /api/bench/results":       "벤치 결과 제출은 Job(서비스 어카운트)이 쓴다. 브라우저가 아니다",
}

// 라우터가 아니라 바깥 래퍼(Security.Wrap)가 직접 처리하는 경로: 세션·CSRF 토큰 발급.
var handledByWrapper = map[string]bool{"GET /api/session": true}

var apiCall = regexp.MustCompile(`K\.api\(\s*'(GET|POST|PUT|DELETE|PATCH)'\s*,\s*`)

// readExpr은 s의 앞에서부터 최상위 ','나 ')'가 나오기 전까지(괄호·따옴표 짝 고려) 한 표현식을 읽는다.
func readExpr(s string) string {
	depth, inStr := 0, byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inStr != 0:
			if c == inStr {
				inStr = 0
			}
		case c == '\'' || c == '"':
			inStr = c
		case c == '(':
			depth++
		case c == ')' || c == ',':
			if depth == 0 {
				return s[:i]
			}
			if c == ')' {
				depth--
			}
		}
	}
	return s
}

// exprToPath: `'/v1/keys/' + encodeURIComponent(n) + '/rotate'` → `/v1/keys/{p}/rotate` (쿼리스트링 제거).
func exprToPath(expr string) string {
	var out strings.Builder
	depth, inStr := 0, byte(0)
	start := 0
	flush := func(tok string) {
		tok = strings.TrimSpace(tok)
		if len(tok) >= 2 && (tok[0] == '\'' || tok[0] == '"') && tok[len(tok)-1] == tok[0] {
			out.WriteString(tok[1 : len(tok)-1])
		} else if tok != "" {
			out.WriteString("{p}")
		}
	}
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case inStr != 0:
			if c == inStr {
				inStr = 0
			}
		case c == '\'' || c == '"':
			inStr = c
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '+' && depth == 0:
			flush(expr[start:i])
			start = i + 1
		}
	}
	flush(expr[start:])
	p := out.String()
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

func uiCalls(t *testing.T) map[string]string { // "METHOD path" → 처음 본 파일
	t.Helper()
	files, _ := filepath.Glob("ui2/*.js")
	if len(files) == 0 {
		t.Fatal("no ui2 js files found")
	}
	got := map[string]string{}
	fetchRe := regexp.MustCompile(`fetch\('(/[^']*)'`)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		src := string(b)
		for _, m := range apiCall.FindAllStringSubmatchIndex(src, -1) {
			method := src[m[2]:m[3]]
			path := exprToPath(readExpr(src[m[1]:]))
			if strings.HasPrefix(path, "/") {
				got[method+" "+path] = filepath.Base(f)
			}
		}
		for _, m := range fetchRe.FindAllStringSubmatch(src, -1) {
			p := m[1]
			if i := strings.IndexByte(p, '?'); i >= 0 {
				p = p[:i]
			}
			got["GET "+p] = filepath.Base(f)
		}
	}
	return got
}

func allowedRoutes(t *testing.T) map[string]bool {
	t.Helper()
	r := adminapi.NewRouter(adminapi.Deps{SocketPath: "x", Jobs: &jobs.Service{}, Dashboard: &dashboard.Service{}, AuditDir: "x", RolesFile: "x"})
	out := map[string]bool{}
	walk := func(method, route string, h http.Handler, mws ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/v1/") || strings.HasPrefix(route, "/api/") {
			out[method+" "+regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(route, "{p}")] = true
		}
		return nil
	}
	if err := chi.Walk(r.(chi.Routes), walk); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUIPathsMatchAllowlist(t *testing.T) {
	ui, allowed := uiCalls(t), allowedRoutes(t)

	var missing, unused []string
	for call, file := range ui {
		if !allowed[call] && !handledByWrapper[call] {
			missing = append(missing, call+"  ("+file+")")
		}
	}
	for call := range allowed {
		if _, used := ui[call]; !used {
			if _, known := knownUnusedByUI[call]; !known {
				unused = append(unused, call)
			}
		}
	}
	// 알려진 미사용 목록이 낡았는지(이제 화면이 쓰거나 라우트가 사라진 항목)도 확인
	var stale []string
	for call := range knownUnusedByUI {
		if _, used := ui[call]; used || !allowed[call] {
			stale = append(stale, call)
		}
	}
	sort.Strings(missing)
	sort.Strings(unused)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("화면이 호출하지만 관리 API 허용 목록에 없는 경로:\n  %s", strings.Join(missing, "\n  "))
	}
	if len(unused) > 0 {
		t.Errorf("허용 목록에 있지만 화면이 쓰지 않는 경로 (knownUnusedByUI에 이유와 함께 추가하거나 허용 목록에서 빼세요):\n  %s", strings.Join(unused, "\n  "))
	}
	if len(stale) > 0 {
		t.Errorf("knownUnusedByUI가 낡았어요 (이제 화면이 쓰거나 라우트가 없음): %v", stale)
	}
	// 화면이 호출하면 안 되는 경로
	for call := range ui {
		if strings.Contains(call, "seal-migrate") {
			t.Errorf("화면이 seal-migrate를 호출해요: %s", call)
		}
	}
	t.Logf("화면 호출 %d개, 허용 목록(/v1,/api) %d개", len(ui), len(allowed))
}
