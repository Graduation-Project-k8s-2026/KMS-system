package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
)

// Info는 GET /api/info로 보여 줄 배포 정보다. 비밀값(토큰, 키, 주소)은 담지 않는다 —
// 모두 배포 때 이미 환경변수로 박히는 "무슨 버전이 떠 있나" 수준의 값이다.
type Info struct {
	ServerVersion string
	SourceSHA     string
	BenchImage    string
	AdminImage    string
}

func handleInfo(info Info, auditEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_version": info.ServerVersion,
			"source_sha":     info.SourceSHA,
			"bench_image":    info.BenchImage,
			"admin_image":    info.AdminImage,
			"audit_enabled":  auditEnabled,
		})
	}
}

// maskEmail은 "abcdef@example.test"를 "abc***@example.test"로 가린다.
// 화면에는 원문 이메일이 가지 않게 서버에서 가린다. @가 없는 이름도 앞 3글자만 남긴다.
func maskEmail(s string) string {
	local, domain, hasAt := strings.Cut(s, "@")
	r := []rune(local)
	if len(r) > 3 {
		r = r[:3]
	}
	out := string(r) + "***"
	if hasAt {
		out += "@" + domain
	}
	return out
}

// handleConsoleUsers는 역할 파일의 사용자와 역할을 (이메일을 가린 채) 돌려준다. 조회 전용이다.
func handleConsoleUsers(rolesFile string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := readRoles(rolesFile)
		if err != nil {
			http.Error(w, "roles unavailable", http.StatusServiceUnavailable)
			return
		}
		type row struct {
			User string `json:"user"`
			Role string `json:"role"`
		}
		rows := make([]row, 0, len(users))
		for who, role := range users {
			rows = append(rows, row{User: maskEmail(who), Role: role})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Role != rows[j].Role {
				return rows[i].Role < rows[j].Role
			}
			return rows[i].User < rows[j].User
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
	}
}

func readRoles(file string) (map[string]string, error) {
	if file == "" {
		return nil, errors.New("roles file not configured")
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Version int               `json:"version"`
		Users   map[string]string `json:"users"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.Version != 1 {
		return nil, errors.New("invalid roles file")
	}
	return doc.Users, nil
}
