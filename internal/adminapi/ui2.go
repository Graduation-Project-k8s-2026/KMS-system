package adminapi

import (
	"embed"
	"io/fs"
	"net/http"
)

// 새 관리 화면(v2)의 정적 파일. 기존 화면(/console 등)과 별개로 /v2/ 아래에서만 서빙한다.
// go:embed는 바이너리 안에 파일을 넣는 Go 기능이라, 배포 때 HTML/CSS/JS를 따로 복사할 필요가 없다.
//
//go:embed ui2
var ui2FS embed.FS

// UI 기본 화면 선택값(ADMIN_API_UI_DEFAULT).
const (
	UIDefaultV1 = "v1"
	UIDefaultV2 = "v2"
)

// mountUI2는 /v2/ 정적 화면을 등록한다. 인증/CSRF는 라우터 바깥의 Security.Wrap이
// 모든 경로에 똑같이 적용하므로 여기서 따로 처리하지 않는다.
func mountUI2(r interface {
	Get(pattern string, h http.HandlerFunc)
	Handle(pattern string, h http.Handler)
}) {
	sub, err := fs.Sub(ui2FS, "ui2")
	if err != nil {
		panic(err) // 빌드 시 embed된 경로라 런타임에 실패할 수 없다
	}
	r.Get("/v2", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/v2/", http.StatusFound)
	})
	r.Handle("/v2/*", http.StripPrefix("/v2/", http.FileServerFS(sub)))
}
