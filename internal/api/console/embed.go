// Package console: KMS 서버를 운영/관리하는 사람이 쓰는 콘솔 정적 HTML을
// 서버 바이너리에 내장한다. internal/api/dashboard([결정 3] 비교 결과 페이지)
// 와는 목적이 다르다 — 이건 실제로 서버를 열고(init/unseal) 키를 만들고
// 관리하는 화면이다.
package console

import _ "embed"

// HTML은 console.html의 내용을 그대로 담은 바이트 슬라이스다. go:embed로
// 빌드 시점에 바이너리 안에 통째로 넣어, 배포 시 이 HTML 파일을 서버
// 바이너리와 별도로 챙길 필요가 없게 한다.
//
//go:embed console.html
var HTML []byte
