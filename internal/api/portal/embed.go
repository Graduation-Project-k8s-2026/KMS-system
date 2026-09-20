// Package portal: 이미 존재하는 키로 암복호화만 수행하는 고객용 포털
// 정적 HTML을 서버 바이너리에 내장한다. 키 생성/회전, init/unseal 같은
// 서버 운영 기능은 여기 전혀 없다 — 그건 internal/api/console의 몫이다.
package portal

import _ "embed"

// HTML은 portal.html의 내용을 그대로 담은 바이트 슬라이스다.
//
//go:embed portal.html
var HTML []byte
