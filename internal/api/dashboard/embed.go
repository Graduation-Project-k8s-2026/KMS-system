// Package dashboard: [결정 3](Seal 비교 실험) 결과를 보여주는 정적 HTML
// 대시보드를 서버 바이너리에 내장한다.
package dashboard

import _ "embed"

// HTML은 dashboard.html의 내용을 그대로 담은 바이트 슬라이스다. go:embed는
// 빌드 시점에 파일 내용을 바이너리 안에 통째로 넣어준다 — 그래서 배포할 때
// 이 HTML 파일을 서버 바이너리와 별도로 챙겨서 옮길 필요가 없다(별도 정적
// 파일 서버나 CDN 없이, 바이너리 하나만 배포하면 /dashboard가 항상 동작한다).
//
//go:embed dashboard.html
var HTML []byte
