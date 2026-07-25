// Package home: /dashboard, /console, /portal 세 화면을 소개하고 이동시키는
// 진입점(랜딩) 페이지를 서버 바이너리에 내장한다.
package home

import _ "embed"

// HTML은 home.html의 내용을 그대로 담은 바이트 슬라이스다.
//
//go:embed home.html
var HTML []byte
