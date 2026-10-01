package bench

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
)

// ParseSize는 "1KB", "100KB", "1MB", "512B", "2048"(단위 없으면 바이트)
// 같은 사람이 읽기 쉬운 크기 표현을 바이트 수로 바꾼다. 1KB=1024바이트
// 기준(이진 단위)을 쓴다 — 메모리/버퍼 크기를 다룰 때의 관례를 따른다.
func ParseSize(s string) (int, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, fmt.Errorf("empty size")
	}
	upper := strings.ToUpper(trimmed)

	multiplier := 1
	numPart := upper
	switch {
	case strings.HasSuffix(upper, "GB"):
		multiplier = 1024 * 1024 * 1024
		numPart = strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "MB"):
		multiplier = 1024 * 1024
		numPart = strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "KB"):
		multiplier = 1024
		numPart = strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "B"):
		multiplier = 1
		numPart = strings.TrimSuffix(upper, "B")
	}

	numPart = strings.TrimSpace(numPart)
	n, err := strconv.Atoi(numPart)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid size %q: must not be negative", s)
	}
	return n * multiplier, nil
}

// ParseSizeList는 쉼표로 구분된 크기 목록("1KB,10KB,100KB,1MB")을 파싱한다.
func ParseSizeList(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	sizes := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := ParseSize(p)
		if err != nil {
			return nil, err
		}
		sizes = append(sizes, n)
	}
	if len(sizes) == 0 {
		return nil, fmt.Errorf("empty size list")
	}
	return sizes, nil
}

// ParseIntList는 쉼표로 구분된 정수 목록("1,10,50,100")을 파싱한다 —
// 동시성 수준 집합에 쓴다.
func ParseIntList(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	values := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid integer %q: %w", p, err)
		}
		if n < 1 {
			return nil, fmt.Errorf("invalid value %q: must be >= 1", p)
		}
		values = append(values, n)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("empty integer list")
	}
	return values, nil
}

// FormatSize는 ParseSize의 역변환이다 — 결과 표/JSON에 사람이 읽기 좋은
// 형태로 되돌리는 용도.
func FormatSize(n int) string {
	switch {
	case n != 0 && n%(1024*1024*1024) == 0:
		return fmt.Sprintf("%dGB", n/(1024*1024*1024))
	case n != 0 && n%(1024*1024) == 0:
		return fmt.Sprintf("%dMB", n/(1024*1024))
	case n != 0 && n%1024 == 0:
		return fmt.Sprintf("%dKB", n/1024)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// RandomPlaintext는 n바이트의 임의 데이터를 만든다. AES-GCM의 연산 비용은
// 내용과 무관하므로, 실행(run) 하나당 한 번만 만들어 모든 요청에 재사용한다
// — 요청마다 새로 생성하면 (특히 큰 페이로드에서) 난수 생성 자체가 클라이언트
// 쪽 CPU를 잡아먹어 달성 가능한 처리량을 왜곡할 수 있다.
func RandomPlaintext(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("generating random plaintext: %w", err)
	}
	return buf, nil
}
