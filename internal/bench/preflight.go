package bench

import (
	"context"
	"fmt"
	"net/http"
)

// Preflight는 측정을 시작하기 전에 대상 서버가 실제로 측정 가능한 상태인지
// 확인한다. 벤치 도구는 Transit API만 호출할 수 있어(Admin은 유닉스 소켓이라
// 접근 불가) seal-status를 직접 물어볼 수 없다 — 대신 1바이트짜리 encrypt를
// 한 번 호출해 그 상태 코드로 판별한다: encrypt는 서버에 아무 상태도 남기지
// 않는 순수 연산이라 이 용도로 안전하게 쓸 수 있다.
//
//   - 200: 정상, 측정을 진행해도 된다
//   - 503: barrier가 sealed (httputil.SealedGuard)
//   - 404: key가 없음 (keys.KeyNotFoundError) — 벤치 도구는 키를 만들지 않는다
//   - 그 외: 분류되지 않은 오류
func Preflight(ctx context.Context, client *Client, key string) error {
	_, status, _, err := client.Encrypt(ctx, key, []byte("x"))
	if err == nil {
		return nil
	}
	switch status {
	case http.StatusServiceUnavailable:
		return fmt.Errorf("preflight failed: server is sealed (encrypt returned 503) — unseal it via the admin API before benchmarking")
	case http.StatusNotFound:
		return fmt.Errorf("preflight failed: key %q not found (encrypt returned 404) — bench does not create keys; create it via the admin API first", key)
	default:
		return fmt.Errorf("preflight failed: %w", err)
	}
}
