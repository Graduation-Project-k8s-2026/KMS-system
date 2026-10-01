package bench

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 서버가 실제로 주고받는 JSON 형식(internal/api/transit)과 일치하는 최소한의
// 와이어 타입. 그 패키지를 그대로 임포트하지 않는다 — 이 도구는 다른 모든
// 호출자와 마찬가지로 HTTP 경계 너머에서 KMS를 두드리는 외부 클라이언트이고,
// 그렇게 다뤄야 "실제로 그 경로를 거친" 측정이 된다.
type encryptReq struct {
	Plaintext string `json:"plaintext"`
}
type encryptResp struct {
	Ciphertext string `json:"ciphertext"`
}
type decryptReq struct {
	Ciphertext string `json:"ciphertext"`
}
type decryptResp struct {
	Plaintext string `json:"plaintext"`
}
type rewrapReq struct {
	Ciphertext string `json:"ciphertext"`
}
type rewrapResp struct {
	Ciphertext string `json:"ciphertext"`
}

// Client는 Transit API(encrypt/decrypt/rewrap)만 호출하는 얇은 HTTP
// 클라이언트다. Admin 평면(유닉스 소켓)에는 접근하지 않는다 — 벤치 도구는
// 서버 상태를 바꾸지 않고, 바꿀 수도 없다.
type Client struct {
	addr  string
	token string
	http  *http.Client
}

// NewClient는 addr(Transit API base URL, 예: "http://localhost:8200")와
// 선택적 token(비어 있으면 Authorization 헤더를 보내지 않음), httpClient로
// Client를 만든다.
func NewClient(addr, token string, httpClient *http.Client) *Client {
	return &Client{addr: strings.TrimRight(addr, "/"), token: token, http: httpClient}
}

// doTimed는 요청 전송 직전부터 응답 본문을 다 읽을 때까지만 시간을 잰다 —
// 요청 바디 직렬화나 응답 바디 역직렬화는 이 함수 밖(호출부)에서 일어나므로
// 측정 구간에 포함되지 않는다.
func (c *Client) doTimed(req *http.Request) (body []byte, status int, latency time.Duration, err error) {
	start := time.Now()
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, time.Since(start), err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	latency = time.Since(start)
	if readErr != nil {
		return nil, resp.StatusCode, latency, fmt.Errorf("reading response body: %w", readErr)
	}
	return body, resp.StatusCode, latency, nil
}

func (c *Client) newRequest(ctx context.Context, path string, payload any) (*http.Request, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encoding request body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.addr+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

// Encrypt는 POST /v1/encrypt/{key}를 호출한다. status는 preflight가 세부
// 사유(sealed/키 없음)를 판별하는 데 쓰고, err가 nil이면 status는 항상 200이다.
func (c *Client) Encrypt(ctx context.Context, key string, plaintext []byte) (ciphertext string, status int, latency time.Duration, err error) {
	req, err := c.newRequest(ctx, "/v1/encrypt/"+url.PathEscape(key), encryptReq{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return "", 0, 0, err
	}

	body, status, latency, err := c.doTimed(req)
	if err != nil {
		return "", status, latency, err
	}
	if status != http.StatusOK {
		return "", status, latency, fmt.Errorf("encrypt: unexpected status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var resp encryptResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", status, latency, fmt.Errorf("encrypt: decoding response: %w", err)
	}
	return resp.Ciphertext, status, latency, nil
}

// Decrypt는 POST /v1/decrypt/{key}를 호출한다.
func (c *Client) Decrypt(ctx context.Context, key, ciphertext string) (plaintext []byte, status int, latency time.Duration, err error) {
	req, err := c.newRequest(ctx, "/v1/decrypt/"+url.PathEscape(key), decryptReq{Ciphertext: ciphertext})
	if err != nil {
		return nil, 0, 0, err
	}

	body, status, latency, err := c.doTimed(req)
	if err != nil {
		return nil, status, latency, err
	}
	if status != http.StatusOK {
		return nil, status, latency, fmt.Errorf("decrypt: unexpected status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var resp decryptResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, status, latency, fmt.Errorf("decrypt: decoding response: %w", err)
	}
	plaintext, err = base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, status, latency, fmt.Errorf("decrypt: decoding base64 plaintext: %w", err)
	}
	return plaintext, status, latency, nil
}

// Rewrap은 POST /v1/rewrap/{key}를 호출한다.
func (c *Client) Rewrap(ctx context.Context, key, ciphertext string) (newCiphertext string, status int, latency time.Duration, err error) {
	req, err := c.newRequest(ctx, "/v1/rewrap/"+url.PathEscape(key), rewrapReq{Ciphertext: ciphertext})
	if err != nil {
		return "", 0, 0, err
	}

	body, status, latency, err := c.doTimed(req)
	if err != nil {
		return "", status, latency, err
	}
	if status != http.StatusOK {
		return "", status, latency, fmt.Errorf("rewrap: unexpected status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var resp rewrapResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", status, latency, fmt.Errorf("rewrap: decoding response: %w", err)
	}
	return resp.Ciphertext, status, latency, nil
}
