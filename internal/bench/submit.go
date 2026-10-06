package bench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// SubmitPath는 관리 API에서 bench 결과를 받는 경로다.
const SubmitPath = "/api/bench/results"

// ParseSubmitURL은 --submit 값(관리 API 주소)을 검증하고 끝의 "/"를 정리한다.
func ParseSubmitURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("must be an http(s) URL such as http://localhost:8201, got %q", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// Submit은 report를 관리 API(baseURL)의 POST /api/bench/results로 제출하고
// 서버가 붙인 결과 id를 반환한다. 201이 아니면 서버가 알려준 사유를 담은
// 오류를 반환한다.
func Submit(ctx context.Context, client *http.Client, baseURL string, report Report) (string, error) {
	body, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("encode report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+SubmitPath, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode != http.StatusCreated {
		var e struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(respBody))
		if json.Unmarshal(respBody, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return "", fmt.Errorf("server returned HTTP %d: %s", resp.StatusCode, msg)
	}
	var ok struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(respBody, &ok); err != nil || ok.ID == "" {
		return "", fmt.Errorf("unexpected response from server: %q", respBody)
	}
	return ok.ID, nil
}
