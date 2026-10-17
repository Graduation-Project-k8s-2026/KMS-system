package adminapi

import (
	"context"
	"embed"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"net/url"
	"time"
)

//go:embed operations.html
var operationUI embed.FS

type metricWindow struct {
	d    time.Duration
	step string
}

// metricWindows: 허용하는 시간 범위. 빈 값은 기존 동작(15분)과 같다.
var metricWindows = map[string]metricWindow{
	"": {15 * time.Minute, "15"}, "15m": {15 * time.Minute, "15"}, "1h": {time.Hour, "60"}, "6h": {6 * time.Hour, "300"}, "24h": {24 * time.Hour, "900"},
}

// Queries are fixed by the server. Browser inputs cannot turn this into a proxy.
func mountOperations(r chi.Router, prom string) {
	r.Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		b, _ := operationUI.ReadFile("operations.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	r.Get("/api/dashboard/metrics", func(w http.ResponseWriter, r *http.Request) {
		queries := map[string]string{"targets": "up", "sealed": "kms_seal_sealed", "requests": "sum by (code) (rate(kms_http_requests_total[5m]))", "last_unseal": "kms_seal_last_unsealed_timestamp_seconds"}
		query, ok := queries[r.URL.Query().Get("metric")]
		if !ok {
			http.Error(w, "unknown metric", 400)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		endpoint := prom + "/api/v1/query?query=" + url.QueryEscape(query)
		if r.URL.Query().Get("range") == "1" {
			// 시간 범위: window=15m|1h|6h|24h (기본 15m). 목록에 없는 값은 거부한다 — 브라우저 입력이 Prometheus 질의 범위를
			// 마음대로 키우지 못하게(상한 24시간) 하고, 범위에 맞춰 step을 키워 점 개수를 일정하게(약 96개) 유지한다.
			win, ok := metricWindows[r.URL.Query().Get("window")]
			if !ok {
				http.Error(w, "unknown window", 400)
				return
			}
			now := time.Now()
			endpoint = prom + "/api/v1/query_range?query=" + url.QueryEscape(query) + "&start=" + url.QueryEscape(now.Add(-win.d).UTC().Format(time.RFC3339)) + "&end=" + url.QueryEscape(now.UTC().Format(time.RFC3339)) + "&step=" + win.step
		}
		req, e := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if e != nil {
			http.Error(w, "N/A", 503)
			return
		}
		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		res, e := client.Do(req)
		if e != nil {
			http.Error(w, "N/A", 503)
			return
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			http.Error(w, "N/A", 503)
			return
		}
		var body struct {
			Status string          `json:"status"`
			Data   json.RawMessage `json:"data"`
		}
		if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&body) != nil || body.Status != "success" {
			http.Error(w, "N/A", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(body)
	})
}
