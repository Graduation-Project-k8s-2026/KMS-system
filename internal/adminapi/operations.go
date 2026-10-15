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
			now := time.Now()
			endpoint = prom + "/api/v1/query_range?query=" + url.QueryEscape(query) + "&start=" + url.QueryEscape(now.Add(-15*time.Minute).UTC().Format(time.RFC3339)) + "&end=" + url.QueryEscape(now.UTC().Format(time.RFC3339)) + "&step=15"
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
