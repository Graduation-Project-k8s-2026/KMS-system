package bench

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleReport() Report {
	return Report{
		Label: "unit", Timestamp: time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC),
		Addr: "http://localhost:8200", Key: "demo", Environment: CollectEnvironment(),
		Runs: []RunReport{{Scenario: "concurrency", Operation: "encrypt", Concurrency: 2, OpsPerSec: 10, SuccessCount: 5}},
	}
}

func TestSubmit_PostsReportJSON(t *testing.T) {
	var gotPath, gotMethod, gotCT string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotCT = r.URL.Path, r.Method, r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"20261006T120000Z-unit","runs":1}`))
	}))
	defer srv.Close()

	id, err := Submit(context.Background(), srv.Client(), srv.URL, sampleReport())
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if id != "20261006T120000Z-unit" {
		t.Errorf("id = %q", id)
	}
	if gotMethod != "POST" || gotPath != "/api/bench/results" || gotCT != "application/json" {
		t.Errorf("request = %s %s (%s)", gotMethod, gotPath, gotCT)
	}
	var back Report
	if err := json.Unmarshal(gotBody, &back); err != nil || back.Label != "unit" || len(back.Runs) != 1 {
		t.Fatalf("body is not the report: %v %s", err, gotBody)
	}
}

func TestSubmit_ReportsServerRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"runs must contain at least one run"}`))
	}))
	defer srv.Close()

	_, err := Submit(context.Background(), srv.Client(), srv.URL, sampleReport())
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "runs must contain") {
		t.Fatalf("err = %v, want HTTP 400 with the server's reason", err)
	}
}

func TestSubmit_UnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := Submit(context.Background(), http.DefaultClient, url, sampleReport()); err == nil {
		t.Fatal("expected a connection error")
	}
}

func TestParseSubmitURL(t *testing.T) {
	got, err := ParseSubmitURL("http://admin:8201/")
	if err != nil || got != "http://admin:8201" {
		t.Fatalf("got %q, %v", got, err)
	}
	for _, bad := range []string{"", "admin:8201", "ftp://x", "http://", "/relative"} {
		if _, err := ParseSubmitURL(bad); err == nil {
			t.Errorf("ParseSubmitURL(%q) must fail", bad)
		}
	}
}
