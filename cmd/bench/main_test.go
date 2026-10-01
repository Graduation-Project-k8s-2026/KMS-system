package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// --- parseFlags: 네트워크 없이도 전부 검증할 수 있는 순수 플래그 파싱 ---

func TestParseFlags_Defaults(t *testing.T) {
	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"--key", "demo"}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags failed: %v", err)
	}
	if cfg.Addr != "http://localhost:8200" {
		t.Errorf("Addr = %q, want default", cfg.Addr)
	}
	if cfg.Scenario != "basic" {
		t.Errorf("Scenario = %q, want basic", cfg.Scenario)
	}
	if len(cfg.Ops) != 3 {
		t.Errorf("Ops = %v, want all three (default --op=all)", cfg.Ops)
	}
	if cfg.Count != 1000 {
		t.Errorf("Count = %d, want 1000", cfg.Count)
	}
	if cfg.BaselinePayload != 1024 {
		t.Errorf("BaselinePayload = %d, want 1024", cfg.BaselinePayload)
	}
	if len(cfg.ConcurrencyLevels) != 4 {
		t.Errorf("ConcurrencyLevels = %v, want 4 entries", cfg.ConcurrencyLevels)
	}
	if !cfg.Keepalive {
		t.Error("Keepalive = false, want true (default)")
	}
}

func TestParseFlags_MissingKey(t *testing.T) {
	var stderr bytes.Buffer
	if _, err := parseFlags([]string{}, &stderr); err == nil {
		t.Fatal("parseFlags without --key succeeded, want error")
	}
}

func TestParseFlags_UnknownScenario(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key", "demo", "--scenario", "bogus"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with unknown --scenario succeeded, want error")
	}
}

func TestParseFlags_UnknownOp(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key", "demo", "--op", "bogus"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with unknown --op succeeded, want error")
	}
}

func TestParseFlags_UnknownFormat(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key", "demo", "--format", "xml"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with unknown --format succeeded, want error")
	}
}

func TestParseFlags_DecryptRequiresWarmup(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key", "demo", "--op", "decrypt", "--warmup", "0"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with --op decrypt --warmup 0 succeeded, want error")
	}
}

func TestParseFlags_TokenAndTokenFileMutuallyExclusive(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key", "demo", "--token", "abc", "--token-file", "/tmp/x"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with both --token and --token-file succeeded, want error")
	}
}

func TestParseFlags_TokenFile(t *testing.T) {
	path := t.TempDir() + "/token"
	if err := os.WriteFile(path, []byte("  secret-token\n"), 0o600); err != nil {
		t.Fatalf("writing token file failed: %v", err)
	}

	var stderr bytes.Buffer
	cfg, err := parseFlags([]string{"--key", "demo", "--token-file", path}, &stderr)
	if err != nil {
		t.Fatalf("parseFlags failed: %v", err)
	}
	if cfg.Token != "secret-token" {
		t.Errorf("Token = %q, want %q (trimmed)", cfg.Token, "secret-token")
	}
}

func TestParseFlags_InvalidPayloadSize(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key", "demo", "--payload", "bogus"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with invalid --payload succeeded, want error")
	}
}

func TestParseFlags_NoCountNoDuration(t *testing.T) {
	var stderr bytes.Buffer
	_, err := parseFlags([]string{"--key", "demo", "--count", "0"}, &stderr)
	if err == nil {
		t.Fatal("parseFlags with --count 0 and no --duration succeeded, want error")
	}
}

// --- run(): 가짜 Transit 서버로 전체 흐름(preflight -> 측정 -> 출력) 검증 ---

func TestRun_TableOutput_EndToEnd(t *testing.T) {
	srv := newFakeTransitServer(t, "demo")
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--addr", srv.URL, "--key", "demo", "--scenario", "basic", "--op", "encrypt",
		"--count", "10", "--warmup", "2", "--concurrency", "2",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run failed: %v (stderr: %s)", err, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "OPERATION") || !strings.Contains(out, "encrypt") {
		t.Fatalf("table output missing expected content:\n%s", out)
	}
}

func TestRun_JSONOutput_EndToEnd(t *testing.T) {
	srv := newFakeTransitServer(t, "demo")
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--addr", srv.URL, "--key", "demo", "--scenario", "basic", "--op", "encrypt",
		"--count", "10", "--warmup", "2", "--format", "json", "--label", "ci-test",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run failed: %v (stderr: %s)", err, stderr.String())
	}

	var report struct {
		Label string `json:"label"`
		Runs  []struct {
			Operation    string `json:"operation"`
			SuccessCount int    `json:"success_count"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout.String())
	}
	if report.Label != "ci-test" {
		t.Errorf("Label = %q, want %q", report.Label, "ci-test")
	}
	if len(report.Runs) != 1 || report.Runs[0].SuccessCount != 10 {
		t.Errorf("Runs = %+v, want one run with success_count=10", report.Runs)
	}
}

func TestRun_PreflightSealed_ReturnsError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/encrypt/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"sealed"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	err := run([]string{"--addr", srv.URL, "--key", "demo", "--count", "5"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run against a sealed server succeeded, want error")
	}
	if !strings.Contains(err.Error(), "sealed") {
		t.Errorf("error = %q, want it to mention sealed", err.Error())
	}
}

func TestRun_OutputFile(t *testing.T) {
	srv := newFakeTransitServer(t, "demo")
	defer srv.Close()

	path := t.TempDir() + "/report.json"
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--addr", srv.URL, "--key", "demo", "--op", "encrypt",
		"--count", "5", "--warmup", "1", "--format", "json", "--output", path,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout should be empty when --output is set, got: %s", stdout.String())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading output file failed: %v", err)
	}
	if !strings.Contains(string(data), `"operation": "encrypt"`) {
		t.Errorf("output file missing expected content:\n%s", data)
	}
}

// newFakeTransitServer는 encrypt/decrypt/rewrap을 최소한으로 흉내 내는
// httptest 서버를 만든다 — internal/bench 패키지의 가짜 서버와 별개로,
// cmd/bench의 run()이 플래그 파싱부터 출력까지 실제로 엮이는지 확인하는
// 용도다.
func newFakeTransitServer(t *testing.T, keyName string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/encrypt/"+keyName, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Plaintext string `json:"plaintext"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		writeJSONResp(w, map[string]string{"ciphertext": "ct:" + req.Plaintext})
	})
	mux.HandleFunc("/v1/decrypt/"+keyName, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		writeJSONResp(w, map[string]string{"plaintext": strings.TrimPrefix(req.Ciphertext, "ct:")})
	})
	mux.HandleFunc("/v1/rewrap/"+keyName, func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Ciphertext string `json:"ciphertext"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		writeJSONResp(w, map[string]string{"ciphertext": "ct2:" + strings.TrimPrefix(req.Ciphertext, "ct:")})
	})
	return httptest.NewServer(mux)
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
