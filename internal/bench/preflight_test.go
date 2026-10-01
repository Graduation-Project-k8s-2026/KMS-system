package bench_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

func TestPreflight_OK(t *testing.T) {
	srv := newFakeServer("demo")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	if err := bench.Preflight(context.Background(), client, "demo"); err != nil {
		t.Fatalf("Preflight failed: %v", err)
	}
}

func TestPreflight_Sealed(t *testing.T) {
	srv := newFakeServer("demo")
	srv.setSealed(true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	err := bench.Preflight(context.Background(), client, "demo")
	if err == nil {
		t.Fatal("Preflight succeeded against a sealed server, want error")
	}
	if !strings.Contains(err.Error(), "sealed") {
		t.Errorf("error = %q, want it to mention sealed", err.Error())
	}
}

func TestPreflight_KeyNotFound(t *testing.T) {
	srv := newFakeServer("demo")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := bench.NewClient(ts.URL, "", ts.Client())
	err := bench.Preflight(context.Background(), client, "does-not-exist")
	if err == nil {
		t.Fatal("Preflight succeeded for a missing key, want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to mention \"not found\"", err.Error())
	}
}
