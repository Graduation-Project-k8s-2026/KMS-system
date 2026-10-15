package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/jobs"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/kmsv2"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"google.golang.org/grpc"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	kt "k8s.io/client-go/testing"
	pb "k8s.io/kms/apis/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseBenchThreeModesAndFailures(t *testing.T) {
	t.Setenv("KMS_SOURCE_SHA", strings.Repeat("b", 40))
	t.Setenv("KMS_IMAGE_DIGEST", "example/bench@sha256:"+strings.Repeat("a", 64))
	t.Setenv("KMS_SERVER_VERSION", "v1.35.9")
	baseArgs := []string{"--run-id=" + strings.Repeat("a", 32), "--count=3", "--payload-bytes=16", "--concurrency=2"}
	execute := func(args []string, wantError bool) {
		t.Helper()
		var out, errout bytes.Buffer
		e := releaseRun(append(append([]string{}, baseArgs...), args...), &out, &errout)
		if (e != nil) != wantError {
			t.Fatalf("bench error expected=%v got=%v", wantError, e)
		}
		if !wantError {
			var result jobs.Result
			if json.Unmarshal(out.Bytes(), &result) != nil || result.Validate() != nil || result.Success != 3 {
				t.Fatal("invalid successful report")
			}
		}
	}
	// Real TLS roundtrips plus separate submission token and required upload failure.
	fakeTransit := newFakeTransitServer(t, "demo")
	defer fakeTransit.Close()
	transit := httptest.NewTLSServer(fakeTransit.Config.Handler)
	defer transit.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: transit.Certificate().Raw}), 0600)
	token := filepath.Join(dir, "transit")
	submitToken := filepath.Join(dir, "submit")
	os.WriteFile(token, []byte("transit-fixture"), 0600)
	os.WriteFile(submitToken, []byte("submit-fixture"), 0600)
	args := []string{"--mode=transit", "--addr=" + transit.URL, "--ca-file=" + ca, "--token-file=" + token}
	execute(args, false)
	upload := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer submit-fixture" {
			t.Error("submission reused Transit credential")
		}
		w.WriteHeader(503)
	}))
	defer upload.Close()
	execute(append(args, "--submit="+upload.URL, "--submit-ca-file="+ca, "--submit-token-file="+submitToken, "--submit-required"), true)
	// Official gRPC client crosses an actual UDS to the implementation.
	b := barrier.NewBarrier(storage.NewMemoryStorage(), seal.NewDevSeal("fixture"))
	b.Unseal()
	km := keys.NewKeyManager(b)
	km.CreateKey("k8s-secrets", 0)
	socket := filepath.Join(dir, "v2.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	server := grpc.NewServer()
	pb.RegisterKeyManagementServiceServer(server, kmsv2.New(km, "k8s-secrets"))
	go server.Serve(listener)
	defer server.Stop()
	execute([]string{"--mode=plugin", "--kms-socket=" + socket}, false)
	b.Seal()
	execute([]string{"--mode=plugin", "--kms-socket=" + socket}, true)
	// E2E API actions are local fake API operations, not evidence of etcd encryption.
	old := newE2EClient
	defer func() { newE2EClient = old }()
	client := fake.NewSimpleClientset()
	newE2EClient = func() (kubernetes.Interface, error) { return client, nil }
	execute([]string{"--mode=e2e", "--namespace=kms-bench-e2e"}, false)
	remaining, _ := client.CoreV1().Secrets("kms-bench-e2e").List(context.Background(), meta.ListOptions{})
	if len(remaining.Items) != 0 {
		t.Fatal("Secret cleanup failed")
	}
	client.PrependReactor("create", "secrets", func(kt.Action) (bool, runtime.Object, error) { return true, nil, errors.New("forbidden") })
	execute([]string{"--mode=e2e", "--namespace=kms-bench-e2e"}, true)
	for _, args := range [][]string{{"--mode=e2e", "--namespace=default"}, {"--mode=transit", "--addr=http://unsafe"}, {"--mode=plugin", "--count=100001"}, {"--mode=plugin", "--submit-required"}} {
		execute(args, true)
	}
}

func TestReleaseCLIRejectsInvalidContractBeforeRequests(t *testing.T) {
	for _, args := range [][]string{
		{"--run-id=" + strings.Repeat("z", 32)},
		{"--run-id=" + strings.Repeat("a", 32), "unexpected"},
		{"--run-id=" + strings.Repeat("a", 32), "--submit-required"},
		{"--run-id=" + strings.Repeat("a", 32), "--token-file=/same", "--submit-token-file=/same"},
	} {
		if err := releaseRun(args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatal("invalid CLI contract accepted")
		}
	}
	var help bytes.Buffer
	if err := run([]string{"--mode=transit", "--help"}, &bytes.Buffer{}, &help); err != nil {
		t.Fatal("help failed")
	}
	for _, flag := range []string{"-mode", "-ca-file", "-submit-ca-file", "-submit-token-file", "-run-id", "-submit-required", "-kms-socket", "-namespace"} {
		if !strings.Contains(help.String(), flag) {
			t.Fatalf("missing CLI flag %s", flag)
		}
	}
}
