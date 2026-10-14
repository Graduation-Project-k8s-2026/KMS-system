package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	pb "k8s.io/kms/apis/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Runs the real main in a child with only temporary host files and an unreachable API.
// It does not initialize or unseal an operational KMS.
func TestServerBootWithoutKubernetesAPI(t *testing.T) {
	if os.Getenv("KMS_TEST_OFFLINE_CHILD") == "1" {
		main()
		return
	}
	dir, e := os.MkdirTemp("", "kms-offline-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	pair := fixture.TLS.Certificates[0]
	cert := fixture.Certificate()
	fixture.Close()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	certFile := write("tls.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))
	priv, e := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if e != nil {
		t.Fatal(e)
	}
	keyFile := write("tls.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}))
	pub, e := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	publicFile := write("sa.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
	kubeconfig := write("sar.conf", []byte(fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- name: offline\n  cluster:\n    server: https://127.0.0.1:1\n    certificate-authority: %s\nusers:\n- name: sar\n  user:\n    client-certificate: %s\n    client-key: %s\ncontexts:\n- name: offline\n  context:\n    cluster: offline\n    user: sar\ncurrent-context: offline\n", certFile, certFile, keyFile)))
	socket := filepath.Join(dir, "admin.sock")
	v2 := filepath.Join(dir, "v2.sock")
	data := filepath.Join(dir, "data")
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerBootWithoutKubernetesAPI$")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "KMS_TEST_OFFLINE_CHILD=1", "KMS_TRANSIT_TLS_CERT=" + certFile, "KMS_TRANSIT_TLS_KEY=" + keyFile, "KMS_SA_PUBLIC_KEY=" + publicFile, "KMS_SA_ISSUER=https://offline.example", "KMS_SA_AUDIENCE=kms-system", "KMS_KUBECONFIG=" + kubeconfig, "KMS_AUDIT_DIR=" + filepath.Join(dir, "audit"), "KMS_DATA_DIR=" + data, "KMS_ADMIN_SOCKET=" + socket, "KMS_V2_SOCKET=" + v2, "KMS_TRANSIT_ADDR=127.0.0.1:0", "KMS_METRICS_ADDR="}
	// Missing required host configuration must fail before opening either UDS.
	for _, missing := range []string{"KMS_TRANSIT_TLS_CERT", "KMS_TRANSIT_TLS_KEY", "KMS_SA_ISSUER", "KMS_SA_AUDIENCE", "KMS_KUBECONFIG", "KMS_AUDIT_DIR", "KMS_SA_PUBLIC_KEY"} {
		t.Run("missing_"+missing, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			invalid := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServerBootWithoutKubernetesAPI$")
			for _, entry := range cmd.Env {
				if !strings.HasPrefix(entry, missing+"=") {
					invalid.Env = append(invalid.Env, entry)
				}
			}
			// An absent public-key setting otherwise uses the production default path.
			if missing == "KMS_SA_PUBLIC_KEY" {
				invalid.Env = append(invalid.Env, missing+"="+filepath.Join(dir, "missing.pub"))
			}
			err := invalid.Run()
			if err == nil || ctx.Err() != nil {
				t.Fatal("invalid config did not fail immediately")
			}
			for _, path := range []string{socket, v2} {
				if _, err = os.Stat(path); !os.IsNotExist(err) {
					t.Fatal("invalid config opened listener")
				}
			}
		})
	}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer cmd.Process.Kill()
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
	deadline := time.Now().Add(8 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		res, e := client.Get("http://localhost/v1/sys/seal-status")
		if e == nil {
			var state struct{ Initialized, Sealed bool }
			json.NewDecoder(res.Body).Decode(&state)
			res.Body.Close()
			if res.StatusCode == 200 && !state.Initialized && state.Sealed {
				ready = true
				break
			}
		}
		select {
		case <-done:
			t.Fatal("offline server exited before opening UDS")
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("offline server did not boot")
	}
	conn, e := grpc.NewClient("passthrough:///kms", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", v2)
	}))
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, e = pb.NewKeyManagementServiceClient(conn).Status(ctx, &pb.StatusRequest{})
	if status.Code(e) != codes.FailedPrecondition {
		t.Fatal("sealed v2 listener not reachable")
	}
	if _, e = os.Stat(filepath.Join(data, "initialization.json")); !os.IsNotExist(e) {
		t.Fatal("boot unexpectedly initialized data")
	}
	cmd.Process.Signal(syscall.SIGTERM)
	select {
	case e = <-done:
		if e != nil {
			t.Fatal("offline shutdown failed")
		}
	case <-time.After(12 * time.Second):
		t.Fatal("offline shutdown timed out")
	}
	if _, e = os.Stat(socket); !os.IsNotExist(e) {
		t.Fatal("admin socket left after shutdown")
	}
}
