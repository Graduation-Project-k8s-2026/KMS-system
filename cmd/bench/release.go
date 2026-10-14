package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/jobs"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/security"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	pb "k8s.io/kms/apis/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var newE2EClient = func() (kubernetes.Interface, error) {
	cfg, e := rest.InClusterConfig()
	if e != nil {
		return nil, e
	}
	cfg.Timeout = 10 * time.Second
	return kubernetes.NewForConfig(cfg)
}

func releaseRun(args []string, out, stderr io.Writer) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var spec jobs.Spec
	fs.StringVar(&spec.Mode, "mode", "transit", "transit|plugin|e2e")
	fs.StringVar(&spec.Scenario, "scenario", "basic", "fixed basic scenario")
	fs.StringVar(&spec.Operation, "op", "roundtrip", "roundtrip encrypt/decrypt or Secret create/read/delete")
	fs.IntVar(&spec.Count, "count", 100, "maximum roundtrips")
	fs.IntVar(&spec.Concurrency, "concurrency", 1, "workers (1..32)")
	fs.IntVar(&spec.Payload, "payload-bytes", 1024, "payload bytes")
	fs.IntVar(&spec.Duration, "duration-seconds", 0, "stop after this duration, capped by count")
	addr := fs.String("addr", "", "Transit HTTPS URL")
	ca := fs.String("ca-file", "", "Transit CA")
	token := fs.String("token-file", "", "Transit projected token")
	socket := fs.String("kms-socket", "", "plugin UDS")
	ns := fs.String("namespace", "kms-bench-e2e", "E2E namespace")
	runID := fs.String("run-id", "", "server-issued run ID")
	submit := fs.String("submit", "", "ingest HTTPS origin")
	submitCA := fs.String("submit-ca-file", "", "ingest CA")
	submitToken := fs.String("submit-token-file", "", "separate projected submission token")
	required := fs.Bool("submit-required", false, "exit nonzero if upload fails")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if e := spec.Validate(); e != nil {
		return e
	}
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(*runID) {
		return errors.New("valid run ID required")
	}
	if *required && (*submit == "" || *submitCA == "" || *submitToken == "") {
		return errors.New("required submission configuration missing")
	}
	if *submitToken != "" && *submitToken == *token {
		return errors.New("separate token files required")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 850*time.Second)
	defer cancel()
	payload := make([]byte, spec.Payload)
	if _, e := rand.Read(payload); e != nil {
		return e
	}
	defer clear(payload)
	var call func(context.Context, int) error
	switch spec.Mode {
	case "transit":
		if !strings.HasPrefix(*addr, "https://") {
			return errors.New("Transit HTTPS required")
		}
		client, e := security.TLSClient(*ca)
		if e != nil {
			return e
		}
		client.Transport = security.FileToken{Base: client.Transport, Path: *token}
		transit := bench.NewClient(*addr, "", client)
		call = func(ctx context.Context, i int) error {
			c, _, _, e := transit.Encrypt(ctx, "demo", payload)
			if e != nil {
				return e
			}
			p, _, _, e := transit.Decrypt(ctx, "demo", c)
			if e == nil && !bytes.Equal(p, payload) {
				return errors.New("roundtrip mismatch")
			}
			clear(p)
			return e
		}
	case "plugin":
		if *socket == "" {
			return errors.New("plugin socket required")
		}
		conn, e := grpc.NewClient("passthrough:///kms", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
		}))
		if e != nil {
			return e
		}
		defer conn.Close()
		client := pb.NewKeyManagementServiceClient(conn)
		call = func(ctx context.Context, i int) error {
			uid := fmt.Sprint(*runID, "-", i)
			c, e := client.Encrypt(ctx, &pb.EncryptRequest{Uid: uid, Plaintext: payload})
			if e != nil {
				return e
			}
			p, e := client.Decrypt(ctx, &pb.DecryptRequest{Uid: uid + "-read", Ciphertext: c.Ciphertext, KeyId: c.KeyId, Annotations: c.Annotations})
			if e == nil && !bytes.Equal(p.Plaintext, payload) {
				return errors.New("roundtrip mismatch")
			}
			return e
		}
	case "e2e":
		if *ns != "kms-bench-e2e" {
			return errors.New("E2E restricted to dedicated namespace")
		}
		client, e := newE2EClient()
		if e != nil {
			return e
		}
		call = func(ctx context.Context, i int) error {
			name := fmt.Sprint("bench-", *runID, "-", i)
			api := client.CoreV1().Secrets(*ns)
			created, e := api.Create(ctx, &core.Secret{ObjectMeta: meta.ObjectMeta{Name: name, Labels: map[string]string{"kms-run-id": *runID}}, Data: map[string][]byte{"sample": payload}}, meta.CreateOptions{})
			if e != nil {
				return e
			}
			got, readErr := api.Get(ctx, name, meta.GetOptions{})
			cleanup, c := context.WithTimeout(context.Background(), 5*time.Second)
			defer c()
			delErr := api.Delete(cleanup, name, meta.DeleteOptions{Preconditions: &meta.Preconditions{UID: &created.UID}})
			if readErr != nil {
				return readErr
			}
			if delErr != nil {
				return delErr
			}
			if !bytes.Equal(got.Data["sample"], payload) {
				return errors.New("Secret roundtrip mismatch")
			}
			return nil
		}
	}
	result := jobs.Result{Schema: 1, RunID: *runID, Mode: spec.Mode, SourceSHA: os.Getenv("KMS_SOURCE_SHA"), Image: os.Getenv("KMS_IMAGE_DIGEST"), ClientVersion: runtime.Version(), ServerVersion: os.Getenv("KMS_SERVER_VERSION"), TLS: spec.Mode != "plugin", Auth: map[string]string{"transit": "jwt-sar", "plugin": "uds", "e2e": "kubernetes"}[spec.Mode], Started: time.Now().UTC()}
	var next atomic.Int64
	var mu sync.Mutex
	var samples []float64
	var wg sync.WaitGroup
	for w := 0; w < spec.Concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				idx := int(next.Add(1))
				if idx > spec.Count || ctx.Err() != nil || (spec.Duration > 0 && time.Since(result.Started) >= time.Duration(spec.Duration)*time.Second) {
					return
				}
				request, cancel := context.WithTimeout(ctx, 30*time.Second)
				start := time.Now()
				e := call(request, idx)
				cancel()
				elapsed := time.Since(start).Seconds()
				mu.Lock()
				result.Requests++
				if e != nil {
					result.Errors++
				} else {
					result.Success++
				}
				samples = append(samples, elapsed)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	result.Ended = time.Now().UTC()
	sort.Float64s(samples)
	if len(samples) > 0 {
		result.P50 = samples[(len(samples)-1)*50/100]
		result.P95 = samples[(len(samples)-1)*95/100]
		result.P99 = samples[(len(samples)-1)*99/100]
	}
	if e := json.NewEncoder(out).Encode(result); e != nil {
		return e
	}
	if *submit != "" {
		if !strings.HasPrefix(*submit, "https://") {
			return errors.New("submission HTTPS required")
		}
		client, e := security.TLSClient(*submitCA)
		if e != nil {
			return e
		}
		client.Transport = security.FileToken{Base: client.Transport, Path: *submitToken}
		b, e := json.Marshal(result)
		if e != nil {
			return e
		}
		req, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(*submit, "/")+"/api/bench/results", bytes.NewReader(b))
		if e != nil {
			return e
		}
		req.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(req)
		if e != nil {
			return errors.New("result upload failed")
		}
		resp.Body.Close()
		if resp.StatusCode != 201 {
			return fmt.Errorf("result upload failed: HTTP %d", resp.StatusCode)
		}
	}
	if ctx.Err() != nil {
		return errors.New("benchmark interrupted")
	}
	if result.Errors > 0 || result.Requests == 0 {
		return errors.New("benchmark contains failed requests")
	}
	return nil
}
