// kms-verify is a host-only official-protocol probe. Fixtures contain public test bytes only.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	pb "k8s.io/kms/apis/v2"
)

var plain = []byte("kms-rev2-public-rpc-proof")

type fixture struct {
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
}

func run() error {
	etcd := flag.Bool("etcd-stdin", false, "read etcd JSON on stdin; output only verified envelope key ID counts")
	socket := flag.String("socket", "/run/custom-kms/kmsv2/kms-v2.sock", "KMS v2 Unix socket")
	save := flag.String("save", "", "create public ciphertext fixture (never overwrite)")
	read := flag.String("read", "", "verify previous fixture after restart/rotation/restore")
	changed := flag.Bool("require-key-change", false, "require current key ID to differ from saved fixture")
	flag.Parse()
	if *etcd {
		return inspectEtcd(os.Stdin, os.Stdout)
	}
	if flag.NArg() != 0 || (*changed && *read == "") {
		return errors.New("invalid arguments")
	}
	conn, e := grpc.NewClient("passthrough:///kms", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", *socket)
	}))
	if e != nil {
		return e
	}
	defer conn.Close()
	c := pb.NewKeyManagementServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, e := c.Status(ctx, &pb.StatusRequest{})
	if e != nil {
		return e
	}
	if st.Version != "v2" || st.Healthz != "ok" || st.KeyId == "" {
		return errors.New("unhealthy Status")
	}
	enc, e := c.Encrypt(ctx, &pb.EncryptRequest{Uid: "public-probe", Plaintext: plain})
	if e != nil {
		return e
	}
	if enc.KeyId != st.KeyId {
		return errors.New("key changed during probe; retry in stable state")
	}
	check := func(f fixture) error {
		r, e := c.Decrypt(ctx, &pb.DecryptRequest{Uid: "public-read", KeyId: f.KeyID, Ciphertext: f.Ciphertext})
		if e != nil {
			return e
		}
		if !bytes.Equal(r.Plaintext, plain) {
			return errors.New("roundtrip mismatch")
		}
		return nil
	}
	if e = check(fixture{enc.KeyId, enc.Ciphertext}); e != nil {
		return e
	}
	if *read != "" {
		b, e := os.ReadFile(*read)
		if e != nil {
			return e
		}
		var f fixture
		if e = json.Unmarshal(b, &f); e != nil {
			return e
		}
		if e = check(f); e != nil {
			return e
		}
		if *changed && f.KeyID == st.KeyId {
			return errors.New("key ID did not change")
		}
	}
	for _, r := range []*pb.DecryptRequest{
		{Uid: "negative", KeyId: "../../invalid", Ciphertext: enc.Ciphertext},
		{Uid: "negative", KeyId: enc.KeyId, Ciphertext: []byte("tampered")},
		{Uid: "negative", KeyId: enc.KeyId, Ciphertext: enc.Ciphertext, Annotations: map[string][]byte{"invalid.example": []byte("x")}},
	} {
		if _, e = c.Decrypt(ctx, r); status.Code(e) != codes.InvalidArgument {
			return errors.New("invalid Decrypt accepted")
		}
	}
	for _, r := range []*pb.EncryptRequest{{Plaintext: plain}, {Uid: "empty"}, {Uid: "oversize", Plaintext: make([]byte, (1<<20)+1)}} {
		if _, e = c.Encrypt(ctx, r); status.Code(e) != codes.InvalidArgument {
			return errors.New("invalid Encrypt accepted")
		}
	}
	_, e = c.Encrypt(ctx, &pb.EncryptRequest{Uid: "protobuf-limit", Plaintext: make([]byte, 5<<20)})
	if status.Code(e) != codes.ResourceExhausted {
		return errors.New("protobuf limit not enforced")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	if _, e = c.Status(cancelled, &pb.StatusRequest{}); status.Code(e) != codes.Canceled {
		return errors.New("cancellation not enforced")
	}
	expired, stop := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stop()
	if _, e = c.Status(expired, &pb.StatusRequest{}); status.Code(e) != codes.DeadlineExceeded {
		return errors.New("deadline not enforced")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- check(fixture{enc.KeyId, enc.Ciphertext}) }()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			return e
		}
	}
	if *save != "" {
		b, e := json.Marshal(fixture{enc.KeyId, enc.Ciphertext})
		if e != nil {
			return e
		}
		f, e := os.OpenFile(*save, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "PASS", "version": st.Version, "key_id": st.KeyId, "roundtrip": true, "negative_inputs": true, "size_limit": true, "deadline": true, "cancellation": true, "concurrent_decrypt": 16, "previous_fixture": *read != ""})
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "KMS v2 verification failed:", status.Code(e))
		os.Exit(1)
	}
}
