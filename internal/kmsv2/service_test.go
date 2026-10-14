package kmsv2_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/kmsv2"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	pb "k8s.io/kms/apis/v2"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestOfficialRPCSealRotationRestart(t *testing.T) {
	dir := t.TempDir()
	s := seal.NewShamirSeal(3)
	store := storage.NewFileStorage(dir)
	b := barrier.NewBarrier(store, s)
	shares, e := b.Initialize(5, 3)
	if e != nil {
		t.Fatal(e)
	}
	km := keys.NewKeyManager(b)
	start := func(km *keys.KeyManager) pb.KeyManagementServiceClient {
		socket := filepath.Join(t.TempDir(), "v2.sock")
		l, e := net.Listen("unix", socket)
		if e != nil {
			t.Fatal(e)
		}
		server := grpc.NewServer()
		pb.RegisterKeyManagementServiceServer(server, kmsv2.New(km, "k8s-secrets"))
		go server.Serve(l)
		t.Cleanup(server.Stop)
		conn, e := grpc.NewClient("passthrough:///kms", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { conn.Close() })
		return pb.NewKeyManagementServiceClient(conn)
	}
	client := start(km)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, e = client.Status(ctx, &pb.StatusRequest{}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("sealed status healthy")
	}
	for _, x := range shares[:3] {
		s.SubmitShare(x)
	}
	if e = b.Unseal(); e != nil {
		t.Fatal(e)
	}
	if _, e = km.CreateKey("k8s-secrets", 0); e != nil {
		t.Fatal(e)
	}
	st, e := client.Status(ctx, &pb.StatusRequest{})
	if e != nil || st.Version != "v2" || st.Healthz != "ok" {
		t.Fatal("official Status failed")
	}
	plain := []byte("public fixed RPC vector")
	encrypted, e := client.Encrypt(ctx, &pb.EncryptRequest{Uid: "encrypt-uid", Plaintext: plain})
	if e != nil {
		t.Fatal(e)
	}
	decrypt := func(c pb.KeyManagementServiceClient) {
		p, e := c.Decrypt(ctx, &pb.DecryptRequest{Uid: "different-decrypt-uid", Ciphertext: encrypted.Ciphertext, KeyId: encrypted.KeyId})
		if e != nil || !bytes.Equal(p.Plaintext, plain) {
			t.Error("old ciphertext failed")
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := km.RotateKey("k8s-secrets"); e != nil {
				t.Error(e)
			}
			decrypt(client)
		}()
	}
	wg.Wait()
	for _, r := range []*pb.DecryptRequest{{Uid: "x", Ciphertext: encrypted.Ciphertext, KeyId: "wrong:1"}, {Uid: "x", Ciphertext: []byte("tampered"), KeyId: encrypted.KeyId}, {Uid: "x", Ciphertext: encrypted.Ciphertext, KeyId: encrypted.KeyId, Annotations: map[string][]byte{"unknown.example": []byte("x")}}} {
		if _, e = client.Decrypt(ctx, r); status.Code(e) != codes.InvalidArgument {
			t.Fatal("invalid RPC accepted")
		}
	}
	if _, e = client.Encrypt(ctx, &pb.EncryptRequest{Plaintext: plain}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("missing uid accepted")
	}
	b.Seal()
	s2 := seal.NewShamirSeal(3)
	b2 := barrier.NewBarrier(storage.NewFileStorage(dir), s2)
	for _, x := range shares[:3] {
		s2.SubmitShare(x)
	}
	if e = b2.Unseal(); e != nil {
		t.Fatal(e)
	}
	decrypt(start(keys.NewKeyManager(b2)))
}

// Fixture generated independently with Python cryptography AESGCM: zero test KEK,
// zero nonce, public plaintext, AAD "kms-v2:k8s-secrets:1". These are not live keys.
func TestDecryptFixedVector(t *testing.T) {
	b := barrier.NewBarrier(storage.NewMemoryStorage(), seal.NewDevSeal("fixture"))
	if e := b.Unseal(); e != nil {
		t.Fatal(e)
	}
	ring := keys.KeyRing{Name: "k8s-secrets", Type: "aes256-gcm", LatestVersion: 1, MinDecryptionVersion: 1, Versions: []keys.KeyVersion{{Version: 1, KeyMaterial: make([]byte, 32)}}}
	if e := b.PutJSON("keys/k8s-secrets", ring); e != nil {
		t.Fatal(e)
	}
	svc := kmsv2.New(keys.NewKeyManager(b), "k8s-secrets")
	ciphertext, e := hex.DecodeString("000000000000000000000000bed2225124034b086e36a0b79ab8d04b521631ea41c34900bed073510dffcda453bce1cec132e98605a6")
	if e != nil {
		t.Fatal(e)
	}
	request := &pb.DecryptRequest{Uid: "independent-request-id", KeyId: "k8s-secrets:1", Ciphertext: ciphertext}
	p, e := svc.Decrypt(context.Background(), request)
	if e != nil || string(p.Plaintext) != "public fixed KMS v2 vector" {
		t.Fatal("fixed protocol vector incompatible")
	}
	request.Ciphertext[len(request.Ciphertext)-1] ^= 1
	if _, e = svc.Decrypt(context.Background(), request); status.Code(e) != codes.InvalidArgument {
		t.Fatal("tampered vector accepted")
	}
}
