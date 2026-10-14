// Package kmsv2 implements the Kubernetes KMS v2 protocol without API dependencies.
package kmsv2

import (
	"context"
	"fmt"
	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "k8s.io/kms/apis/v2"
	"strconv"
	"strings"
)

type Service struct {
	pb.UnimplementedKeyManagementServiceServer
	Keys *keys.KeyManager
	Name string
}

func New(km *keys.KeyManager, name string) *Service {
	km.Protect(name)
	return &Service{Keys: km, Name: name}
}
func (s *Service) current() (int, []byte, error) {
	v, k, e := s.Keys.GetEncryptionKEK(s.Name)
	if e != nil {
		return 0, nil, status.Error(codes.FailedPrecondition, "sealed or key unavailable")
	}
	return v, k, nil
}
func (s *Service) id(v int) string { return s.Name + ":" + strconv.Itoa(v) }
func (s *Service) Status(ctx context.Context, r *pb.StatusRequest) (*pb.StatusResponse, error) {
	v, _, e := s.current()
	if e != nil {
		return nil, e
	}
	return &pb.StatusResponse{Version: "v2", Healthz: "ok", KeyId: s.id(v)}, nil
}
func (s *Service) Encrypt(ctx context.Context, r *pb.EncryptRequest) (*pb.EncryptResponse, error) {
	if r.Uid == "" || len(r.Plaintext) == 0 || len(r.Plaintext) > 1<<20 {
		return nil, status.Error(codes.InvalidArgument, "uid and bounded plaintext required")
	}
	if ctx.Err() != nil {
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	v, k, e := s.current()
	if e != nil {
		return nil, e
	}
	id := s.id(v)
	c, e := kmscrypto.Encrypt(k, r.Plaintext, []byte("kms-v2:"+id))
	clear(k)
	if e != nil {
		return nil, status.Error(codes.Internal, "encryption failed")
	}
	return &pb.EncryptResponse{Ciphertext: c, KeyId: id}, nil
}
func (s *Service) Decrypt(ctx context.Context, r *pb.DecryptRequest) (*pb.DecryptResponse, error) {
	if r.Uid == "" || len(r.Ciphertext) == 0 || len(r.Ciphertext) > (1<<20)+28 || len(r.Annotations) != 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid decrypt request")
	}
	if ctx.Err() != nil {
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	v, e := strconv.Atoi(strings.TrimPrefix(r.KeyId, s.Name+":"))
	if e != nil || v < 1 || r.KeyId != s.id(v) {
		return nil, status.Error(codes.InvalidArgument, "invalid key ID")
	}
	k, e := s.Keys.GetDecryptionKEK(s.Name, v)
	if e != nil {
		return nil, status.Error(codes.FailedPrecondition, "sealed or key unavailable")
	}
	p, e := kmscrypto.Decrypt(k, r.Ciphertext, []byte("kms-v2:"+r.KeyId))
	clear(k)
	if e != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Sprint("ciphertext authentication failed"))
	}
	return &pb.DecryptResponse{Plaintext: p}, nil
}
