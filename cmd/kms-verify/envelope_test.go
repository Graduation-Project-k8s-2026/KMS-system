package main

import (
	"google.golang.org/protobuf/encoding/protowire"
	"testing"
)

func TestEnvelopeRequiresExpectedFields(t *testing.T) {
	p := []byte("k8s:enc:kms:v2:custom-kms:")
	for i, v := range []string{"ciphertext", "k8s-secrets:2", "encrypted-dek"} {
		p = protowire.AppendTag(p, protowire.Number(i+1), protowire.BytesType)
		p = protowire.AppendBytes(p, []byte(v))
	}
	if id, e := envelopeKeyID(p); e != nil || id != "k8s-secrets:2" {
		t.Fatal("valid envelope rejected")
	}
	for _, bad := range [][]byte{p[:len(p)-1], []byte("plaintext"), append(append([]byte{}, p...), protowire.AppendTag(nil, 2, protowire.BytesType)...)} {
		if _, e := envelopeKeyID(bad); e == nil {
			t.Fatal("invalid envelope accepted")
		}
	}
}
