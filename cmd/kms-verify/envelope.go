package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"google.golang.org/protobuf/encoding/protowire"
	"io"
	"regexp"
)

// Field numbers are from the Kubernetes v0.35.9 EncryptedObject protobuf:
// pkg/storage/value/encrypt/envelope/kmsv2/v2/api.proto. No encrypted data is emitted.
func envelopeKeyID(raw []byte) (string, error) {
	prefix := []byte("k8s:enc:kms:v2:custom-kms:")
	if !bytes.HasPrefix(raw, prefix) {
		return "", errors.New("unexpected storage prefix")
	}
	raw = raw[len(prefix):]
	key := ""
	seen := map[protowire.Number]bool{}
	for len(raw) > 0 {
		number, typ, n := protowire.ConsumeTag(raw)
		if n < 0 {
			return "", errors.New("invalid protobuf tag")
		}
		raw = raw[n:]
		size := protowire.ConsumeFieldValue(number, typ, raw)
		if size < 0 {
			return "", errors.New("invalid protobuf field")
		}
		if number >= 1 && number <= 3 {
			if seen[number] || typ != protowire.BytesType {
				return "", errors.New("duplicate or mistyped envelope field")
			}
			seen[number] = true
			v, n := protowire.ConsumeBytes(raw)
			if n < 0 || len(v) == 0 {
				return "", errors.New("empty envelope field")
			}
			if number == 2 {
				key = string(v)
			}
		}
		raw = raw[size:]
	}
	if len(seen) != 3 || !regexp.MustCompile(`^k8s-secrets:[1-9][0-9]*$`).MatchString(key) {
		return "", errors.New("incomplete or unexpected envelope")
	}
	return key, nil
}
func inspectEtcd(reader io.Reader, writer io.Writer) error {
	var d struct {
		More  bool `json:"more"`
		Count int  `json:"count"`
		KVs   []struct {
			Key   []byte `json:"key"`
			Value []byte `json:"value"`
		} `json:"kvs"`
	}
	if e := json.NewDecoder(reader).Decode(&d); e != nil {
		return errors.New("invalid etcd JSON")
	}
	if d.More || len(d.KVs) == 0 || d.Count != len(d.KVs) {
		return errors.New("incomplete etcd range")
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, kv := range d.KVs {
		if !bytes.HasPrefix(kv.Key, []byte("/registry/secrets/")) || seen[string(kv.Key)] {
			return errors.New("invalid or duplicate Secret key")
		}
		seen[string(kv.Key)] = true
		id, e := envelopeKeyID(kv.Value)
		if e != nil {
			return e
		}
		counts[id]++
	}
	return json.NewEncoder(writer).Encode(map[string]any{"status": "PASS", "secret_count": len(d.KVs), "key_id_counts": counts})
}
