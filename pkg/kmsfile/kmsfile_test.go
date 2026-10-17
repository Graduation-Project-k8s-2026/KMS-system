package kmsfile

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

const testCT = "kms:v1:ZmFrZS1kYXRhLWtleS1jaXBoZXJ0ZXh0"

func newKey() []byte { k := make([]byte, 32); rand.Read(k); return k }

func enc(t *testing.T, data []byte, key []byte, chunk int) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader(data), Params{KeyName: "team.k", DataKeyCiphertext: testCT, DataKey: append([]byte(nil), key...), ChunkSize: chunk}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func dec(file []byte, key []byte, expect string) ([]byte, error) {
	d, err := NewDecoder(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = d.Decrypt(&out, append([]byte(nil), key...), expect)
	return out.Bytes(), err
}

func TestRoundTripSizes(t *testing.T) {
	key := newKey()
	const c = 1024
	for _, n := range []int{0, 1, c - 1, c, c + 1, 2 * c, 2*c + 5, 10*c + 7, 64 << 10} {
		data := make([]byte, n)
		rand.Read(data)
		file := enc(t, data, key, c)
		got, err := dec(file, key, "team.k")
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("size %d: err=%v equal=%v", n, err, bytes.Equal(got, data))
		}
	}
	// 기본 청크 크기로도
	data := make([]byte, 3*DefaultChunkSize+10)
	rand.Read(data)
	if got, err := dec(enc(t, data, key, 0), key, ""); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("default chunk: %v", err)
	}
}

func TestHeaderFieldsAndDetection(t *testing.T) {
	key := newKey()
	file := enc(t, []byte("hi"), key, 0)
	if !IsKMSFile(file) || IsKMSFile([]byte("kms:v1:xx")) || IsKMSFile([]byte("KM")) {
		t.Fatal("IsKMSFile")
	}
	d, err := NewDecoder(bytes.NewReader(file))
	if err != nil || d.Header.KeyName != "team.k" || d.Header.DataKeyCiphertext != testCT || d.Header.ChunkSize != DefaultChunkSize {
		t.Fatalf("header = %+v, %v", d.Header, err)
	}
	if _, err := NewDecoder(bytes.NewReader([]byte("not a file at all"))); !errors.Is(err, ErrNotKMSFile) {
		t.Fatalf("err = %v", err)
	}
}

func TestEachChunkHasDistinctNonceAndCiphertext(t *testing.T) {
	key := newKey()
	data := bytes.Repeat([]byte{7}, 3*1024) // 같은 평문 3청크
	file := enc(t, data, key, 1024)
	d, _ := NewDecoder(bytes.NewReader(file))
	body := file[len(d.Header.raw):]
	c := 1024 + tagSize
	if bytes.Equal(body[:c], body[c:2*c]) || bytes.Equal(body[c:2*c], body[2*c:3*c]) {
		t.Fatal("identical plaintext chunks produced identical ciphertext (nonce reuse?)")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	key := newKey()
	const c = 1024
	data := make([]byte, 5*c+100)
	rand.Read(data)
	file := enc(t, data, key, c)
	d, _ := NewDecoder(bytes.NewReader(file))
	hl := len(d.Header.raw)
	full := c + tagSize

	mustFail := func(name string, f []byte) {
		t.Helper()
		got, err := dec(f, key, "")
		if err == nil {
			t.Fatalf("%s: tampering not detected", name)
		}
		if bytes.Equal(got, data) {
			t.Fatalf("%s: full plaintext returned", name)
		}
	}
	// 본문 비트 변조
	f := append([]byte(nil), file...)
	f[hl+10] ^= 1
	mustFail("bit flip", f)
	// 청크 교환 (1번 ↔ 2번)
	f = append([]byte(nil), file...)
	a, b := f[hl+full:hl+2*full], f[hl+2*full:hl+3*full]
	tmp := append([]byte(nil), a...)
	copy(a, b)
	copy(b, tmp)
	mustFail("swap", f)
	// 청크 삭제 (가운데)
	f = append(append([]byte(nil), file[:hl+full]...), file[hl+2*full:]...)
	mustFail("delete middle", f)
	// 끝 잘라내기: 마지막 청크 제거(청크 경계), 그리고 중간에서 자르기
	mustFail("truncate last chunk", file[:hl+5*full])
	mustFail("truncate inside", file[:len(file)-10])
	mustFail("truncate to header only", file[:hl])
	// 덧붙이기: 쓰레기, 그리고 유효한 청크 하나 더(같은 파일의 첫 청크)
	mustFail("append garbage", append(append([]byte(nil), file...), 1, 2, 3))
	mustFail("append valid-looking chunk", append(append([]byte(nil), file...), file[hl:hl+full]...))
	// 헤더 변조: 키 이름 바꾸기(같은 길이), data key 암호문 바꾸기
	f = append([]byte(nil), file...)
	f[4+1+2] ^= 1
	mustFail("header key name", f)
	f = append([]byte(nil), file...)
	f[hl-12-4-3] ^= 1 // data key 암호문 안쪽
	mustFail("header ciphertext", f)
	// 다른 data key
	if _, err := dec(file, newKey(), ""); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("wrong key err = %v", err)
	}
}

func TestExpectedKeyNameMismatchRejectedBeforeDecrypting(t *testing.T) {
	key := newKey()
	file := enc(t, []byte("secret"), key, 0)
	got, err := dec(file, key, "other.key")
	if !errors.Is(err, ErrKeyMismatch) || len(got) != 0 {
		t.Fatalf("err = %v, plaintext len = %d", err, len(got))
	}
}

func TestDataKeyZeroedAndValidated(t *testing.T) {
	key := newKey()
	var out bytes.Buffer
	if err := Encrypt(&out, bytes.NewReader([]byte("x")), Params{KeyName: "k", DataKeyCiphertext: testCT, DataKey: key}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, make([]byte, 32)) {
		t.Fatal("Encrypt did not zero the data key")
	}
	if err := Encrypt(&out, bytes.NewReader(nil), Params{KeyName: "k", DataKeyCiphertext: testCT, DataKey: make([]byte, 16)}); !errors.Is(err, ErrBadDataKey) {
		t.Fatalf("16-byte key err = %v", err)
	}
	if err := Encrypt(&out, bytes.NewReader(nil), Params{KeyName: "k", DataKeyCiphertext: testCT, DataKey: newKey(), ChunkSize: 10}); err == nil {
		t.Fatal("tiny chunk accepted")
	}
	// 복호화도 키를 지운다
	k2 := newKey()
	f := enc(t, []byte("x"), k2, 0)
	d, _ := NewDecoder(bytes.NewReader(f))
	dk := append([]byte(nil), k2...)
	if err := d.Decrypt(io.Discard, dk, ""); err != nil || !bytes.Equal(dk, make([]byte, 32)) {
		t.Fatalf("Decrypt did not zero the data key: %v", err)
	}
}

func TestStreamingDoesNotBufferWholeFile(t *testing.T) {
	// 100 MiB를 흘려 보내도 메모리 대신 청크 단위로 처리된다: 출력 크기 = 입력 + 청크당 16바이트 + 헤더
	key := newKey()
	const total = 100 << 20
	cw := &countWriter{}
	if err := Encrypt(cw, io.LimitReader(zeroReader{}, total), Params{KeyName: "k", DataKeyCiphertext: testCT, DataKey: key}); err != nil {
		t.Fatal(err)
	}
	chunks := (total + DefaultChunkSize - 1) / DefaultChunkSize
	if cw.n < total+chunks*tagSize || cw.n > total+chunks*tagSize+300 {
		t.Fatalf("output size = %d", cw.n)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type countWriter struct{ n int }

func (c *countWriter) Write(p []byte) (int, error) { c.n += len(p); return len(p), nil }
