// Package kmsfile은 큰 파일용 봉투 암호화 형식(KMSF)과 스트리밍 암복호화를 제공한다.
// internal/ 밖(pkg/)에 있어 다른 모듈에서도 import할 수 있다.
//
// 흐름: KMS에서 data key(평문+암호문)를 받아 Encrypt로 파일을 암호화하면, 결과 파일 헤더에 data key의 암호문(`kms:v..`)이
// 들어간다. 복호화할 때는 NewDecoder로 헤더를 읽어 암호문을 꺼내고, KMS decrypt로 평문 data key를 되찾아 Decoder.Decrypt에 넘긴다.
//
// 형식 (모든 정수는 big-endian):
//
//	헤더  : "KMSF" | 버전(1바이트=1) | 키 이름 길이(2) | 키 이름 | data key 암호문 길이(2) | 암호문 | 청크 크기(4) | 기본 nonce(12)
//	본문  : 청크 반복. 각 청크 = AES-256-GCM(평문 청크) 결과(평문 길이 + 16바이트 태그).
//	        마지막 청크를 제외한 모든 청크의 평문은 정확히 청크 크기다. 빈 파일은 평문 0바이트짜리 마지막 청크 하나.
//
// 보안 설계 (청크 스트림 암호화, STREAM 구성과 같은 발상):
//   - nonce = 기본 nonce의 마지막 8바이트에 청크 번호를 XOR → 청크마다 다르다(같은 data key로 nonce가 재사용되지 않음).
//   - AAD = SHA-256(헤더 전체) | 청크 번호(8) | 마지막 청크 여부(1).
//     · 청크 순서 바꾸기/삭제: 번호가 AAD에 있어 인증 실패.
//     · 끝 잘라내기: 새 마지막 청크는 "마지막 아님"으로 암호화되어 있어 마지막으로 읽으면 인증 실패.
//     · 덧붙이기: 원래 마지막 청크 뒤에 데이터가 더 있으면 그 청크를 "마지막 아님"으로 해석해 인증 실패.
//     · 헤더 변조(키 이름, data key 암호문, 청크 크기, nonce): 헤더 해시가 AAD에 있어 모든 청크가 인증 실패.
//   - 파일 전체를 메모리에 올리지 않는다 (청크 크기 + 1청크 선읽기만).
package kmsfile

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Magic            = "KMSF"
	Version          = 1
	DefaultChunkSize = 64 << 10
	minChunk         = 1 << 10
	maxChunk         = 16 << 20
	maxKeyName       = 255
	maxCiphertext    = 4096
	nonceSize        = 12
	tagSize          = 16
	DataKeyLen       = 32 // AES-256
)

var (
	ErrNotKMSFile  = errors.New("kmsfile: not a KMSF file")
	ErrBadHeader   = errors.New("kmsfile: malformed header")
	ErrKeyMismatch = errors.New("kmsfile: file was encrypted with a different key name")
	ErrAuthFailed  = errors.New("kmsfile: authentication failed (data modified, truncated, extended, or wrong key)")
	ErrBadDataKey  = errors.New("kmsfile: data key must be 32 bytes")
)

// Header는 파일 앞부분의 메타데이터다.
type Header struct {
	KeyName           string
	DataKeyCiphertext string
	ChunkSize         int
	BaseNonce         [nonceSize]byte
	raw               []byte // 직렬화된 헤더 (해시 계산용)
}

// IsKMSFile은 앞 4바이트 이상이 주어졌을 때 KMSF 파일인지 판별한다.
func IsKMSFile(prefix []byte) bool { return len(prefix) >= 4 && string(prefix[:4]) == Magic }

func (h *Header) marshal() []byte {
	var b bytes.Buffer
	b.WriteString(Magic)
	b.WriteByte(Version)
	binary.Write(&b, binary.BigEndian, uint16(len(h.KeyName)))
	b.WriteString(h.KeyName)
	binary.Write(&b, binary.BigEndian, uint16(len(h.DataKeyCiphertext)))
	b.WriteString(h.DataKeyCiphertext)
	binary.Write(&b, binary.BigEndian, uint32(h.ChunkSize))
	b.Write(h.BaseNonce[:])
	return b.Bytes()
}

func (h *Header) hash() [32]byte { return sha256.Sum256(h.raw) }

// Params는 Encrypt 입력이다. DataKey는 Encrypt가 끝나면(성공/실패 모두) 0으로 지운다.
type Params struct {
	KeyName           string
	DataKeyCiphertext string // KMS가 돌려준 "kms:v.." 문자열
	DataKey           []byte // 평문 data key (32바이트)
	ChunkSize         int    // 0이면 DefaultChunkSize
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != DataKeyLen {
		return nil, ErrBadDataKey
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func chunkNonce(base [nonceSize]byte, idx uint64) []byte {
	n := make([]byte, nonceSize)
	copy(n, base[:])
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], idx)
	for i := 0; i < 8; i++ {
		n[nonceSize-8+i] ^= c[i]
	}
	return n
}

func chunkAAD(hash [32]byte, idx uint64, last bool) []byte {
	aad := make([]byte, 0, 41)
	aad = append(aad, hash[:]...)
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], idx)
	aad = append(aad, c[:]...)
	if last {
		return append(aad, 1)
	}
	return append(aad, 0)
}

// readFull은 io.ReadFull과 같지만 EOF/짧은 읽기를 에러 없이 (읽은 바이트 수, 끝 여부)로 돌려준다.
func readFull(r io.Reader, buf []byte) (int, bool, error) {
	n, err := io.ReadFull(r, buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return n, true, nil
	}
	return n, false, err
}

// Encrypt는 src를 읽어 KMSF 형식으로 dst에 쓴다.
func Encrypt(dst io.Writer, src io.Reader, p Params) error {
	defer zero(p.DataKey)
	if p.ChunkSize == 0 {
		p.ChunkSize = DefaultChunkSize
	}
	if p.ChunkSize < minChunk || p.ChunkSize > maxChunk {
		return fmt.Errorf("kmsfile: chunk size must be between %d and %d", minChunk, maxChunk)
	}
	if p.KeyName == "" || len(p.KeyName) > maxKeyName || p.DataKeyCiphertext == "" || len(p.DataKeyCiphertext) > maxCiphertext {
		return errors.New("kmsfile: key name and data key ciphertext are required (and bounded)")
	}
	gcm, err := newGCM(p.DataKey)
	if err != nil {
		return err
	}
	h := &Header{KeyName: p.KeyName, DataKeyCiphertext: p.DataKeyCiphertext, ChunkSize: p.ChunkSize}
	if _, err := rand.Read(h.BaseNonce[:]); err != nil {
		return err
	}
	h.raw = h.marshal()
	if _, err := dst.Write(h.raw); err != nil {
		return err
	}
	hash := h.hash()

	br := bufio.NewReaderSize(src, p.ChunkSize+1)
	buf := make([]byte, p.ChunkSize)
	defer zero(buf)
	for idx := uint64(0); ; idx++ {
		n, short, err := readFull(br, buf)
		if err != nil {
			return err
		}
		last := short
		if !short { // 정확히 한 청크를 채웠다: 뒤에 데이터가 더 있는지 한 바이트 미리 본다
			if _, perr := br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		out := gcm.Seal(nil, chunkNonce(h.BaseNonce, idx), buf[:n], chunkAAD(hash, idx, last))
		if _, err := dst.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
	}
}

// Decoder는 헤더를 읽은 상태의 KMSF 스트림이다.
type Decoder struct {
	Header Header
	br     *bufio.Reader
}

// NewDecoder는 src에서 헤더를 읽고 검증한다. 본문은 아직 읽지 않는다.
func NewDecoder(src io.Reader) (*Decoder, error) {
	br := bufio.NewReaderSize(src, DefaultChunkSize+tagSize+1)
	var raw bytes.Buffer
	read := func(n int) ([]byte, error) {
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return nil, err
		}
		raw.Write(b)
		return b, nil
	}
	magic, err := read(4)
	if err != nil || string(magic) != Magic {
		return nil, ErrNotKMSFile
	}
	v, err := read(1)
	if err != nil || v[0] != Version {
		return nil, fmt.Errorf("%w: unsupported version", ErrBadHeader)
	}
	h := Header{}
	l, err := read(2)
	if err != nil {
		return nil, ErrBadHeader
	}
	kl := int(binary.BigEndian.Uint16(l))
	if kl == 0 || kl > maxKeyName {
		return nil, ErrBadHeader
	}
	kn, err := read(kl)
	if err != nil {
		return nil, ErrBadHeader
	}
	h.KeyName = string(kn)
	l, err = read(2)
	if err != nil {
		return nil, ErrBadHeader
	}
	cl := int(binary.BigEndian.Uint16(l))
	if cl == 0 || cl > maxCiphertext {
		return nil, ErrBadHeader
	}
	ct, err := read(cl)
	if err != nil {
		return nil, ErrBadHeader
	}
	h.DataKeyCiphertext = string(ct)
	cs, err := read(4)
	if err != nil {
		return nil, ErrBadHeader
	}
	h.ChunkSize = int(binary.BigEndian.Uint32(cs))
	if h.ChunkSize < minChunk || h.ChunkSize > maxChunk {
		return nil, fmt.Errorf("%w: chunk size out of range", ErrBadHeader)
	}
	nn, err := read(nonceSize)
	if err != nil {
		return nil, ErrBadHeader
	}
	copy(h.BaseNonce[:], nn)
	h.raw = raw.Bytes()
	return &Decoder{Header: h, br: bufio.NewReaderSize(br, h.ChunkSize+tagSize+1)}, nil
}

// Decrypt는 본문을 청크 단위로 복호화해 dst에 쓴다. expectKeyName이 비어 있지 않으면 헤더의 키 이름과 같아야 한다
// (다른 키로 만든 파일을 엉뚱한 키로 풀려는 시도를 일찍 거절). 평문 data key(dataKey)는 끝나면 0으로 지운다.
// 인증에 실패한 청크의 평문은 dst에 쓰지 않는다 (앞선 청크는 이미 쓰였을 수 있으므로 호출자는 실패 시 출력을 버려야 한다).
func (d *Decoder) Decrypt(dst io.Writer, dataKey []byte, expectKeyName string) error {
	defer zero(dataKey)
	if expectKeyName != "" && expectKeyName != d.Header.KeyName {
		return ErrKeyMismatch
	}
	gcm, err := newGCM(dataKey)
	if err != nil {
		return err
	}
	hash := d.Header.hash()
	size := d.Header.ChunkSize + tagSize
	buf := make([]byte, size)
	for idx := uint64(0); ; idx++ {
		n, short, err := readFull(d.br, buf)
		if err != nil {
			return err
		}
		if n < tagSize {
			return ErrAuthFailed // 본문이 없거나 청크가 잘렸다
		}
		last := short
		if !short {
			if _, perr := d.br.Peek(1); perr == io.EOF {
				last = true
			} else if perr != nil {
				return perr
			}
		}
		plain, err := gcm.Open(nil, chunkNonce(d.Header.BaseNonce, idx), buf[:n], chunkAAD(hash, idx, last))
		if err != nil {
			return ErrAuthFailed
		}
		_, werr := dst.Write(plain)
		zero(plain)
		if werr != nil {
			return werr
		}
		if last {
			return nil
		}
	}
}
