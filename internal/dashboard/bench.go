package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// 업로드 제한과 저장 한도의 기본값.
const (
	DefaultMaxBenchBytes = 1 << 20 // 요청 본문 1MB
	DefaultMaxBenchFiles = 500
	maxRunsPerResult     = 200
	maxStringField       = 256
)

var (
	// idPattern은 서버가 만든 id만 통과시킨다. 점·슬래시가 없어 경로
	// 조작 문자열이 들어올 여지가 없다.
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	unsafeLabel  = regexp.MustCompile(`[^A-Za-z0-9_-]+`)
	validBenchOp = map[string]bool{"encrypt": true, "decrypt": true, "rewrap": true}
)

var (
	ErrNotFound  = errors.New("bench result not found")
	ErrInvalidID = errors.New("invalid bench result id")
	// ErrTooLarge: 요청 본문이 크기 제한을 넘었다.
	ErrTooLarge = errors.New("bench result too large")
)

// ValidationError는 업로드된 JSON이 bench 결과 형식에 맞지 않을 때의 오류다.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, a...)}
}

// BenchMeta는 목록에 보여줄 요약이다.
type BenchMeta struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Timestamp  time.Time `json:"timestamp"`
	Addr       string    `json:"addr"`
	Scenarios  []string  `json:"scenarios"`
	Conditions int       `json:"conditions"`

	storedAt string // id 앞부분(저장 시각) — 오래된 순 정렬용
}

// benchDoc은 검증에 쓰는 최소 스키마다. 저장은 원문 그대로 하므로 여기에
// 없는 필드는 버려지지 않고 파일에 남는다.
type benchDoc struct {
	Label     string     `json:"label"`
	Timestamp time.Time  `json:"timestamp"`
	Addr      string     `json:"addr"`
	Key       string     `json:"key"`
	Runs      []benchRun `json:"runs"`
}

type benchRun struct {
	Scenario     string  `json:"scenario"`
	Operation    string  `json:"operation"`
	PayloadBytes int     `json:"payload_bytes"`
	Concurrency  int     `json:"concurrency"`
	OpsPerSec    float64 `json:"ops_per_sec"`
	SuccessCount int     `json:"success_count"`
	ErrorCount   int     `json:"error_count"`
	Latency      *struct {
		Mean float64 `json:"mean_seconds"`
		P50  float64 `json:"p50_seconds"`
		P99  float64 `json:"p99_seconds"`
		Max  float64 `json:"max_seconds"`
	} `json:"latency"`
}

func validateBench(raw []byte) (benchDoc, error) {
	var doc benchDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return doc, invalid("invalid JSON: %v", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return doc, invalid("invalid JSON: unexpected data after the top-level object")
	}
	if doc.Timestamp.IsZero() {
		return doc, invalid("timestamp is required (RFC 3339)")
	}
	for name, v := range map[string]string{"label": doc.Label, "addr": doc.Addr, "key": doc.Key} {
		if len(v) > maxStringField {
			return doc, invalid("%s is longer than %d bytes", name, maxStringField)
		}
	}
	if len(doc.Runs) == 0 {
		return doc, invalid("runs must contain at least one run")
	}
	if len(doc.Runs) > maxRunsPerResult {
		return doc, invalid("runs has %d entries, max is %d", len(doc.Runs), maxRunsPerResult)
	}
	for i, r := range doc.Runs {
		at := func(f string) string { return fmt.Sprintf("runs[%d].%s", i, f) }
		switch {
		case r.Scenario == "" || len(r.Scenario) > maxStringField:
			return doc, invalid("%s is required", at("scenario"))
		case !validBenchOp[r.Operation]:
			return doc, invalid("%s must be encrypt, decrypt or rewrap", at("operation"))
		case r.Concurrency < 1:
			return doc, invalid("%s must be >= 1", at("concurrency"))
		case r.PayloadBytes < 0:
			return doc, invalid("%s must be >= 0", at("payload_bytes"))
		case !finiteNonNeg(r.OpsPerSec):
			return doc, invalid("%s must be a finite number >= 0", at("ops_per_sec"))
		case r.SuccessCount < 0 || r.ErrorCount < 0:
			return doc, invalid("%s/%s must be >= 0", at("success_count"), at("error_count"))
		case r.Latency == nil:
			return doc, invalid("%s is required", at("latency"))
		case !finiteNonNeg(r.Latency.Mean) || !finiteNonNeg(r.Latency.P50) ||
			!finiteNonNeg(r.Latency.P99) || !finiteNonNeg(r.Latency.Max):
			return doc, invalid("%s values must be finite numbers >= 0", at("latency"))
		}
	}
	return doc, nil
}

func finiteNonNeg(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }

// sanitizeLabel은 라벨을 파일명에 안전한 문자만 남겨 짧게 만든다.
func sanitizeLabel(label string) string {
	s := unsafeLabel.ReplaceAllString(label, "-")
	s = strings.Trim(s, "-_")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-_")
	}
	if s == "" {
		return "run"
	}
	return s
}

// BenchStore는 bench 결과를 디렉터리에 한 실행당 파일 하나로 저장한다.
// 목록은 메모리 색인에서 답하므로 목록 조회가 파일을 읽지 않는다.
type BenchStore struct {
	dir      string
	maxBytes int64
	maxFiles int
	now      func() time.Time

	mu    sync.Mutex
	index map[string]BenchMeta
}

// NewBenchStore는 dir을 만들고 기존 파일로 색인을 구성한다. 읽을 수 없는
// 파일은 경고만 남기고 건너뛴다.
func NewBenchStore(dir string, maxBytes int64, maxFiles int) (*BenchStore, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBenchBytes
	}
	if maxFiles <= 0 {
		maxFiles = DefaultMaxBenchFiles
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("bench dir: %w", err)
	}
	s := &BenchStore{dir: dir, maxBytes: maxBytes, maxFiles: maxFiles, now: time.Now, index: map[string]BenchMeta{}}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("bench dir: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		id, ok := strings.CutSuffix(name, ".json")
		if e.IsDir() || !ok || !idPattern.MatchString(id) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			log.Printf("dashboard: skipping unreadable bench file %s: %v", name, err)
			continue
		}
		doc, err := validateBench(raw)
		if err != nil {
			log.Printf("dashboard: skipping invalid bench file %s: %v", name, err)
			continue
		}
		s.index[id] = metaFor(id, doc)
	}
	return s, nil
}

func metaFor(id string, doc benchDoc) BenchMeta {
	seen := map[string]bool{}
	scenarios := []string{}
	for _, r := range doc.Runs {
		if !seen[r.Scenario] {
			seen[r.Scenario] = true
			scenarios = append(scenarios, r.Scenario)
		}
	}
	sort.Strings(scenarios)
	return BenchMeta{
		ID: id, Label: doc.Label, Timestamp: doc.Timestamp, Addr: doc.Addr,
		Scenarios: scenarios, Conditions: len(doc.Runs),
		storedAt: id,
	}
}

// Put은 raw(bench JSON 원문)를 검증하고 서버가 만든 id로 저장한다.
// 저장 개수가 상한을 넘으면 오래된 것부터 지운다.
func (s *BenchStore) Put(raw []byte) (BenchMeta, error) {
	if int64(len(raw)) > s.maxBytes {
		return BenchMeta{}, ErrTooLarge
	}
	doc, err := validateBench(raw)
	if err != nil {
		return BenchMeta{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 같은 초·같은 라벨이면 -2, -3 … 접미사를 붙인다.
	base := s.now().UTC().Format("20060102T150405Z") + "-" + sanitizeLabel(doc.Label)
	id := base
	for n := 2; ; n++ {
		if _, taken := s.index[id]; !taken {
			break
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}

	// 임시 파일에 쓴 뒤 하드링크로 최종 이름을 만든다 — 같은 이름이 있으면
	// 덮어쓰지 않고 실패하며, 쓰는 도중 중단돼도 반쯤 쓴 결과 파일이 남지 않는다.
	tmp, err := os.CreateTemp(s.dir, ".upload-*")
	if err != nil {
		return BenchMeta{}, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return BenchMeta{}, err
	}
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return BenchMeta{}, err
	}
	if err := tmp.Close(); err != nil {
		return BenchMeta{}, err
	}
	if err := os.Link(tmp.Name(), s.path(id)); err != nil {
		return BenchMeta{}, err
	}

	meta := metaFor(id, doc)
	s.index[id] = meta
	s.evictLocked()
	return meta, nil
}

func (s *BenchStore) evictLocked() {
	if len(s.index) <= s.maxFiles {
		return
	}
	metas := make([]BenchMeta, 0, len(s.index))
	for _, m := range s.index {
		metas = append(metas, m)
	}
	sort.Slice(metas, func(i, j int) bool { return metas[i].storedAt < metas[j].storedAt })
	for _, m := range metas[:len(metas)-s.maxFiles] {
		if err := os.Remove(s.path(m.ID)); err != nil && !os.IsNotExist(err) {
			log.Printf("dashboard: evicting %s failed: %v", m.ID, err)
			continue
		}
		delete(s.index, m.ID)
	}
}

func (s *BenchStore) path(id string) string { return filepath.Join(s.dir, id+".json") }

// List는 실행 시각(timestamp) 내림차순 목록을 반환한다.
func (s *BenchStore) List() []BenchMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BenchMeta, 0, len(s.index))
	for _, m := range s.index {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Timestamp.Equal(out[j].Timestamp) {
			return out[i].Timestamp.After(out[j].Timestamp)
		}
		return out[i].ID > out[j].ID
	})
	return out
}

// Get은 저장된 원문 JSON을 그대로 반환한다.
func (s *BenchStore) Get(id string) ([]byte, error) {
	if !idPattern.MatchString(id) {
		return nil, ErrInvalidID
	}
	s.mu.Lock()
	_, ok := s.index[id]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	raw, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	return raw, err
}

// Delete는 결과 하나를 지운다.
func (s *BenchStore) Delete(id string) error {
	if !idPattern.MatchString(id) {
		return ErrInvalidID
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.index[id]; !ok {
		return ErrNotFound
	}
	if err := os.Remove(s.path(id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	delete(s.index, id)
	return nil
}
