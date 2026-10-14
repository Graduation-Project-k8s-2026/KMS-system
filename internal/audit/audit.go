// Package audit writes bounded, fsynced records containing no request bodies or credentials.
package audit

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Event struct {
	UTC       time.Time `json:"utc"`
	RequestID string    `json:"request_id"`
	Subject   string    `json:"subject"`
	Action    string    `json:"action"`
	Allowed   bool      `json:"allowed"`
	Success   bool      `json:"success"`
}
type Log struct {
	Dir string
	mu  sync.Mutex
}

func New(dir string) (*Log, error) {
	if dir == "" {
		return nil, errors.New("audit directory required")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	return &Log{Dir: dir}, nil
}
func (l *Log) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.UTC = time.Now().UTC()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	if e.RequestID == "" {
		e.RequestID = hex.EncodeToString(b)
	}
	entries, err := os.ReadDir(l.Dir)
	if err != nil {
		return err
	}
	for _, f := range entries {
		st, err := f.Info()
		if err != nil {
			return err
		}
		if filepath.Ext(f.Name()) == ".jsonl" && time.Since(st.ModTime()) > 30*24*time.Hour {
			if err = os.Remove(filepath.Join(l.Dir, f.Name())); err != nil {
				return err
			}
		}
	}
	record, err := json.Marshal(e)
	if err != nil {
		return err
	}
	record = append(record, '\n')
	p := filepath.Join(l.Dir, e.UTC.Format("2006-01-02")+".jsonl")
	st, err := os.Stat(p)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	size := int64(0)
	if st != nil {
		size = st.Size()
	}
	if size+int64(len(record)) > 8<<20 {
		return errors.New("audit daily capacity exceeded")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(record); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	parent, err := os.Open(l.Dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
func (l *Log) Middleware(subject func(*http.Request) string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && (r.URL.Path == "/healthz" || r.URL.Path == "/readyz") {
			next.ServeHTTP(w, r)
			return
		}
		principal := &principalValue{Name: subject(r)}
		r = r.WithContext(context.WithValue(r.Context(), principalKey{}, principal))
		id := make([]byte, 16)
		if _, err := rand.Read(id); err != nil {
			http.Error(w, "audit unavailable", 503)
			return
		}
		requestID := hex.EncodeToString(id)
		if err := l.Write(Event{RequestID: requestID, Subject: subject(r), Action: action(r) + " requested"}); err != nil {
			http.Error(w, "audit unavailable", 503)
			return
		}
		rec := &buffered{header: make(http.Header), status: 200}
		next.ServeHTTP(rec, r)
		if err := l.Write(Event{RequestID: requestID, Subject: principal.Name, Action: action(r) + " completed", Allowed: rec.status != 401 && rec.status != 403, Success: rec.status < 400 && !rec.overflow}); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "audit completion unavailable; operation may have committed", 503)
			return
		}
		if rec.overflow {
			http.Error(w, "response too large", 503)
			return
		}
		for k, values := range rec.header {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.status)
		w.Write(rec.body.Bytes())
	})
}

type buffered struct {
	header   http.Header
	status   int
	body     bytes.Buffer
	overflow bool
}

func (w *buffered) Header() http.Header { return w.header }
func (w *buffered) WriteHeader(c int)   { w.status = c }
func (w *buffered) Write(b []byte) (int, error) {
	if w.body.Len()+len(b) > 2<<20 {
		w.overflow = true
		return 0, errors.New("response limit")
	}
	return w.body.Write(b)
}
func (w *buffered) Flush() {}

// ReadToday returns a bounded projection of today's events, never raw file contents.
func ReadToday(dir string) ([]Event, error) {
	f, err := os.Open(filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl"))
	if os.IsNotExist(err) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 9<<20))
	events := []Event{}
	for {
		var e Event
		err = d.Decode(&e)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		events = append(events, e)
		if len(events) > 1000 {
			events = events[1:]
		}
	}
	return events, nil
}

func action(r *http.Request) string {
	path := r.URL.Path
	for _, p := range []string{"/v1/sys/init", "/v1/sys/unseal", "/v1/sys/seal", "/api/jobs", "/api/bench/results", "/v1/keys", "/api/session", "/api/audit"} {
		if path == p || strings.HasPrefix(path, p+"/") {
			return r.Method + " " + p
		}
	}
	return r.Method + " other"
}

type principalKey struct{}
type principalValue struct{ Name string }

// SetSubject must only be called after authentication of this request.
func SetSubject(r *http.Request, name string) {
	if p, ok := r.Context().Value(principalKey{}).(*principalValue); ok {
		p.Name = name
	}
}
