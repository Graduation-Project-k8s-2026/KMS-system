package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersistentAuditCapacityRetention(t *testing.T) {
	dir := t.TempDir()
	l, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = l.Write(Event{Subject: "uid:10001", Action: "unseal", Allowed: true, Success: true}); e != nil {
		t.Fatal(e)
	}
	l, e = New(dir)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var event Event
	if e = json.Unmarshal(b, &event); e != nil || event.RequestID == "" || event.Action != "unseal" {
		t.Fatal("audit not preserved")
	}
	old := filepath.Join(dir, "2000-01-01.jsonl")
	os.WriteFile(old, []byte("old"), 0600)
	past := time.Now().Add(-31 * 24 * time.Hour)
	os.Chtimes(old, past, past)
	if e = l.Write(Event{Action: "read"}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(old); !os.IsNotExist(e) {
		t.Fatal("retention not enforced")
	}
	if e = os.WriteFile(p, []byte(strings.Repeat("x", (8<<20)+1)), 0600); e != nil {
		t.Fatal(e)
	}
	if e = l.Write(Event{Action: "overflow"}); e == nil {
		t.Fatal("capacity exceeded silently")
	}
}

func TestAuditCompletionFailureDoesNotReportSuccess(t *testing.T) {
	dir := t.TempDir()
	l, e := New(dir)
	if e != nil {
		t.Fatal(e)
	}
	h := l.Middleware(func(*http.Request) string { return "fixture" }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
		if e := os.WriteFile(p, []byte(strings.Repeat("x", (8<<20)+1)), 0600); e != nil {
			t.Fatal(e)
		}
		w.WriteHeader(201)
		w.Write([]byte("sensitive-response-fixture"))
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/sys/init", nil))
	if w.Code != 503 || strings.Contains(w.Body.String(), "sensitive-response-fixture") {
		t.Fatal("uncommitted audit returned sensitive success")
	}
}

func TestAuditExactLimitAndPayloadExclusion(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler := l.Middleware(func(*http.Request) string { return "verified-user" }, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) }))
	req := httptest.NewRequest("POST", "/v1/sys/unseal", strings.NewReader("private-body-fixture"))
	req.Header.Set("Authorization", "private-header-fixture")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("denial changed")
	}
	events, err := ReadToday(dir)
	if err != nil || len(events) != 2 {
		t.Fatal("intent/completion missing")
	}
	if events[0].RequestID != events[1].RequestID || events[1].Allowed || events[1].Success {
		t.Fatal("denial audit incorrect")
	}
	path := filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private-") {
		t.Fatal("payload or credential included in audit")
	}
	if err = os.Truncate(path, (8<<20)-1); err != nil {
		t.Fatal(err)
	}
	if err = l.Write(Event{Action: "write"}); err == nil {
		t.Fatal("record exceeded daily quota")
	}
	st, err := os.Stat(path)
	if err != nil || st.Size() != (8<<20)-1 {
		t.Fatal("quota failure modified log")
	}
}
