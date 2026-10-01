package bench_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// fakeServer은 internal/api/transit의 encrypt/decrypt/rewrap과 같은 와이어
// 형식으로 응답하는 최소한의 가짜 Transit 서버다. 실제 암호화는 하지 않고
// "ct:"+base64(plaintext) 형태로만 왕복시킨다 — bench 패키지는 HTTP 경계
// 너머를 전혀 모르므로, 이 가짜 서버로도 client/runner/preflight 전체 흐름을
// 충분히 검증할 수 있다.
type fakeServer struct {
	keyName string
	sleep   time.Duration

	mu           sync.Mutex
	sealed       bool
	encryptCalls int
	decryptCalls int
	rewrapCalls  int

	inFlight    int32
	maxInFlight int32
}

func newFakeServer(keyName string) *fakeServer {
	return &fakeServer{keyName: keyName}
}

func (f *fakeServer) setSealed(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sealed = v
}

func (f *fakeServer) counts() (encrypt, decrypt, rewrap int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.encryptCalls, f.decryptCalls, f.rewrapCalls
}

func (f *fakeServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/encrypt/", f.handleEncrypt)
	mux.HandleFunc("/v1/decrypt/", f.handleDecrypt)
	mux.HandleFunc("/v1/rewrap/", f.handleRewrap)
	return mux
}

// trackInFlight는 동시 처리 중인 요청 수의 최댓값을 기록한다 — 동시성
// 수준이 실제로 worker 수만큼 반영되는지 검증하는 데 쓴다.
func (f *fakeServer) trackInFlight() func() {
	cur := atomic.AddInt32(&f.inFlight, 1)
	for {
		max := atomic.LoadInt32(&f.maxInFlight)
		if cur <= max {
			break
		}
		if atomic.CompareAndSwapInt32(&f.maxInFlight, max, cur) {
			break
		}
	}
	if f.sleep > 0 {
		time.Sleep(f.sleep)
	}
	return func() { atomic.AddInt32(&f.inFlight, -1) }
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeServer) checkKeyAndSeal(w http.ResponseWriter, r *http.Request, prefix string) bool {
	f.mu.Lock()
	sealed := f.sealed
	f.mu.Unlock()
	if sealed {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "kms is sealed"})
		return false
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	if name != f.keyName {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return false
	}
	return true
}

func (f *fakeServer) handleEncrypt(w http.ResponseWriter, r *http.Request) {
	done := f.trackInFlight()
	defer done()
	if !f.checkKeyAndSeal(w, r, "/v1/encrypt/") {
		return
	}
	f.mu.Lock()
	f.encryptCalls++
	f.mu.Unlock()

	var req struct {
		Plaintext string `json:"plaintext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": "ct:" + req.Plaintext})
}

func (f *fakeServer) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	done := f.trackInFlight()
	defer done()
	if !f.checkKeyAndSeal(w, r, "/v1/decrypt/") {
		return
	}
	f.mu.Lock()
	f.decryptCalls++
	f.mu.Unlock()

	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !strings.HasPrefix(req.Ciphertext, "ct:") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed ciphertext"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"plaintext": strings.TrimPrefix(req.Ciphertext, "ct:")})
}

func (f *fakeServer) handleRewrap(w http.ResponseWriter, r *http.Request) {
	done := f.trackInFlight()
	defer done()
	if !f.checkKeyAndSeal(w, r, "/v1/rewrap/") {
		return
	}
	f.mu.Lock()
	f.rewrapCalls++
	f.mu.Unlock()

	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !strings.HasPrefix(req.Ciphertext, "ct:") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed ciphertext"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ciphertext": "ct2:" + strings.TrimPrefix(req.Ciphertext, "ct:")})
}
