package transit_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	kmstransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
)

// auditEnv: 신원을 컨텍스트에 직접 주입(인증 미들웨어 대용)하고 비동기 감사를 켠 Transit 라우터.
func auditEnv(t *testing.T, authorizer *authz.Authorizer) (srv *httptest.Server, km *keys.KeyManager, dir string, log *audit.TransitLog) {
	t.Helper()
	store := storage.NewMemoryStorage()
	sealer := seal.NewDevSeal("test-passphrase")
	b := barrier.NewBarrier(store, sealer)
	if err := b.Unseal(); err != nil {
		t.Fatal(err)
	}
	km = keys.NewKeyManager(b)
	dir = t.TempDir()
	var err error
	log, err = audit.NewTransit(dir, 256, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	router := apitransit.NewRouter(apitransit.Deps{Barrier: b, Transit: kmstransit.NewTransitService(km), Seal: sealer, Authorizer: authorizer, Audit: log})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := authn.Identity{Namespace: "shop", ServiceAccount: "api", Subject: "system:serviceaccount:shop:api"}
		router.ServeHTTP(w, r.WithContext(authn.WithIdentity(r.Context(), id)))
	})
	srv = httptest.NewServer(wrapped)
	t.Cleanup(srv.Close)
	return
}

func TestTransitAudit_RecordsFieldsAndNeverSecrets(t *testing.T) {
	srv, km, dir, log := auditEnv(t, newFakeAuthorizer(t, true))
	for _, n := range []string{"global-key", "team-a.ledger"} {
		if _, err := km.CreateKey(n, 0); err != nil {
			t.Fatal(err)
		}
	}
	const secretPlain = "SECRET-PLAINTEXT-FIXTURE"
	pt := base64.StdEncoding.EncodeToString([]byte(secretPlain))

	resp := doJSON(t, http.MethodPost, srv.URL+"/v1/encrypt/team-a.ledger", map[string]string{"plaintext": pt})
	var enc struct{ Ciphertext string }
	decodeJSON(t, resp, &enc)
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/team-a.ledger", map[string]string{"ciphertext": enc.Ciphertext})
	resp.Body.Close()
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/rewrap/team-a.ledger", map[string]string{"ciphertext": enc.Ciphertext})
	resp.Body.Close()
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/encrypt/global-key", map[string]string{"plaintext": pt})
	if rid := resp.Header.Get("X-Request-ID"); rid == "" {
		t.Error("X-Request-ID header missing")
	}
	resp.Body.Close()
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/global-key", map[string]string{"ciphertext": "kms:v1:garbage"})
	resp.Body.Close()

	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	evs, err := audit.ReadTransitToday(dir)
	if err != nil || len(evs) != 5 {
		t.Fatalf("events = %d (%v)", len(evs), err)
	}
	want := []struct {
		action, key, ns string
		status          int
	}{
		{"encrypt", "team-a.ledger", "team-a", 200}, {"decrypt", "team-a.ledger", "team-a", 200}, {"rewrap", "team-a.ledger", "team-a", 200},
		{"encrypt", "global-key", "", 200}, {"decrypt", "global-key", "", 400},
	}
	for i, w := range want {
		e := evs[i]
		if e.Action != w.action || e.Key != w.key || e.SARNamespace != w.ns || e.Status != w.status ||
			e.Subject != "system:serviceaccount:shop:api" || e.RequestID == "" || e.UTC.IsZero() || e.LatencyMs < 0 {
			t.Errorf("event %d = %+v, want %+v", i, e, w)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".jsonl"))
	for _, secret := range []string{secretPlain, pt, enc.Ciphertext, "kms:v1:garbage", "Bearer"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("audit file contains secret material %q", secret)
		}
	}
}

func TestTransitAudit_RecordsDenialsWithoutBlockingRequests(t *testing.T) {
	srv, _, dir, log := auditEnv(t, newFakeAuthorizer(t, false))
	resp := doJSON(t, http.MethodPost, srv.URL+"/v1/encrypt/anything", map[string]string{"plaintext": "AA=="})
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	log.Close()
	evs, _ := audit.ReadTransitToday(dir)
	if len(evs) != 1 || evs[0].Status != 403 || evs[0].Key != "anything" {
		t.Fatalf("events = %+v", evs)
	}
	b, _ := json.Marshal(evs[0])
	if strings.Contains(string(b), "plaintext") {
		t.Fatal("body leaked")
	}
}
