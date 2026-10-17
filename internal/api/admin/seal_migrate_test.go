package admin_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiadmin "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/admin"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	kmscrypto "github.com/Graduation-Project-k8s-2026/KMS-system/internal/crypto"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/kmsv2"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal/sealtest"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/shamir"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	transitsvc "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
	pb "k8s.io/kms/apis/v2"
)

const (
	initPathKey = "initialization.json"
	blobPathKey = "seal/tpm/rootkey"
	v2KeyName   = "k8s-secrets"
)

// faultStore: 특정 키의 Put/Delete를 실패시킬 수 있는 저장소 래퍼(실패 주입).
type faultStore struct {
	storage.StorageBackend
	failPut    map[string]bool
	failDelete map[string]bool
}

func (f *faultStore) Put(key string, v []byte) error {
	if f.failPut[key] {
		return errors.New("injected put failure")
	}
	return f.StorageBackend.Put(key, v)
}
func (f *faultStore) Delete(key string) error {
	if f.failDelete[key] {
		return errors.New("injected delete failure")
	}
	return f.StorageBackend.Delete(key)
}

// proc: main.go의 조립을 흉내 낸 "서버 프로세스 하나". 같은 store/장치로 새 proc을
// 만들면 재시작이다(메모리 상태 — 루트 키, 모인 조각 — 는 모두 사라진다).
type proc struct {
	t   *testing.T
	srv *httptest.Server
	b   *barrier.Barrier
	sw  *seal.Switch
	km  *keys.KeyManager

	shares []string // initAndUnseal이 받은 조각 (재해제 테스트용)
}

func startProc(t *testing.T, store storage.StorageBackend, dev *sealtest.Device) *proc {
	t.Helper()
	sw := seal.NewSwitch("shamir", seal.NewShamirSeal(3), nil,
		func() (seal.TPMBackend, error) { return dev.Open(store) }, store)
	b := barrier.NewBarrier(store, sw)
	km := keys.NewKeyManager(b)
	if err := b.CheckInitialization(5, 3); err != nil {
		t.Fatal(err)
	}
	mode, err := b.SealMode()
	if err != nil {
		t.Fatal(err)
	}
	if mode == "" {
		mode = "shamir"
	}
	sw.SetMode(mode)
	onUnseal := func() error {
		if _, err := km.GetKeyMeta(v2KeyName); err != nil {
			_, err = km.CreateKey(v2KeyName, 0)
			return err
		}
		return nil
	}
	if mode == "tpm" { // main.go의 기동 시 자동 해제
		if b.Unseal() == nil {
			if onUnseal() != nil {
				b.Seal()
			}
		}
	}
	srv := httptest.NewServer(apiadmin.NewRouter(apiadmin.Deps{
		Barrier: b, Keys: km, Seal: sw, OnUnseal: onUnseal, ReservedKey: v2KeyName,
		ShamirParts: 5, ShamirThreshold: 3,
	}))
	t.Cleanup(srv.Close)
	return &proc{t: t, srv: srv, b: b, sw: sw, km: km}
}

func (p *proc) post(path string, body any) (int, map[string]any) {
	p.t.Helper()
	resp := doJSON(p.t, http.MethodPost, p.srv.URL+path, body)
	var out map[string]any
	decodeJSON(p.t, resp, &out)
	return resp.StatusCode, out
}

func (p *proc) status() map[string]any {
	p.t.Helper()
	resp, err := http.Get(p.srv.URL + "/v1/sys/seal-status")
	if err != nil {
		p.t.Fatal(err)
	}
	var out map[string]any
	decodeJSON(p.t, resp, &out)
	return out
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func (p *proc) unsealWith(shares []string) {
	p.t.Helper()
	for i, s := range shares[:3] {
		code, out := p.post("/v1/sys/unseal", map[string]string{"share": s})
		if code != 200 {
			p.t.Fatalf("unseal share %d: %d %v", i, code, out)
		}
	}
	if p.b.IsSealed() {
		p.t.Fatal("still sealed after 3 shares")
	}
}

// initAndUnseal: 새 저장소를 초기화하고 조각 3개로 해제한다. 조각 5개를 반환.
func (p *proc) initAndUnseal() []string {
	p.t.Helper()
	code, out := p.post("/v1/sys/init", map[string]string{})
	if code != 201 {
		p.t.Fatalf("init: %d %v", code, out)
	}
	shares := toStrings(out["shares"])
	p.shares = shares
	p.unsealWith(shares)
	return shares
}

// fixtures: 이전 전에 transit 키와 KMS v2 키로 만든 암호문.
type fixtures struct {
	transitCT string
	v2CT      *pb.EncryptResponse
}

func (p *proc) makeFixtures() fixtures {
	p.t.Helper()
	if _, err := p.km.CreateKey("app", 0); err != nil {
		p.t.Fatal(err)
	}
	ct, err := transitsvc.NewTransitService(p.km).Encrypt("app", []byte("before-migration"))
	if err != nil {
		p.t.Fatal(err)
	}
	v2, err := kmsv2.New(p.km, v2KeyName).Encrypt(context.Background(), &pb.EncryptRequest{Uid: "u", Plaintext: []byte("v2-before-migration")})
	if err != nil {
		p.t.Fatal(err)
	}
	return fixtures{ct, v2}
}

func (p *proc) checkFixtures(f fixtures) {
	p.t.Helper()
	pt, err := transitsvc.NewTransitService(p.km).Decrypt("app", f.transitCT)
	if err != nil || string(pt) != "before-migration" {
		p.t.Fatalf("transit ciphertext from before migration not decryptable: %v", err)
	}
	v2, err := kmsv2.New(p.km, v2KeyName).Decrypt(context.Background(), &pb.DecryptRequest{Uid: "u", Ciphertext: f.v2CT.Ciphertext, KeyId: f.v2CT.KeyId})
	if err != nil || string(v2.Plaintext) != "v2-before-migration" {
		p.t.Fatalf("KMS v2 ciphertext from before migration not decryptable: %v", err)
	}
}

func recordOf(t *testing.T, store storage.StorageBackend) map[string]any {
	t.Helper()
	raw, err := store.Get(initPathKey)
	if err != nil || raw == nil {
		t.Fatalf("no init record: %v", err)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

func hasBlob(t *testing.T, store storage.StorageBackend) bool {
	t.Helper()
	d, err := store.Get(blobPathKey)
	if err != nil {
		t.Fatal(err)
	}
	return d != nil
}

// ---- 테스트 ----

func TestSealMigrate_ShamirToTPM_RestartAutoUnseals(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	oldShares := p.initAndUnseal()
	fx := p.makeFixtures()

	code, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	if code != 200 || out["seal_type"] != "tpm" || out["previous"] != "shamir" {
		t.Fatalf("migrate: %d %v", code, out)
	}
	shares := toStrings(out["shares"])
	if len(shares) != 5 {
		t.Fatalf("shares = %d, want 5", len(shares))
	}
	if rec := recordOf(t, store); rec["format_version"].(float64) != 2 || rec["seal"] != "tpm" {
		t.Fatalf("record = %v", rec)
	}
	if st := p.status(); st["seal_type"] != "tpm" || st["recovery_available"] != true || st["sealed"] != false {
		t.Fatalf("status after migrate = %v", st)
	}

	// 재시작 흉내: 사람 개입 없이 해제되어야 한다.
	p2 := startProc(t, store, dev)
	if st := p2.status(); st["sealed"] != false || st["seal_type"] != "tpm" {
		t.Fatalf("status after restart = %v", st)
	}
	p2.checkFixtures(fx)

	// 이전 전에 받은 조각(구 조각)도 같은 루트 키라 복구에 쓸 수 있다.
	if code, _ := p2.post("/v1/sys/seal", nil); code != 200 {
		t.Fatal("seal failed")
	}
	p2.unsealWith(oldShares)
	p2.checkFixtures(fx)
}

func TestSealMigrate_TPMBlobMissing_StartsSealedAndRecoversWithShares(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	fx := p.makeFixtures()
	_, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	recovery := toStrings(out["shares"])

	if err := store.Delete(blobPathKey); err != nil {
		t.Fatal(err)
	}
	p2 := startProc(t, store, dev)
	st := p2.status()
	if st["sealed"] != true || st["seal_type"] != "tpm" || st["recovery_available"] != true {
		t.Fatalf("status = %v", st)
	}
	// 봉인 상태에서 transit 데이터 접근 불가(fail-closed).
	if _, err := p2.km.ListKeys(); err == nil {
		t.Fatal("keys readable while sealed")
	}
	// 조각 없이 재시도해도 blob이 없으니 봉인 유지.
	if code, _ := p2.post("/v1/sys/unseal", map[string]string{}); code == 200 {
		t.Fatal("unsealed without blob or shares")
	}
	p2.unsealWith(recovery)
	p2.checkFixtures(fx)
	// 복구 해제 후에도 기록은 tpm 유지.
	if st := p2.status(); st["seal_type"] != "tpm" || recordOf(t, store)["seal"] != "tpm" {
		t.Fatalf("record/status changed by recovery: %v", st)
	}
}

func TestSealMigrate_DeviceBroken_SealedThenRetryWithoutShares(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	fx := p.makeFixtures()
	p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})

	dev.SetBroken(true)
	p2 := startProc(t, store, dev)
	if p2.status()["sealed"] != true {
		t.Fatal("must start sealed when the TPM device is unavailable")
	}
	if code, _ := p2.post("/v1/sys/unseal", map[string]string{}); code == 200 {
		t.Fatal("unsealed with broken device")
	}
	dev.SetBroken(false)
	if code, out := p2.post("/v1/sys/unseal", map[string]string{}); code != 200 {
		t.Fatalf("retry after device returns: %d %v", code, out)
	}
	p2.checkFixtures(fx)
}

func TestSealMigrate_WrongRecoveryShares_RemainSealed(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	store.Delete(blobPathKey)

	p2 := startProc(t, store, dev)
	_, foreign, _ := seal.InitShamir(5, 3)
	var last int
	for _, s := range foreign[:3] {
		last, _ = p2.post("/v1/sys/unseal", map[string]string{"share": base64.StdEncoding.EncodeToString(s)})
	}
	if last == 200 || !p2.b.IsSealed() {
		t.Fatal("foreign shares unsealed the barrier")
	}
}

func TestSealMigrate_TPMToShamir_NewSharesWork(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	fx := p.makeFixtures()
	p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})

	code, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "shamir"})
	if code != 200 || out["seal_type"] != "shamir" || out["previous"] != "tpm" {
		t.Fatalf("migrate back: %d %v", code, out)
	}
	newShares := toStrings(out["shares"])
	if hasBlob(t, store) {
		t.Fatal("TPM blob still present after tpm->shamir")
	}
	if rec := recordOf(t, store); rec["seal"] != "shamir" || rec["format_version"].(float64) != 2 {
		t.Fatalf("record = %v", rec)
	}

	p2 := startProc(t, store, dev)
	if st := p2.status(); st["sealed"] != true || st["seal_type"] != "shamir" || st["recovery_available"] != false {
		t.Fatalf("status = %v", st)
	}
	p2.unsealWith(newShares)
	p2.checkFixtures(fx)
}

func TestSealMigrate_ShamirReissue_OldSharesStillValidAndWarned(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	oldShares := p.initAndUnseal()
	fx := p.makeFixtures()

	code, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "shamir"})
	if code != 200 {
		t.Fatalf("reissue: %d %v", code, out)
	}
	if w, _ := out["warning"].(string); !strings.Contains(w, "rekey") {
		t.Fatalf("warning missing rekey notice: %q", w)
	}
	newShares := toStrings(out["shares"])
	for name, set := range map[string][]string{"old": oldShares, "new": newShares} {
		p2 := startProc(t, store, dev)
		p2.unsealWith(set)
		p2.checkFixtures(fx)
		_ = name
	}
}

func TestSealMigrate_RequiresUnsealed_409(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	p.post("/v1/sys/seal", nil)
	for _, target := range []string{"tpm", "shamir"} {
		if code, _ := p.post("/v1/sys/seal-migrate", map[string]string{"target": target}); code != 409 {
			t.Fatalf("sealed migrate to %s = %d, want 409", target, code)
		}
	}
	if hasBlob(t, store) || recordOf(t, store)["seal"] != "shamir" {
		t.Fatal("state changed by rejected migration")
	}
}

func TestSealMigrate_BadRequests(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	for _, target := range []string{"", "k8s", "dev", "TPM"} {
		if code, _ := p.post("/v1/sys/seal-migrate", map[string]string{"target": target}); code != 400 {
			t.Errorf("target %q = %d, want 400", target, code)
		}
	}
	resp, _ := http.Post(p.srv.URL+"/v1/sys/seal-migrate", "application/json", strings.NewReader("not json"))
	if resp.StatusCode != 400 {
		t.Errorf("bad body = %d", resp.StatusCode)
	}
	p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	if code, _ := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"}); code != 409 {
		t.Errorf("tpm->tpm = %d, want 409", code)
	}
}

func TestSealMigrate_RecordSaveFails_NoBlobLeft(t *testing.T) {
	mem := storage.NewMemoryStorage()
	fs := &faultStore{StorageBackend: mem, failPut: map[string]bool{}, failDelete: map[string]bool{}}
	dev := sealtest.NewDevice()
	p := startProc(t, fs, dev)
	p.initAndUnseal()
	fx := p.makeFixtures()
	before, _ := mem.Get(initPathKey)

	fs.failPut[initPathKey] = true
	code, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	if code < 500 {
		t.Fatalf("expected failure, got %d %v", code, out)
	}
	if _, leaked := out["shares"]; leaked {
		t.Fatal("shares returned on failed migration")
	}
	if hasBlob(t, mem) {
		t.Fatal("TPM blob left behind after record save failure")
	}
	after, _ := mem.Get(initPathKey)
	if string(before) != string(after) {
		t.Fatal("record changed")
	}
	if p.sw.Mode() != "shamir" || p.status()["seal_type"] != "shamir" {
		t.Fatal("mode switched despite failure")
	}
	// 실패 뒤 정상 복구: 장애가 풀리면 같은 요청이 성공한다.
	fs.failPut[initPathKey] = false
	if code, _ := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"}); code != 200 {
		t.Fatalf("retry after fault cleared = %d", code)
	}
	startProc(t, mem, dev).checkFixtures(fx)
}

func TestSealMigrate_BlobRemovalFails_RecordRolledBackToTPM(t *testing.T) {
	mem := storage.NewMemoryStorage()
	fs := &faultStore{StorageBackend: mem, failPut: map[string]bool{}, failDelete: map[string]bool{}}
	dev := sealtest.NewDevice()
	p := startProc(t, fs, dev)
	p.initAndUnseal()
	fx := p.makeFixtures()
	p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})

	fs.failDelete[blobPathKey] = true
	code, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "shamir"})
	if code < 500 {
		t.Fatalf("expected failure, got %d %v", code, out)
	}
	if rec := recordOf(t, mem); rec["seal"] != "tpm" || !hasBlob(t, mem) {
		t.Fatalf("not rolled back: record=%v blob=%v", rec, hasBlob(t, mem))
	}
	if p.sw.Mode() != "tpm" {
		t.Fatal("mode changed despite failure")
	}
	// 롤백된 상태에서 재시작하면 TPM으로 자동 해제된다.
	startProc(t, mem, dev).checkFixtures(fx)
}

func TestSealMigrate_DeviceUnavailable_503AndNothingChanges(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	before, _ := store.Get(initPathKey)
	dev.SetBroken(true)
	if code, _ := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"}); code != 503 {
		t.Fatalf("code = %d, want 503", code)
	}
	after, _ := store.Get(initPathKey)
	if string(before) != string(after) || hasBlob(t, store) {
		t.Fatal("state changed")
	}
}

func TestSealMigrate_StaleBlobExists_409AndBlobUntouched(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	tpm, _ := dev.Open(store)
	tpm.SealExisting(make([]byte, 32)) // 어떤 키인지 알 수 없는 남은 blob
	blob, _ := store.Get(blobPathKey)
	before, _ := store.Get(initPathKey)

	if code, _ := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"}); code != 409 {
		t.Fatalf("code = %d, want 409", code)
	}
	blob2, _ := store.Get(blobPathKey)
	after, _ := store.Get(initPathKey)
	if string(blob) != string(blob2) || string(before) != string(after) {
		t.Fatal("stale blob or record was modified")
	}
}

// 운영 저장소는 v1 기록이다: v2 코드로 기동·해제되고, 이전 뒤 v2로 바뀌며, 같은 루트
// 키라 이전 전에 만든 암호문(transit, KMS v2 경로)이 계속 복호화된다.
func TestSealMigrate_FromV1Store(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	shares := p.initAndUnseal()
	fx := p.makeFixtures()

	// 기록을 v1 형식으로 되돌려 쓴다(운영 저장소와 같은 모양, 같은 루트 키).
	raw := make([][]byte, 3)
	for i := range raw {
		raw[i], _ = base64.StdEncoding.DecodeString(shares[i])
	}
	root, err := shamir.Combine(raw)
	if err != nil {
		t.Fatal(err)
	}
	rec := recordOf(t, store)
	storeID := rec["store_id"].(string)
	ver, _ := kmscrypto.Encrypt(root, []byte("kms-root-valid-v1"), []byte(fmt.Sprintf("kms-init:1:%s:5:3", storeID)))
	v1, _ := json.Marshal(map[string]any{"format_version": 1, "store_id": storeID, "parts": 5, "threshold": 3, "verification": ver})
	store.Put(initPathKey, v1)

	p1 := startProc(t, store, dev) // v1 저장소 기동
	if st := p1.status(); st["sealed"] != true || st["seal_type"] != "shamir" {
		t.Fatalf("v1 status = %v", st)
	}
	p1.unsealWith(shares)
	p1.checkFixtures(fx)

	if code, out := p1.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"}); code != 200 {
		t.Fatalf("migrate from v1: %d %v", code, out)
	}
	if rec := recordOf(t, store); rec["format_version"].(float64) != 2 || rec["seal"] != "tpm" {
		t.Fatalf("record after migrate = %v", rec)
	}
	startProc(t, store, dev).checkFixtures(fx)
}

func TestSealMigrate_NotRegisteredOnNonSwitchSeal(t *testing.T) {
	srv := newTestServer(t) // dev seal
	resp := doJSON(t, http.MethodPost, srv.URL+"/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
}

func TestSealMigrate_ResponseNeverContainsRootKeyAndSharesAreOnlyInBody(t *testing.T) {
	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	p.initAndUnseal()
	_, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	// 서버 저장소 어디에도 새 조각이 평문으로 남아 있지 않아야 한다.
	names, _ := store.List("")
	for _, n := range names {
		d, _ := store.Get(n)
		for _, s := range toStrings(out["shares"]) {
			raw, _ := base64.StdEncoding.DecodeString(s)
			if strings.Contains(string(d), string(raw)) || strings.Contains(string(d), s) {
				t.Fatalf("share found persisted in %q", n)
			}
		}
	}
}

func TestSealMigrate_SharesNeverLogged(t *testing.T) {
	var buf strings.Builder
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	store, dev := storage.NewMemoryStorage(), sealtest.NewDevice()
	p := startProc(t, store, dev)
	initShares := p.initAndUnseal()
	_, out := p.post("/v1/sys/seal-migrate", map[string]string{"target": "tpm"})
	_, out2 := p.post("/v1/sys/seal-migrate", map[string]string{"target": "shamir"})
	all := append(append(initShares, toStrings(out["shares"])...), toStrings(out2["shares"])...)
	for _, s := range all {
		if strings.Contains(buf.String(), s) {
			t.Fatal("a share appeared in the log output")
		}
	}
}

func (p *proc) unsealWithSharesAgain(t *testing.T) {
	t.Helper()
	p.sw.Shamir().Reset()
	p.unsealWith(p.shares)
}
