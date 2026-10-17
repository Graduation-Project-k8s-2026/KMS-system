package admin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	apitransit "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/kmsv2"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/rotation"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal/sealtest"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	transitsvc "github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
	pb "k8s.io/kms/apis/v2"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func lifecycleProc(t *testing.T) (*proc, *kmsv2.Service) {
	t.Helper()
	p := startProc(t, storage.NewMemoryStorage(), sealtest.NewDevice())
	v2 := kmsv2.New(p.km, v2KeyName) // 생성자가 v2 키를 보호 키로 등록한다
	p.initAndUnseal()
	return p, v2
}

func TestKeyLifecycleAPI_StatesAndResponses(t *testing.T) {
	p, _ := lifecycleProc(t)
	p.post("/v1/keys", map[string]any{"name": "app"})

	code, out := p.post("/v1/keys/app/disable", nil)
	if code != 200 || out["state"] != "disabled" {
		t.Fatalf("disable: %d %v", code, out)
	}
	if code, out = p.post("/v1/keys/app/schedule-deletion", map[string]int{"pending_days": 3}); code != 400 || out["error"] != "invalid_request" {
		t.Fatalf("3 days: %d %v", code, out)
	}
	if code, out = p.post("/v1/keys/app/schedule-deletion", map[string]int{"pending_days": 31}); code != 400 {
		t.Fatalf("31 days: %d %v", code, out)
	}
	resp, _ := http.Post(p.srv.URL+"/v1/keys/app/schedule-deletion", "application/json", strings.NewReader("")) // 본문 생략 = 30일
	var meta map[string]any
	decodeJSON(t, resp, &meta)
	if resp.StatusCode != 200 || meta["state"] != "pending_deletion" || meta["deletion_date"] == nil {
		t.Fatalf("schedule default: %d %v", resp.StatusCode, meta)
	}
	date, _ := time.Parse(time.RFC3339, meta["deletion_date"].(string))
	if d := time.Until(date); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("default deletion date = %v from now", d)
	}
	if code, out = p.post("/v1/keys/app/enable", nil); code != 409 || out["error"] != "invalid_state" {
		t.Fatalf("enable while pending: %d %v", code, out)
	}
	if code, out = p.post("/v1/keys/app/cancel-deletion", nil); code != 200 || out["state"] != "disabled" || out["deletion_date"] != nil {
		t.Fatalf("cancel: %d %v", code, out)
	}
	if code, out = p.post("/v1/keys/app/enable", nil); code != 200 || out["state"] != "active" {
		t.Fatalf("enable: %d %v", code, out)
	}
	// GET 조회에 state가 들어간다
	r2, _ := http.Get(p.srv.URL + "/v1/keys/app")
	decodeJSON(t, r2, &meta)
	if meta["state"] != "active" {
		t.Fatalf("GET meta = %v", meta)
	}
	if code, out = p.post("/v1/keys/nope/disable", nil); code != 404 || out["error"] != "key_not_found" {
		t.Fatalf("missing: %d %v", code, out)
	}
}

func TestKeyLifecycleAPI_ProtectedKeysAndKMSv2PathUnaffected(t *testing.T) {
	p, v2 := lifecycleProc(t)
	p.km.Protect("extra") // KMS_PROTECTED_KEYS
	p.post("/v1/keys", map[string]any{"name": "extra"})

	for _, k := range []string{v2KeyName, "extra"} {
		for _, op := range []string{"disable", "schedule-deletion"} {
			if code, out := p.post("/v1/keys/"+k+"/"+op, nil); code != 409 || out["error"] != "key_protected" {
				t.Fatalf("%s %s: %d %v", k, op, code, out)
			}
		}
	}
	// 보호 키는 enable/cancel 같은 무해한 호출이 와도 active로 남고 KMS v2 경로가 계속 동작한다.
	ctx := context.Background()
	enc, err := v2.Encrypt(ctx, &pb.EncryptRequest{Uid: "u", Plaintext: []byte("cluster-secret")})
	if err != nil {
		t.Fatalf("KMS v2 encrypt: %v", err)
	}
	dec, err := v2.Decrypt(ctx, &pb.DecryptRequest{Uid: "u", Ciphertext: enc.Ciphertext, KeyId: enc.KeyId})
	if err != nil || string(dec.Plaintext) != "cluster-secret" {
		t.Fatalf("KMS v2 decrypt: %v", err)
	}
	if st, err := v2.Status(ctx, &pb.StatusRequest{}); err != nil || st.Healthz != "ok" {
		t.Fatalf("KMS v2 status: %v", err)
	}
}

// KMS v2 경로(apiserver → 유닉스 소켓)는 SAR/인증을 거치지 않는다: Transit이 모든 요청을 거부(SAR 전부
// 거부)하는 상황에서도, 키 상태 변경·감사·오류 형식 변경과 무관하게 암복호화가 된다.
func TestKMSv2PathIndependentOfTransitAuthzAndLifecycle(t *testing.T) {
	p, v2 := lifecycleProc(t)
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		sar.Status.Allowed = false // 전부 거부
		return true, sar, nil
	})
	alog, _ := audit.NewTransit(t.TempDir(), 16, time.Second)
	defer alog.Close()
	tr := apitransit.NewRouter(apitransit.Deps{
		ReservedKey: v2KeyName, Barrier: p.b, Transit: transitsvc.NewTransitService(p.km), Audit: alog,
		Authorizer: authz.NewAuthorizer(client.AuthorizationV1().SubjectAccessReviews(), authz.Config{}),
	})
	withID := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr.ServeHTTP(w, r.WithContext(authn.WithIdentity(r.Context(), authn.Identity{Namespace: "x", ServiceAccount: "y", Subject: "system:serviceaccount:x:y"})))
	})
	ts := httptest.NewServer(withID)
	defer ts.Close()

	// 데이터 평면에서는 v2 키 이름이 거부되고(예약 키), 다른 키도 SAR 거부로 403.
	for _, k := range []string{v2KeyName, "app", "team-a.app"} {
		resp := doJSON(t, http.MethodPost, ts.URL+"/v1/encrypt/"+k, map[string]string{"plaintext": "AA=="})
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("transit %s = %d, want 403", k, resp.StatusCode)
		}
	}
	// 그런데도 KMS v2 서비스는 정상이다.
	enc, err := v2.Encrypt(context.Background(), &pb.EncryptRequest{Uid: "u", Plaintext: []byte("still-works")})
	if err != nil {
		t.Fatalf("KMS v2 encrypt while transit denies everything: %v", err)
	}
	if dec, err := v2.Decrypt(context.Background(), &pb.DecryptRequest{Uid: "u", Ciphertext: enc.Ciphertext, KeyId: enc.KeyId}); err != nil || string(dec.Plaintext) != "still-works" {
		t.Fatalf("KMS v2 decrypt: %v", err)
	}
	// 키 회전 뒤에도 이전 KMS v2 암호문이 복호화된다 (키 상태 기능이 버전 정책을 건드리지 않음).
	p.post("/v1/keys/"+v2KeyName+"/rotate", nil)
	if _, err := v2.Decrypt(context.Background(), &pb.DecryptRequest{Uid: "u", Ciphertext: enc.Ciphertext, KeyId: enc.KeyId}); err != nil {
		t.Fatalf("KMS v2 decrypt after rotation: %v", err)
	}
}

func TestTransitRejectsInactiveKeysWith409(t *testing.T) {
	p, _ := lifecycleProc(t)
	p.post("/v1/keys", map[string]any{"name": "app"})
	tr := httptest.NewServer(apitransit.NewRouter(apitransit.Deps{Barrier: p.b, Transit: transitsvc.NewTransitService(p.km)}))
	defer tr.Close()
	ct, err := transitsvc.NewTransitService(p.km).Encrypt("app", []byte("x")) // 비활성화 전에 만든 진짜 암호문
	if err != nil {
		t.Fatal(err)
	}
	enc := func(op string) (int, map[string]any) {
		var out map[string]any
		resp := doJSON(t, http.MethodPost, tr.URL+"/v1/"+op+"/app", map[string]string{"plaintext": "AA==", "ciphertext": ct})
		decodeJSON(t, resp, &out)
		return resp.StatusCode, out
	}
	if code, _ := enc("encrypt"); code != 200 {
		t.Fatalf("active encrypt = %d", code)
	}
	p.post("/v1/keys/app/disable", nil)
	for _, op := range []string{"encrypt", "decrypt", "rewrap"} {
		if code, out := enc(op); code != 409 || out["error"] != "key_not_active" {
			t.Fatalf("%s on disabled: %d %v", op, code, out)
		}
	}
	p.post("/v1/keys/app/enable", nil)
	if code, _ := enc("encrypt"); code != 200 {
		t.Fatalf("re-enabled encrypt = %d", code)
	}
}

func TestReaperPurgesAfterGraceAndStopsWhenSealed(t *testing.T) {
	p, _ := lifecycleProc(t)
	now := time.Now()
	p.km.SetClock(func() time.Time { return now })
	p.post("/v1/keys", map[string]any{"name": "doomed"})
	p.post("/v1/keys/doomed/schedule-deletion", map[string]int{"pending_days": 7})

	var events []string
	r := rotation.NewReaper(p.km, time.Hour,
		func(n string) error { events = append(events, "before:"+n); return nil },
		func(n string) { events = append(events, "after:"+n) })
	if names, err := r.Tick(); err != nil || len(names) != 0 {
		t.Fatalf("early tick: %v %v", names, err)
	}
	now = now.Add(8 * 24 * time.Hour)
	p.b.Seal()
	if _, err := r.Tick(); err == nil {
		t.Fatal("tick while sealed must not delete")
	}
	p.unsealWithSharesAgain(t)
	if names, err := r.Tick(); err != nil || len(names) != 1 {
		t.Fatalf("tick after grace: %v %v", names, err)
	}
	if strings.Join(events, ",") != "before:doomed,after:doomed" {
		t.Fatalf("events = %v", events)
	}
	if code, _ := p.post("/v1/keys/doomed/disable", nil); code != 404 {
		t.Fatalf("purged key still exists: %d", code)
	}
}
