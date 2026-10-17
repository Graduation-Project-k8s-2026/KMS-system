package transit_test

import (
	"bytes"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/audit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
)

type dk struct {
	Ciphertext string `json:"ciphertext"`
	Plaintext  string `json:"plaintext"`
	KeyVersion int    `json:"key_version"`
}

func TestDataKey_RoundTripViaDecrypt(t *testing.T) {
	srv, km, dir, alog := auditEnv(t, newFakeAuthorizer(t, true))
	km.CreateKey("team-a.pay", 0)
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	defer log.SetOutput(prev)

	// 기본값: 256비트 + 평문 포함
	var out dk
	resp := doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/team-a.pay", map[string]any{})
	decodeJSON(t, resp, &out)
	if resp.StatusCode != 200 || !strings.HasPrefix(out.Ciphertext, "kms:v1:") || out.KeyVersion != 1 {
		t.Fatalf("datakey = %d %+v", resp.StatusCode, out)
	}
	key, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil || len(key) != 32 {
		t.Fatalf("plaintext key len = %d (%v), want 32", len(key), err)
	}
	// 기존 decrypt로 같은 키를 되찾는다
	var dec struct{ Plaintext string }
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/team-a.pay", map[string]string{"ciphertext": out.Ciphertext})
	decodeJSON(t, resp, &dec)
	if dec.Plaintext != out.Plaintext {
		t.Fatal("decrypt did not return the same data key")
	}
	// 128비트, plaintext=false
	var small dk
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/team-a.pay", map[string]any{"bits": 128})
	decodeJSON(t, resp, &small)
	if k, _ := base64.StdEncoding.DecodeString(small.Plaintext); len(k) != 16 {
		t.Fatalf("128-bit key len = %d", len(k))
	}
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/team-a.pay", map[string]any{"plaintext": false})
	raw := decodeRaw(t, resp)
	if _, has := raw["plaintext"]; has || raw["ciphertext"] == nil {
		t.Fatalf("plaintext=false response = %v", raw)
	}
	// 키 두 번 호출하면 서로 다른 키
	var again dk
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/team-a.pay", map[string]any{})
	decodeJSON(t, resp, &again)
	if again.Plaintext == out.Plaintext {
		t.Fatal("data keys must be unique")
	}
	// 잘못된 bits
	resp = doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/team-a.pay", map[string]any{"bits": 512})
	wantError(t, resp, 400, "invalid_request")

	// 평문 키는 감사 파일·로그 어디에도 없다
	alog.Close()
	files, _ := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	auditRaw, _ := os.ReadFile(files[0])
	for _, secret := range []string{out.Plaintext, small.Plaintext, again.Plaintext} {
		if secret == "" {
			continue
		}
		if strings.Contains(string(auditRaw), secret) || strings.Contains(logBuf.String(), secret) {
			t.Fatal("plaintext data key leaked into audit or log")
		}
	}
	evs, _ := audit.ReadTransitToday(dir)
	if len(evs) == 0 || evs[0].Action != "datakey" || evs[0].Key != "team-a.pay" || evs[0].SARNamespace != "team-a" {
		t.Fatalf("audit = %+v", evs)
	}
}

func TestDataKey_AfterRotationOldCiphertextStillDecrypts(t *testing.T) {
	srv, km, _, _ := auditEnv(t, newFakeAuthorizer(t, true))
	km.CreateKey("k", 0)
	var old dk
	decodeJSON(t, doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/k", map[string]any{}), &old)
	km.RotateKey("k")
	var neu dk
	decodeJSON(t, doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/k", map[string]any{}), &neu)
	if neu.KeyVersion != 2 || !strings.HasPrefix(neu.Ciphertext, "kms:v2:") {
		t.Fatalf("new datakey = %+v", neu)
	}
	var dec struct{ Plaintext string }
	decodeJSON(t, doJSON(t, http.MethodPost, srv.URL+"/v1/decrypt/k", map[string]string{"ciphertext": old.Ciphertext}), &dec)
	if dec.Plaintext != old.Plaintext {
		t.Fatal("pre-rotation data key must still decrypt")
	}
}

func TestDataKey_DeniedInactiveAndVerb(t *testing.T) {
	// 403: 권한 없음
	srv, km, _, _ := auditEnv(t, newFakeAuthorizer(t, false))
	km.CreateKey("k", 0)
	wantError(t, doJSON(t, http.MethodPost, srv.URL+"/v1/datakey/k", map[string]any{}), 403, "forbidden")

	// SAR에는 verb "datakey"와 키 소유 네임스페이스가 실린다
	var mu sync.Mutex
	var verbs, nss []string
	client := fake.NewSimpleClientset()
	client.Fake.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		sar := a.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		mu.Lock()
		verbs = append(verbs, sar.Spec.ResourceAttributes.Verb)
		nss = append(nss, sar.Spec.ResourceAttributes.Namespace)
		mu.Unlock()
		sar.Status.Allowed = true
		return true, sar, nil
	})
	srv2, km2, _, _ := auditEnv(t, authz.NewAuthorizer(client.AuthorizationV1().SubjectAccessReviews(), authz.Config{TTL: -1}))
	km2.CreateKey("team-a.k", 0)
	km2.CreateKey("global", 0)
	doJSON(t, http.MethodPost, srv2.URL+"/v1/datakey/team-a.k", map[string]any{}).Body.Close()
	doJSON(t, http.MethodPost, srv2.URL+"/v1/datakey/global", map[string]any{}).Body.Close()
	if strings.Join(verbs, ",") != "datakey,datakey" || strings.Join(nss, ",") != "team-a," {
		t.Fatalf("SAR verbs=%v namespaces=%v", verbs, nss)
	}

	// 409: 비활성
	srv3, km3, _, _ := auditEnv(t, newFakeAuthorizer(t, true))
	km3.CreateKey("k", 0)
	km3.DisableKey("k")
	wantError(t, doJSON(t, http.MethodPost, srv3.URL+"/v1/datakey/k", map[string]any{}), 409, "key_not_active")
	wantError(t, doJSON(t, http.MethodPost, srv3.URL+"/v1/datakey/missing", map[string]any{}), 404, "key_not_found")
}
