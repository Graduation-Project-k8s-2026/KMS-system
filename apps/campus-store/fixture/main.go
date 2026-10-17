//go:build campusstorelab

// A loopback-only, isolated integration fixture. It uses the repository's real
// Transit, key, barrier, JWT and SAR middleware. Only the Kubernetes SAR backend
// is fake; this is NOT proof of an operating cluster's RBAC configuration.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	api "github.com/Graduation-Project-k8s-2026/KMS-system/internal/api/transit"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/transit"
	"github.com/golang-jwt/jwt/v5"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func main() {
	dir := flag.String("dir", "", "private temporary fixture directory")
	flag.Parse()
	if *dir == "" {
		log.Fatal("--dir required")
	}
	must(os.MkdirAll(*dir, 0700))
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	verifier := authn.NewVerifier([]crypto.PublicKey{&rsaKey.PublicKey}, authn.Config{Strict: true, Issuer: "campus-local-fixture", Audience: "kms-system"})
	client := fake.NewSimpleClientset()
	// C+B 모델: campus-shipping은 점 없는 전역 키라 SAR namespace가 ""(클러스터 범위)로 온다 —
	// ClusterRoleBinding만 효력이 있다는 운영 규칙을 그대로 흉내 낸다.
	permissions := map[string]string{"checkout": "encrypt", "shipping": "decrypt", "migration": "rewrap"}
	client.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (bool, runtime.Object, error) {
		sar := action.(ktesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		a := sar.Spec.ResourceAttributes
		for user, verb := range permissions {
			if a != nil && a.Group == "kms.local" && a.Resource == "keys" && a.Namespace == "" && a.Name == "campus-shipping" && a.Verb == verb && sar.Spec.User == "system:serviceaccount:campus-store:"+user {
				sar.Status.Allowed = true
			}
		}
		return true, sar, nil
	})
	authorizer := authz.NewAuthorizer(client.AuthorizationV1().SubjectAccessReviews(), authz.Config{TTL: -1})
	sealer := seal.NewDevSeal("isolated-campus-fixture-only")
	b := barrier.NewBarrier(storage.NewMemoryStorage(), sealer)
	must(b.Unseal())
	km := keys.NewKeyManager(b)
	_, err = km.CreateKey("campus-shipping", 0)
	must(err)
	router := api.NewRouter(api.Deps{Barrier: b, Transit: transit.NewTransitService(km), Seal: sealer, Verifier: verifier, Authorizer: authorizer, ReservedKey: "k8s-secrets"})
	random := make([]byte, 32)
	_, err = rand.Read(random)
	must(err)
	control := hex.EncodeToString(random)
	must(os.WriteFile(filepath.Join(*dir, "control.token"), []byte(control), 0600))
	mux := http.NewServeMux()
	mux.Handle("/", router)
	mux.HandleFunc("POST /lab/{action}", func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+control)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		var e error
		switch r.PathValue("action") {
		case "rotate":
			_, e = km.RotateKey("campus-shipping")
		case "minimum2":
			n := 2
			_, e = km.UpdateConfig("campus-shipping", &n, nil)
		case "seal":
			b.Seal()
		case "unseal":
			e = b.Unseal()
		default:
			http.NotFound(w, r)
			return
		}
		if e != nil {
			http.Error(w, "fixture operation failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	cert := srv.TLS.Certificates[0]
	must(os.WriteFile(filepath.Join(*dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600))
	privateDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	must(err)
	must(os.WriteFile(filepath.Join(*dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0600))
	for _, user := range []string{"checkout", "shipping", "marketing", "migration"} {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{Issuer: "campus-local-fixture", Audience: jwt.ClaimStrings{"kms-system"}, Subject: "system:serviceaccount:campus-store:" + user, ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour))})
		signed, e := token.SignedString(rsaKey)
		must(e)
		must(os.WriteFile(filepath.Join(*dir, user+".token"), []byte(signed), 0600))
	}
	ready, _ := json.Marshal(map[string]string{"url": srv.URL, "scope": "real KMS core + JWT/SAR middleware; simulated Kubernetes SAR; no production access"})
	must(os.WriteFile(filepath.Join(*dir, "ready.json"), ready, 0600))
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
