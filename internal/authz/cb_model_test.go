package authz_test

import (
	"context"
	"sync"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authn"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/authz"
)

// grant: RBAC 한 줄을 흉내 낸다. ns가 ""이면 ClusterRoleBinding(클러스터 전체),
// 아니면 그 네임스페이스의 RoleBinding이다.
type grant struct{ ns, subject, key, verb string }

// rbacReactor: 쿠버네티스 RBAC의 핵심 규칙만 구현한 가짜 apiserver.
//   - 요청 namespace가 ""(클러스터 범위)이면 ClusterRoleBinding만 효력.
//   - 요청 namespace가 있으면 그 네임스페이스의 RoleBinding 또는 ClusterRoleBinding이 효력.
type rbacReactor struct {
	mu     sync.Mutex
	grants []grant
	seenNS []string // SAR에 실린 namespace 기록
}

func (r *rbacReactor) react(action k8stesting.Action) (bool, runtime.Object, error) {
	sar := action.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
	ra := sar.Spec.ResourceAttributes
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seenNS = append(r.seenNS, ra.Namespace)
	allowed := false
	for _, g := range r.grants {
		if g.subject == sar.Spec.User && g.key == ra.Name && g.verb == ra.Verb && (g.ns == "" || g.ns == ra.Namespace) {
			allowed = true
		}
	}
	sar.Status = authorizationv1.SubjectAccessReviewStatus{Allowed: allowed}
	return true, sar, nil
}

func id(ns, sa string) authn.Identity {
	return authn.Identity{Namespace: ns, ServiceAccount: sa, Subject: "system:serviceaccount:" + ns + ":" + sa}
}

func TestCB_OwnedKey_OnlyOwnerNamespaceBindingCounts(t *testing.T) {
	teamB := id("team-b", "worker")
	rb := &rbacReactor{grants: []grant{
		{ns: "team-a", subject: teamB.Subject, key: "team-a.payment", verb: "encrypt"}, // 소유 팀이 team-b SA를 허용
		{ns: "team-b", subject: teamB.Subject, key: "team-a.ledger", verb: "encrypt"},  // 엉뚱한 네임스페이스의 Role
	}}
	a := newFakeAuthorizer(t, rb.react, authz.Config{})
	ctx := context.Background()

	if !a.Allowed(ctx, teamB, "team-a.payment", "encrypt") {
		t.Fatal("cross-namespace SA listed in the owner's RoleBinding must be allowed")
	}
	if a.Allowed(ctx, teamB, "team-a.ledger", "encrypt") {
		t.Fatal("Role in a non-owner namespace must not grant access (403)")
	}
	if a.Allowed(ctx, teamB, "team-a.payment", "decrypt") {
		t.Fatal("verb not granted must be denied")
	}
	for _, ns := range rb.seenNS {
		if ns != "team-a" {
			t.Fatalf("SAR namespace = %q, want owner namespace team-a", ns)
		}
	}
}

func TestCB_GlobalKey_OnlyClusterBindingCounts(t *testing.T) {
	sa := id("team-a", "app")
	rb := &rbacReactor{grants: []grant{
		{ns: "team-a", subject: sa.Subject, key: "shared", verb: "encrypt"}, // 네임스페이스 Role: 전역 키에는 효력 없음
		{ns: "", subject: sa.Subject, key: "shared", verb: "decrypt"},       // ClusterRoleBinding
	}}
	a := newFakeAuthorizer(t, rb.react, authz.Config{})
	ctx := context.Background()

	if a.Allowed(ctx, sa, "shared", "encrypt") {
		t.Fatal("namespace Role must not grant a global key")
	}
	if !a.Allowed(ctx, sa, "shared", "decrypt") {
		t.Fatal("ClusterRoleBinding must grant a global key")
	}
	for _, ns := range rb.seenNS {
		if ns != "" {
			t.Fatalf("SAR namespace = %q, want empty (cluster scope)", ns)
		}
	}
}

func TestCB_Cache_SeparatedByJudgedNamespace(t *testing.T) {
	sa := id("team-a", "app")
	rb := &rbacReactor{grants: []grant{{ns: "team-a", subject: sa.Subject, key: "team-a.k", verb: "encrypt"}}}
	a := newFakeAuthorizer(t, rb.react, authz.Config{})
	ctx := context.Background()

	// 같은 base 이름이라도 소유 네임스페이스가 다르면 별개 판단이어야 한다 (캐시가 섞이면 안 됨).
	if !a.Allowed(ctx, sa, "team-a.k", "encrypt") {
		t.Fatal("team-a.k must be allowed")
	}
	if a.Allowed(ctx, sa, "team-b.k", "encrypt") {
		t.Fatal("team-b.k must not reuse team-a.k's cached allow")
	}
	if a.Allowed(ctx, sa, "k", "encrypt") {
		t.Fatal("global k must not reuse a namespaced cached allow")
	}
	before := len(rb.seenNS)
	a.Allowed(ctx, sa, "team-a.k", "encrypt") // 캐시 적중: SAR 추가 없음
	a.Allowed(ctx, sa, "team-b.k", "encrypt")
	a.Allowed(ctx, sa, "k", "encrypt")
	if len(rb.seenNS) != before {
		t.Fatalf("expected cache hits, SAR calls grew by %d", len(rb.seenNS)-before)
	}
	want := []string{"team-a", "team-b", ""}
	for i, w := range want {
		if rb.seenNS[i] != w {
			t.Fatalf("SAR %d namespace = %q, want %q", i, rb.seenNS[i], w)
		}
	}
}

func TestCB_MalformedNames_DeniedWithoutSAR(t *testing.T) {
	sa := id("team-a", "app")
	rb := &rbacReactor{grants: []grant{{ns: "", subject: sa.Subject, key: "a.b.c", verb: "encrypt"}}}
	a := newFakeAuthorizer(t, rb.react, authz.Config{})
	for _, name := range []string{"a.b.c", "Team-A.x", ".x", "x.", "-a.x", "a.x y"} {
		if a.Allowed(context.Background(), sa, name, "encrypt") {
			t.Fatalf("%q allowed", name)
		}
	}
	if len(rb.seenNS) != 0 {
		t.Fatal("SAR sent for malformed key names")
	}
}
