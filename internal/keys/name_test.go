package keys

import "testing"

func TestParseName(t *testing.T) {
	good := map[string][2]string{
		"payment":        {"", "payment"},
		"k8s-secrets":    {"", "k8s-secrets"},
		"team-a.payment": {"team-a", "payment"},
		"a.B_c-1":        {"a", "B_c-1"},
	}
	for name, want := range good {
		ns, base, err := ParseName(name)
		if err != nil || ns != want[0] || base != want[1] {
			t.Errorf("ParseName(%q) = %q, %q, %v", name, ns, base, err)
		}
	}
	for _, bad := range []string{"", ".x", "x.", "a.b.c", "Team.x", "-a.x", "a-.x", "a_b.x", "a.x y", "a/b", "..", "a..b",
		"team-a.payment-with-a-very-long-name-that-exceeds-the-sixty-four-char-limit"} {
		if _, _, err := ParseName(bad); err == nil {
			t.Errorf("ParseName(%q) accepted", bad)
		}
	}
}

func TestCreateKey_NamespacedAndLegacyBothWork(t *testing.T) {
	m := newTestManager(t)
	for _, n := range []string{"legacy_key", "team-a.payment"} {
		if _, err := m.CreateKey(n, 0); err != nil {
			t.Fatalf("CreateKey(%q): %v", n, err)
		}
		if _, err := m.GetKeyMeta(n); err != nil {
			t.Fatalf("GetKeyMeta(%q): %v", n, err)
		}
	}
}
