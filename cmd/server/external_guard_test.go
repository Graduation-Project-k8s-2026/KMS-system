package main

import "testing"

func TestExternalDisabledReason(t *testing.T) {
	cases := []struct {
		name                           string
		addr                           string
		verifier, authorizer, failOpen bool
		wantDisabled                   bool
	}{
		{"off by default", "", true, true, false, false},
		{"normal", "0.0.0.0:9443", true, true, false, false},
		{"authn off", "0.0.0.0:9443", false, true, false, true},
		{"authz off", "0.0.0.0:9443", true, false, false, true},
		{"fail-open", "0.0.0.0:9443", true, true, true, true},
		{"everything off", "0.0.0.0:9443", false, false, true, true},
	}
	for _, c := range cases {
		got := externalDisabledReason(c.addr, c.verifier, c.authorizer, c.failOpen)
		if (got != "") != c.wantDisabled {
			t.Errorf("%s: reason = %q, wantDisabled = %v", c.name, got, c.wantDisabled)
		}
	}
}
