package main

import "testing"

func TestParseAllowedSeals(t *testing.T) {
	ok, err := parseAllowedSeals(" shamir , tpm ")
	if err != nil || !ok["shamir"] || !ok["tpm"] || len(ok) != 2 {
		t.Fatalf("got %v, %v", ok, err)
	}
	for _, bad := range []string{"", ",", "dev", "shamir,k8s", "TPM"} {
		if _, err := parseAllowedSeals(bad); err == nil {
			t.Errorf("parseAllowedSeals(%q) accepted", bad)
		}
	}
}
