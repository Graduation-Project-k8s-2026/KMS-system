package main

import "testing"

// TestResolveMetricsAddr_Unset_DefaultsToNineOneHundred는 KMS_METRICS_ADDR을
// 아예 설정하지 않으면 기본값(:9100)으로 활성화되는지 확인한다.
func TestResolveMetricsAddr_Unset_DefaultsToNineOneHundred(t *testing.T) {
	addr, enabled := resolveMetricsAddr()
	if !enabled {
		t.Fatal("enabled = false, want true (KMS_METRICS_ADDR unset should default to enabled)")
	}
	if addr != ":9100" {
		t.Fatalf("addr = %q, want %q", addr, ":9100")
	}
}

// TestResolveMetricsAddr_CustomValue_UsesIt는 값을 설정하면 그 값을 그대로
// 쓰는지 확인한다.
func TestResolveMetricsAddr_CustomValue_UsesIt(t *testing.T) {
	t.Setenv("KMS_METRICS_ADDR", ":9200")

	addr, enabled := resolveMetricsAddr()
	if !enabled {
		t.Fatal("enabled = false, want true")
	}
	if addr != ":9200" {
		t.Fatalf("addr = %q, want %q", addr, ":9200")
	}
}

// TestResolveMetricsAddr_EmptyString_Disables는 빈 문자열로 명시적으로
// 설정하면(KMS_METRICS_ADDR="") 리스너를 비활성화하는지 확인한다 —
// 설정하지 않은 경우(기본값 사용)와 구분돼야 한다.
func TestResolveMetricsAddr_EmptyString_Disables(t *testing.T) {
	t.Setenv("KMS_METRICS_ADDR", "")

	_, enabled := resolveMetricsAddr()
	if enabled {
		t.Fatal("enabled = true, want false (KMS_METRICS_ADDR=\"\" should disable the listener)")
	}
}
