package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/barrier"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/keys"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/metrics"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/storage"
)

func gaugeValue(t *testing.T, families []*dto.MetricFamily, name string) float64 {
	t.Helper()
	for _, f := range families {
		if f.GetName() == name {
			if len(f.Metric) != 1 {
				t.Fatalf("metric %s has %d series, want 1", name, len(f.Metric))
			}
			return f.Metric[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("metric %s not found among %d families", name, len(families))
	return 0
}

// TestSealKeyCollector_Sealed_ReportsSealedAndZeroKeys는 sealed 상태에서
// kms_seal_sealed=1이고, 키 목록을 읽을 수 없으므로 kms_keys_total/
// kms_key_versions_total이 0인지 확인한다(에러를 내는 대신 0으로 표현).
func TestSealKeyCollector_Sealed_ReportsSealedAndZeroKeys(t *testing.T) {
	store := storage.NewMemoryStorage()
	b := barrier.NewBarrier(store, seal.NewDevSeal("test-passphrase"))
	km := keys.NewKeyManager(b)

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewSealKeyCollector(b, km))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	if got := gaugeValue(t, families, "kms_seal_sealed"); got != 1 {
		t.Fatalf("kms_seal_sealed = %v, want 1 (sealed)", got)
	}
	if got := gaugeValue(t, families, "kms_keys_total"); got != 0 {
		t.Fatalf("kms_keys_total = %v, want 0 while sealed", got)
	}
	if got := gaugeValue(t, families, "kms_key_versions_total"); got != 0 {
		t.Fatalf("kms_key_versions_total = %v, want 0 while sealed", got)
	}
	if got := gaugeValue(t, families, "kms_seal_last_unsealed_timestamp_seconds"); got != 0 {
		t.Fatalf("kms_seal_last_unsealed_timestamp_seconds = %v, want 0 (never observed unsealed)", got)
	}
}

// TestSealKeyCollector_Unsealed_ReportsKeysAndVersions는 unseal 후 키를
// 만들고 회전시키면 개수/버전 총합이 정확히 반영되는지, unseal 시각
// 게이지가 채워지는지 확인한다.
func TestSealKeyCollector_Unsealed_ReportsKeysAndVersions(t *testing.T) {
	store := storage.NewMemoryStorage()
	b := barrier.NewBarrier(store, seal.NewDevSeal("test-passphrase"))
	km := keys.NewKeyManager(b)

	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	if _, err := km.CreateKey("app", 0); err != nil {
		t.Fatalf("CreateKey(app) failed: %v", err)
	}
	if _, err := km.CreateKey("other", 0); err != nil {
		t.Fatalf("CreateKey(other) failed: %v", err)
	}
	if _, err := km.RotateKey("app"); err != nil {
		t.Fatalf("RotateKey(app) failed: %v", err)
	}
	// app has 2 versions (rotated once), other has 1 -> total 3.

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewSealKeyCollector(b, km))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	if got := gaugeValue(t, families, "kms_seal_sealed"); got != 0 {
		t.Fatalf("kms_seal_sealed = %v, want 0 (unsealed)", got)
	}
	if got := gaugeValue(t, families, "kms_keys_total"); got != 2 {
		t.Fatalf("kms_keys_total = %v, want 2", got)
	}
	if got := gaugeValue(t, families, "kms_key_versions_total"); got != 3 {
		t.Fatalf("kms_key_versions_total = %v, want 3", got)
	}
	if got := gaugeValue(t, families, "kms_seal_last_unsealed_timestamp_seconds"); got <= 0 {
		t.Fatalf("kms_seal_last_unsealed_timestamp_seconds = %v, want > 0", got)
	}
}

// TestSealKeyCollector_NoSensitiveLabels는 노출된 지표 어디에도 키 이름이
// 라벨이나 텍스트로 등장하지 않는지 확인한다 — 개수/총합만 게이지 값으로
// 노출해야 한다.
func TestSealKeyCollector_NoSensitiveLabels(t *testing.T) {
	store := storage.NewMemoryStorage()
	b := barrier.NewBarrier(store, seal.NewDevSeal("test-passphrase"))
	km := keys.NewKeyManager(b)

	if err := b.Unseal(); err != nil {
		t.Fatalf("Unseal failed: %v", err)
	}
	const sensitiveName = "super-secret-key-name"
	if _, err := km.CreateKey(sensitiveName, 0); err != nil {
		t.Fatalf("CreateKey failed: %v", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewSealKeyCollector(b, km))

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather failed: %v", err)
	}

	for _, f := range families {
		for _, m := range f.Metric {
			for _, l := range m.GetLabel() {
				if l.GetValue() == sensitiveName || l.GetName() == sensitiveName {
					t.Fatalf("metric %s exposes the key name as a label: %+v", f.GetName(), l)
				}
			}
		}
	}
}
