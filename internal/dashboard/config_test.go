package dashboard

import (
	"testing"
	"time"
)

func lookupFrom(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestConfigFromEnv_Defaults(t *testing.T) {
	cfg, err := ConfigFromEnv(lookupFrom(nil), "/run/admin.sock")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MetricsURL != "http://127.0.0.1:9100/metrics" || cfg.MetricsInterval != 5*time.Second ||
		cfg.MetricsWindow != 15*time.Minute || cfg.BenchDir != "./admin-data/bench" || cfg.SocketPath != "/run/admin.sock" {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestConfigFromEnv_Overrides(t *testing.T) {
	cfg, err := ConfigFromEnv(lookupFrom(map[string]string{
		EnvMetricsURL: "http://kms:9100/metrics", EnvMetricsInterval: "2", EnvMetricsWindow: "30", EnvBenchDir: "/var/bench",
	}), "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MetricsURL != "http://kms:9100/metrics" || cfg.MetricsInterval != 2*time.Second ||
		cfg.MetricsWindow != 30*time.Minute || cfg.BenchDir != "/var/bench" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestConfigFromEnv_EmptyURLDisablesCollection(t *testing.T) {
	cfg, err := ConfigFromEnv(lookupFrom(map[string]string{EnvMetricsURL: ""}), "")
	if err != nil || cfg.MetricsURL != "" {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}

func TestConfigFromEnv_RejectsBadNumbers(t *testing.T) {
	for _, env := range []string{EnvMetricsInterval, EnvMetricsWindow} {
		for _, v := range []string{"abc", "0", "-3", "1.5"} {
			if _, err := ConfigFromEnv(lookupFrom(map[string]string{env: v}), ""); err == nil {
				t.Errorf("%s=%q must be rejected", env, v)
			}
		}
	}
}
