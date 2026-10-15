//go:build tpm_lab

// seal-lab deliberately has no production storage, network client or CLI for Root material.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"runtime"
	"time"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/seal"
)

func main() {
	repeats := flag.Int("repeats", 5, "isolated repetitions (3..30)")
	flag.Parse()
	if *repeats < 3 || *repeats > 30 || flag.NArg() != 0 {
		os.Exit(2)
	}
	failed := false
	for i := 0; i < *repeats; i++ {
		for _, r := range seal.RunBenchmark(context.Background()) {
			scope := map[string]string{"dev": "development-baseline", "shamir": "3-of-5-no-human-wait", "tpm": "software-simulator-no-hardware-protection", "k8s": "fake-client-no-cluster-network"}[r.Type]
			row := map[string]any{"iteration": i + 1, "at": time.Now().UTC(), "go": runtime.Version(), "architecture": runtime.GOARCH, "scope": scope, "result": r}
			if r.Error != "" {
				failed = true
			}
			if json.NewEncoder(os.Stdout).Encode(row) != nil {
				os.Exit(1)
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}
