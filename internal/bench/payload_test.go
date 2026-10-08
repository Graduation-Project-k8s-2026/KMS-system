package bench_test

import (
	"testing"

	"github.com/Graduation-Project-k8s-2026/KMS-system/internal/bench"
)

func TestParseSize(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"1KB", 1024, false},
		{"10KB", 10 * 1024, false},
		{"100KB", 100 * 1024, false},
		{"1MB", 1024 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"512B", 512, false},
		{"2048", 2048, false},
		{"0", 0, false},
		{" 1KB ", 1024, false},
		{"1kb", 1024, false},
		{"", 0, true},
		{"abc", 0, true},
		{"-1KB", 0, true},
		{"1XB", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := bench.ParseSize(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseSize(%q) = %d, nil; want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSize(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseSizeList(t *testing.T) {
	got, err := bench.ParseSizeList("1KB,10KB, 100KB ,1MB")
	if err != nil {
		t.Fatalf("ParseSizeList failed: %v", err)
	}
	want := []int{1024, 10 * 1024, 100 * 1024, 1024 * 1024}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %d, want %d", i, got[i], want[i])
		}
	}

	if _, err := bench.ParseSizeList(""); err == nil {
		t.Fatal("ParseSizeList(\"\") succeeded, want error")
	}
	if _, err := bench.ParseSizeList("1KB,bogus"); err == nil {
		t.Fatal("ParseSizeList with invalid entry succeeded, want error")
	}
}

func TestParseIntList(t *testing.T) {
	got, err := bench.ParseIntList("1,10,50,100")
	if err != nil {
		t.Fatalf("ParseIntList failed: %v", err)
	}
	want := []int{1, 10, 50, 100}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d] = %d, want %d", i, got[i], want[i])
		}
	}

	if _, err := bench.ParseIntList("1,0,5"); err == nil {
		t.Fatal("ParseIntList with a value < 1 succeeded, want error")
	}
	if _, err := bench.ParseIntList("1,abc"); err == nil {
		t.Fatal("ParseIntList with non-integer succeeded, want error")
	}
	if _, err := bench.ParseIntList(""); err == nil {
		t.Fatal("ParseIntList(\"\") succeeded, want error")
	}
}

func TestFormatSize(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{1024, "1KB"},
		{10 * 1024, "10KB"},
		{1024 * 1024, "1MB"},
		{512, "512B"},
		{0, "0B"},
		{1500, "1500B"}, // not a clean multiple of 1KB
	}
	for _, tc := range cases {
		if got := bench.FormatSize(tc.in); got != tc.want {
			t.Errorf("FormatSize(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseSize_FormatSize_RoundTrip(t *testing.T) {
	for _, s := range []string{"1KB", "10KB", "100KB", "1MB"} {
		n, err := bench.ParseSize(s)
		if err != nil {
			t.Fatalf("ParseSize(%q) failed: %v", s, err)
		}
		if got := bench.FormatSize(n); got != s {
			t.Fatalf("FormatSize(ParseSize(%q)) = %q, want %q", s, got, s)
		}
	}
}

func TestRandomPlaintext(t *testing.T) {
	buf, err := bench.RandomPlaintext(1024)
	if err != nil {
		t.Fatalf("RandomPlaintext failed: %v", err)
	}
	if len(buf) != 1024 {
		t.Fatalf("len = %d, want 1024", len(buf))
	}

	buf2, err := bench.RandomPlaintext(0)
	if err != nil {
		t.Fatalf("RandomPlaintext(0) failed: %v", err)
	}
	if len(buf2) != 0 {
		t.Fatalf("len = %d, want 0", len(buf2))
	}
}
