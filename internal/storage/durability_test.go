package storage

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestAtomicFaultsPreserveCommittedValue(t *testing.T) {
	for _, stage := range []string{"create", "write", "sync", "rename", "dir-sync"} {
		for _, failure := range []error{syscall.ENOSPC, syscall.EROFS} {
			t.Run(stage+failure.Error(), func(t *testing.T) {
				s := NewFileStorage(t.TempDir())
				if e := s.Put("keys/a", []byte("old")); e != nil {
					t.Fatal(e)
				}
				s.fault = func(v string) error {
					if v == stage {
						return failure
					}
					return nil
				}
				if e := s.Put("keys/a", []byte("new")); !errors.Is(e, failure) {
					t.Fatal("fault was hidden")
				}
				s.fault = nil
				got, e := s.Get("keys/a")
				if e != nil {
					t.Fatal(e)
				}
				want := "old"
				if stage == "dir-sync" {
					want = "new"
				}
				if string(got) != want {
					t.Fatal("torn value")
				}
				st, _ := os.Stat(filepath.Join(s.root, "keys"))
				if st.Mode().Perm() != 0700 {
					t.Fatal("directory permissions")
				}
				st, _ = os.Stat(filepath.Join(s.root, "keys/a"))
				if st.Mode().Perm() != 0600 {
					t.Fatal("file permissions")
				}
			})
		}
	}
}
func TestLockSymlinkAndTraversal(t *testing.T) {
	dir := t.TempDir()
	s, e := OpenFileStorage(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if second, e := OpenFileStorage(dir); e == nil {
		second.Close()
		t.Fatal("second writer accepted")
	}
	outside := t.TempDir()
	os.Symlink(outside, filepath.Join(dir, "escape"))
	for _, key := range []string{"../outside", "/absolute", "escape/value"} {
		if e = s.Put(key, []byte("x")); e == nil {
			t.Fatal("unsafe path accepted")
		}
	}
}
func TestKilledWriter(t *testing.T) {
	if os.Getenv("KMS_TEST_KILL_WRITER") == "1" {
		s := NewFileStorage(os.Getenv("KMS_TEST_DIR"))
		s.fault = func(stage string) error {
			if stage == "rename" {
				syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
			return nil
		}
		_ = s.Put("keys/a", bytes.Repeat([]byte("n"), 1<<20))
		os.Exit(2)
	}
	dir := t.TempDir()
	s := NewFileStorage(dir)
	if e := s.Put("keys/a", []byte("committed")); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestKilledWriter$")
	cmd.Env = append(os.Environ(), "KMS_TEST_KILL_WRITER=1", "KMS_TEST_DIR="+dir)
	if e := cmd.Run(); e == nil {
		t.Fatal("writer not killed")
	}
	got, e := s.Get("keys/a")
	if e != nil || string(got) != "committed" {
		t.Fatal("committed data lost")
	}
}
