package seal

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// 장치가 없을 때 원인이 메시지와 errors.Is 양쪽에 드러나는지(CGO·시뮬레이터 불필요).
func TestOpenTPMDevice_MissingDevice(t *testing.T) {
	_, err := OpenTPMDevice(filepath.Join(t.TempDir(), "nope"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("err = %v", err)
	}
}
