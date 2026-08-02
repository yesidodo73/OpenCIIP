//go:build linux

package executor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedParentDirectoriesRejectsWritableAncestor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned temporary directories are required to isolate writable-ancestor rejection")
	}
	root, err := os.MkdirTemp("/root", "openciip-executor-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove fixture: %v", err)
		}
	})
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if trustedParentDirectories(filepath.Join(bin, "visudo")) {
		t.Fatal("trustedParentDirectories() accepted a group/other-writable ancestor")
	}
}

func TestTrustedParentDirectoriesAcceptsSystemExecutablePath(t *testing.T) {
	if !trustedParentDirectories("/usr/bin/true") {
		t.Fatal("trustedParentDirectories() rejected /usr/bin")
	}
}
