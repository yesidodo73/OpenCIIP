//go:build linux

package stateroot

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestValidateDirectoryInfoEnforcesOwnershipAndModes(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod(0700) error = %v", err)
	}
	privateInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatalf("Lstat(private directory) error = %v", err)
	}

	if err := validateDirectoryInfo(directory, privateInfo, true); err != nil {
		t.Fatalf("validateDirectoryInfo(private final) error = %v", err)
	}
	if err := validateDirectoryInfo(directory, privateInfo, false); err != nil {
		t.Fatalf("validateDirectoryInfo(private parent) error = %v", err)
	}

	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatalf("Chmod(0755) error = %v", err)
	}
	readOnlyParentInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatalf("Lstat(0755 directory) error = %v", err)
	}
	if err := validateDirectoryInfo(directory, readOnlyParentInfo, false); err != nil {
		t.Fatalf("validateDirectoryInfo(0755 parent) error = %v", err)
	}
	if err := validateDirectoryInfo(directory, readOnlyParentInfo, true); err == nil {
		t.Fatal("validateDirectoryInfo() accepted a final directory that was not mode 0700")
	}

	if err := os.Chmod(directory, 0o720); err != nil {
		t.Fatalf("Chmod(0720) error = %v", err)
	}
	writableParentInfo, err := os.Lstat(directory)
	if err != nil {
		t.Fatalf("Lstat(0720 directory) error = %v", err)
	}
	if err := validateDirectoryInfo(directory, writableParentInfo, false); err == nil {
		t.Fatal("validateDirectoryInfo() accepted a group-writable parent")
	}

	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("restore Chmod(0700) error = %v", err)
	}
	privateInfo, err = os.Lstat(directory)
	if err != nil {
		t.Fatalf("Lstat(restored directory) error = %v", err)
	}
	stat, ok := privateInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("directory ownership is unavailable")
	}
	otherOwner := *stat
	otherOwner.Uid = uint32(os.Geteuid()) + 1
	if err := validateDirectoryInfo(directory, statOverrideInfo{FileInfo: privateInfo, stat: &otherOwner}, true); err == nil {
		t.Fatal("validateDirectoryInfo() accepted a final directory owned by another UID")
	}
}

func TestValidateDirectoryInfoRejectsNonDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	filePath := filepath.Join(root, "file")
	if err := os.WriteFile(filePath, []byte("content"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	fileInfo, err := os.Lstat(filePath)
	if err != nil {
		t.Fatalf("Lstat(file) error = %v", err)
	}
	if err := validateDirectoryInfo(filePath, fileInfo, true); err == nil {
		t.Fatal("validateDirectoryInfo() accepted a regular file")
	}

	linkPath := filepath.Join(root, "link")
	if err := os.Symlink(root, linkPath); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	linkInfo, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Lstat(link) error = %v", err)
	}
	if err := validateDirectoryInfo(linkPath, linkInfo, true); err == nil {
		t.Fatal("validateDirectoryInfo() accepted a symbolic link")
	}
	if err := verifyOpenedIdentity(linkPath); err == nil {
		t.Fatal("verifyOpenedIdentity() followed a symbolic link")
	}
}

func TestPrepareDoesNotCreateBelowWorldWritableParent(t *testing.T) {
	t.Parallel()

	info, err := os.Lstat("/tmp")
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o022 == 0 {
		t.Skip("/tmp is unavailable or is not group/other writable on this host")
	}
	candidate := filepath.Join("/tmp", fmt.Sprintf("openciip-state-root-test-%d-%d", os.Getpid(), time.Now().UnixNano()))
	if _, err := os.Lstat(candidate); err == nil {
		t.Fatalf("unexpected pre-existing test path %s", candidate)
	} else if !os.IsNotExist(err) {
		t.Fatalf("Lstat(candidate) error = %v", err)
	}

	resolved, err := Prepare(candidate)
	if err == nil {
		t.Fatalf("Prepare(%s) resolved %s below a world-writable parent", candidate, resolved)
	}
	if !strings.Contains(err.Error(), "writable by group or other users") {
		t.Fatalf("Prepare(%s) error = %v, want untrusted-parent rejection", candidate, err)
	}
	if _, err := os.Lstat(candidate); !os.IsNotExist(err) {
		t.Fatalf("Prepare() left candidate path with error %v, want no creation", err)
	}
}

func TestValidateStateFilesystemRejectsSpecialFilesystem(t *testing.T) {
	t.Parallel()

	err := validateStateFilesystem("/proc")
	if err == nil {
		t.Fatal("validateStateFilesystem(/proc) accepted procfs")
	}
	if !strings.Contains(err.Error(), "unsupported remote, volatile, overlay, or special filesystem") {
		t.Fatalf("validateStateFilesystem(/proc) error = %v, want unsupported-filesystem rejection", err)
	}
}

func TestPrepareAndValidateOnVerifiedLocalFilesystem(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("verified state-root integration requires the same root context as automatic remediation")
	}
	parent := os.Getenv("OPENCIIP_TEST_TRUSTED_STATE_PARENT")
	if parent == "" {
		t.Skip("set OPENCIIP_TEST_TRUSTED_STATE_PARENT to an existing trusted directory on a supported host filesystem")
	}
	parent = filepath.Clean(parent)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("trusted test parent %s is not a real directory: info=%v error=%v", parent, parentInfo, err)
	}
	candidate, err := os.MkdirTemp(parent, "openciip-stateroot-test-")
	if err != nil {
		t.Fatalf("MkdirTemp(trusted parent) error = %v", err)
	}
	if err := os.Remove(candidate); err != nil {
		t.Fatalf("Remove(prepared candidate) error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(candidate); err != nil && !os.IsNotExist(err) {
			t.Errorf("Remove(test state root) error = %v", err)
		}
	})

	resolved, err := Prepare(candidate)
	if err != nil {
		t.Fatalf("Prepare(%s) error = %v", candidate, err)
	}
	if resolved != candidate {
		t.Fatalf("Prepare() = %q, want canonical candidate %q", resolved, candidate)
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		t.Fatalf("Lstat(prepared root) error = %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("prepared root ownership is unavailable")
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("prepared root mode=%v uid=%d, want directory 0700 uid=%d", info.Mode(), stat.Uid, os.Geteuid())
	}
	validated, err := Validate(candidate)
	if err != nil {
		t.Fatalf("Validate(%s) error = %v", candidate, err)
	}
	if validated != resolved {
		t.Fatalf("Validate() = %q, want prepared path %q", validated, resolved)
	}
}

type statOverrideInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (info statOverrideInfo) Sys() any {
	return info.stat
}
