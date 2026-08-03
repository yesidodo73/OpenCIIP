//go:build linux

package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestNewWriterAllowsPrivateRootBelowWritableAncestors(t *testing.T) {
	t.Parallel()

	ancestor := filepath.Join(t.TempDir(), "home", "user")
	if err := os.MkdirAll(ancestor, 0o777); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", ancestor, err)
	}
	if err := os.Chmod(ancestor, 0o777); err != nil {
		t.Fatalf("Chmod(%s) error = %v", ancestor, err)
	}

	reportRoot := filepath.Join(ancestor, "reports")
	writer, err := NewWriter(reportRoot)
	if err != nil {
		t.Fatalf("NewWriter(%s) error = %v", reportRoot, err)
	}
	if writer.basePath != reportRoot {
		t.Fatalf("writer.basePath = %q, want %q", writer.basePath, reportRoot)
	}
	info, err := os.Lstat(reportRoot)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", reportRoot, err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("report root mode = %04o, want 0700", got)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("report root stat type = %T, want *syscall.Stat_t", info.Sys())
	}
	if got, want := stat.Uid, uint32(os.Geteuid()); got != want {
		t.Fatalf("report root UID = %d, want %d", got, want)
	}
}

func TestNewWriterRejectsWritableReportRoot(t *testing.T) {
	t.Parallel()

	reportRoot := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(reportRoot, 0o700); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", reportRoot, err)
	}
	if err := os.Chmod(reportRoot, 0o777); err != nil {
		t.Fatalf("Chmod(%s) error = %v", reportRoot, err)
	}

	_, err := NewWriter(reportRoot)
	if err == nil || !strings.Contains(err.Error(), "unless it is a trusted sticky directory") {
		t.Fatalf("NewWriter(%s) error = %v, want writable-root rejection", reportRoot, err)
	}
}

func TestNewWriterAllowsTrustedStickyReportRoot(t *testing.T) {
	t.Parallel()

	reportRoot := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(reportRoot, 0o700); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", reportRoot, err)
	}
	if err := os.Chmod(reportRoot, os.ModeSticky|0o777); err != nil {
		t.Fatalf("Chmod(%s) error = %v", reportRoot, err)
	}

	writer, err := NewWriter(reportRoot)
	if err != nil {
		t.Fatalf("NewWriter(%s) error = %v", reportRoot, err)
	}
	path, err := writer.WriteScan(context.Background(), model.ScanRun{Metadata: model.RunMetadata{
		RunID:     "scan-sticky-root-fixture",
		StartedAt: time.Date(2026, 8, 3, 1, 2, 3, 0, time.UTC),
		Platform:  model.PlatformInfo{Hostname: "fixture"},
		Counts:    map[model.Status]int{},
		Complete:  true,
	}})
	if err != nil {
		t.Fatalf("WriteScan() error = %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("final report directory mode = %04o, want 0700", got)
	}
}

func TestNewWriterAllowsSystemTemporaryDirectoryWhenSticky(t *testing.T) {
	t.Parallel()

	reportRoot := filepath.Clean(os.TempDir())
	info, err := os.Lstat(reportRoot)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", reportRoot, err)
	}
	if info.Mode()&os.ModeSticky == 0 {
		t.Skipf("system temporary directory %s is not sticky", reportRoot)
	}
	if _, err := NewWriter(reportRoot); err != nil {
		t.Fatalf("NewWriter(%s) error = %v", reportRoot, err)
	}
}

func TestNewWriterRejectsSymlinkAncestor(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	realParent := filepath.Join(root, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("Mkdir(%s) error = %v", realParent, err)
	}
	linkedParent := filepath.Join(root, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatalf("Symlink(%s, %s) error = %v", realParent, linkedParent, err)
	}

	_, err := NewWriter(filepath.Join(linkedParent, "reports"))
	if err == nil || !strings.Contains(err.Error(), "not a real directory") {
		t.Fatalf("NewWriter through symlink error = %v, want symlink rejection", err)
	}
}
