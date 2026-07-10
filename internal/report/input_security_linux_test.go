//go:build linux

package report

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestReadScanAcceptsStrictLinuxInputWithoutMutatingFiles(t *testing.T) {
	directory := writeStrictReportInput(t, "scan-complete")
	metadataPath := filepath.Join(directory, "metadata.json")
	resultsPath := filepath.Join(directory, "results.json")

	directoryBefore := captureReportInputSnapshot(t, directory, false)
	metadataBefore := captureReportInputSnapshot(t, metadataPath, true)
	resultsBefore := captureReportInputSnapshot(t, resultsPath, true)
	entriesBefore := reportInputEntryNames(t, directory)

	if directoryBefore.info.Mode().Perm() != 0o700 {
		t.Fatalf("report directory mode = %04o, want 0700", directoryBefore.info.Mode().Perm())
	}
	if err := validateReportInputDirectorySecurity(directoryBefore.info); err != nil {
		t.Fatalf("validateReportInputDirectorySecurity() error = %v", err)
	}
	for name, snapshot := range map[string]reportInputSnapshot{
		"metadata.json": metadataBefore,
		"results.json":  resultsBefore,
	} {
		if snapshot.info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", name, snapshot.info.Mode().Perm())
		}
		if snapshot.stat.Nlink != 1 {
			t.Fatalf("%s link count = %d, want 1", name, snapshot.stat.Nlink)
		}
		if err := validateReportInputFileSecurity(snapshot.info); err != nil {
			t.Fatalf("validateReportInputFileSecurity(%s) error = %v", name, err)
		}
	}

	loaded, err := ReadScan(directory)
	if err != nil {
		t.Fatalf("ReadScan() error = %v", err)
	}
	if loaded.Metadata.RunID != "scan-20260711" || len(loaded.Results) != 1 || loaded.Results[0].RuleID != "U-01" {
		t.Fatalf("ReadScan() returned unexpected scan identity: run=%q results=%d", loaded.Metadata.RunID, len(loaded.Results))
	}

	assertReportInputSnapshotUnchanged(t, directoryBefore, captureReportInputSnapshot(t, directory, false))
	assertReportInputSnapshotUnchanged(t, metadataBefore, captureReportInputSnapshot(t, metadataPath, true))
	assertReportInputSnapshotUnchanged(t, resultsBefore, captureReportInputSnapshot(t, resultsPath, true))
	if entriesAfter := reportInputEntryNames(t, directory); !reflect.DeepEqual(entriesAfter, entriesBefore) {
		t.Fatalf("report directory entries changed during read: before=%v after=%v", entriesBefore, entriesAfter)
	}
}

func TestReadScanRejectsPartialDirectory(t *testing.T) {
	directory := writeStrictReportInput(t, ".scan.partial")
	if _, err := ReadScan(directory); err == nil {
		t.Fatal("ReadScan() error = nil, want partial report rejection")
	}
}

func TestReadScanRejectsRelaxedDirectoryPermissions(t *testing.T) {
	for _, mode := range []os.FileMode{0o750, 0o701, 0o770} {
		mode := mode
		t.Run(mode.String(), func(t *testing.T) {
			directory := writeStrictReportInput(t, "scan-complete")
			if err := os.Chmod(directory, mode); err != nil {
				t.Fatalf("Chmod(%04o) error = %v", mode, err)
			}
			if _, err := ReadScan(directory); err == nil {
				t.Fatalf("ReadScan() error = nil, want relaxed directory mode %04o rejection", mode)
			}
		})
	}
}

func TestReadScanRejectsRelaxedInputFilePermissions(t *testing.T) {
	for _, name := range []string{"metadata.json", "results.json"} {
		name := name
		for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
			mode := mode
			t.Run(name+"-"+mode.String(), func(t *testing.T) {
				directory := writeStrictReportInput(t, "scan-complete")
				path := filepath.Join(directory, name)
				if err := os.Chmod(path, mode); err != nil {
					t.Fatalf("Chmod(%s, %04o) error = %v", name, mode, err)
				}
				if _, err := ReadScan(directory); err == nil {
					t.Fatalf("ReadScan() error = nil, want relaxed %s mode %04o rejection", name, mode)
				}
			})
		}
	}
}

func TestReadScanRejectsSymlinkedReportPath(t *testing.T) {
	t.Run("final directory", func(t *testing.T) {
		directory := writeStrictReportInput(t, "scan-complete")
		link := filepath.Join(filepath.Dir(directory), "scan-link")
		if err := os.Symlink(directory, link); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
		if _, err := ReadScan(link); err == nil {
			t.Fatal("ReadScan() error = nil, want report directory symlink rejection")
		}
	})

	t.Run("ancestor directory", func(t *testing.T) {
		base := t.TempDir()
		realParent := filepath.Join(base, "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatalf("Mkdir() error = %v", err)
		}
		directory := writeStrictReportInputUnder(t, realParent, "scan-complete")
		linkParent := filepath.Join(base, "linked-parent")
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}
		linkedDirectory := filepath.Join(linkParent, filepath.Base(directory))
		if _, err := ReadScan(linkedDirectory); err == nil {
			t.Fatal("ReadScan() error = nil, want symlinked ancestor rejection")
		}
	})
}

func TestReadScanRejectsUnsafeInputFileTypesAndLinks(t *testing.T) {
	for _, name := range []string{"metadata.json", "results.json"} {
		name := name
		for _, kind := range []string{"symlink", "hardlink", "directory", "fifo"} {
			kind := kind
			t.Run(name+"-"+kind, func(t *testing.T) {
				directory := writeStrictReportInput(t, "scan-complete")
				path := filepath.Join(directory, name)
				switch kind {
				case "symlink":
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatalf("ReadFile() error = %v", err)
					}
					if err := os.Remove(path); err != nil {
						t.Fatalf("Remove() error = %v", err)
					}
					backingName := "." + name + ".backing"
					backingPath := filepath.Join(directory, backingName)
					if err := os.WriteFile(backingPath, data, 0o600); err != nil {
						t.Fatalf("WriteFile() error = %v", err)
					}
					if err := os.Symlink(backingName, path); err != nil {
						t.Fatalf("Symlink() error = %v", err)
					}
				case "hardlink":
					if err := os.Link(path, filepath.Join(directory, "."+name+".alias")); err != nil {
						t.Fatalf("Link() error = %v", err)
					}
				case "directory":
					if err := os.Remove(path); err != nil {
						t.Fatalf("Remove() error = %v", err)
					}
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatalf("Mkdir() error = %v", err)
					}
				case "fifo":
					if err := os.Remove(path); err != nil {
						t.Fatalf("Remove() error = %v", err)
					}
					if err := syscall.Mkfifo(path, 0o600); err != nil {
						t.Fatalf("Mkfifo() error = %v", err)
					}
				default:
					t.Fatalf("unknown unsafe input kind %q", kind)
				}

				if _, err := ReadScan(directory); err == nil {
					t.Fatalf("ReadScan() error = nil, want %s %s rejection", name, kind)
				}
			})
		}
	}
}

func TestOpenStrictReportFileRejectsSymlinkWithoutCallerLstat(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "backing.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink("backing.json", filepath.Join(directory, "metadata.json")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatalf("OpenRoot() error = %v", err)
	}
	defer root.Close()

	file, err := openStrictReportFile(root, "metadata.json")
	if err == nil {
		_ = file.Close()
		t.Fatal("openStrictReportFile() error = nil, want O_NOFOLLOW symlink rejection")
	}
}

func TestLinuxReportInputValidatorsRejectDifferentOwner(t *testing.T) {
	foreignUID := uint32(os.Geteuid()) + 1
	directory := syntheticLinuxFileInfo{
		name: "scan-complete",
		mode: os.ModeDir | 0o700,
		stat: syscall.Stat_t{Uid: foreignUID, Mode: syscall.S_IFDIR | 0o700},
	}
	if err := validateReportInputDirectorySecurity(directory); err == nil {
		t.Fatal("validateReportInputDirectorySecurity() error = nil, want different-owner rejection")
	}
	file := syntheticLinuxFileInfo{
		name: "metadata.json",
		mode: 0o600,
		stat: syscall.Stat_t{Uid: foreignUID, Mode: syscall.S_IFREG | 0o600, Nlink: 1},
	}
	if err := validateReportInputFileSecurity(file); err == nil {
		t.Fatal("validateReportInputFileSecurity() error = nil, want different-owner rejection")
	}
}

type reportInputSnapshot struct {
	path string
	info os.FileInfo
	stat syscall.Stat_t
	data []byte
}

func captureReportInputSnapshot(t *testing.T, path string, readContent bool) reportInputSnapshot {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s) error = %v", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("Lstat(%s) did not return syscall.Stat_t", path)
	}
	snapshot := reportInputSnapshot{path: path, info: info, stat: *stat}
	if readContent {
		snapshot.data, err = os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
	}
	return snapshot
}

func assertReportInputSnapshotUnchanged(t *testing.T, before, after reportInputSnapshot) {
	t.Helper()
	if !os.SameFile(before.info, after.info) {
		t.Fatalf("%s inode changed during report read", before.path)
	}
	if before.info.Mode() != after.info.Mode() || before.info.Size() != after.info.Size() || !before.info.ModTime().Equal(after.info.ModTime()) {
		t.Fatalf("%s file metadata changed during report read", before.path)
	}
	if before.stat.Dev != after.stat.Dev || before.stat.Ino != after.stat.Ino || before.stat.Uid != after.stat.Uid ||
		before.stat.Gid != after.stat.Gid || before.stat.Nlink != after.stat.Nlink || before.stat.Mode != after.stat.Mode {
		t.Fatalf("%s ownership, link, mode, or identity changed during report read", before.path)
	}
	if !bytes.Equal(before.data, after.data) {
		t.Fatalf("%s contents changed during report read", before.path)
	}
}

func reportInputEntryNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("ReadDir(%s) error = %v", directory, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func writeStrictReportInput(t *testing.T, name string) string {
	t.Helper()
	return writeStrictReportInputUnder(t, t.TempDir(), name)
}

func writeStrictReportInputUnder(t *testing.T, parent, name string) string {
	t.Helper()
	directory := filepath.Join(parent, name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	run := validLoadedScanFixture()
	metadata, err := marshalJSON(run.Metadata)
	if err != nil {
		t.Fatalf("marshalJSON(metadata) error = %v", err)
	}
	results, err := marshalJSON(run.Results)
	if err != nil {
		t.Fatalf("marshalJSON(results) error = %v", err)
	}
	for fileName, data := range map[string][]byte{
		"metadata.json": metadata,
		"results.json":  results,
	} {
		path := filepath.Join(directory, fileName)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", fileName, err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("Chmod(%s) error = %v", fileName, err)
		}
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatalf("Chmod(report directory) error = %v", err)
	}
	return directory
}

type syntheticLinuxFileInfo struct {
	name string
	mode os.FileMode
	stat syscall.Stat_t
}

func (i syntheticLinuxFileInfo) Name() string       { return i.name }
func (i syntheticLinuxFileInfo) Size() int64        { return 0 }
func (i syntheticLinuxFileInfo) Mode() os.FileMode  { return i.mode }
func (i syntheticLinuxFileInfo) ModTime() time.Time { return time.Time{} }
func (i syntheticLinuxFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i syntheticLinuxFileInfo) Sys() any           { return &i.stat }
