package logging

import (
	"context"
	"errors"
	"os"
	"path"
	"sort"
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type guideLogReader struct {
	metadata map[string]system.FileMetadata
}

func newGuideLogReader(entries map[string]system.FileMetadata) guideLogReader {
	metadata := map[string]system.FileMetadata{
		"/var/log": {Path: "/var/log", FileType: "directory", Mode: os.ModeDir | 0o755, UID: 0, GID: 0},
	}
	for name, item := range entries {
		item.Path = name
		if item.FileType == "" {
			item.FileType = "regular"
		}
		metadata[name] = item
	}
	return guideLogReader{metadata: metadata}
}

func (reader guideLogReader) ReadFile(context.Context, string, int64) ([]byte, system.FileMetadata, error) {
	return nil, system.FileMetadata{}, errors.New("not implemented")
}

func (reader guideLogReader) Stat(name string) (system.FileMetadata, error) {
	item, exists := reader.metadata[name]
	if !exists {
		return system.FileMetadata{}, os.ErrNotExist
	}
	if item.FileType == "symlink" {
		target, exists := reader.metadata[item.LinkTarget]
		if !exists {
			return system.FileMetadata{}, os.ErrNotExist
		}
		target.Path = name
		return target, nil
	}
	return item, nil
}

func (reader guideLogReader) Lstat(name string) (system.FileMetadata, error) {
	item, exists := reader.metadata[name]
	if !exists {
		return system.FileMetadata{}, os.ErrNotExist
	}
	return item, nil
}

func (reader guideLogReader) ReadDir(directory string) ([]os.DirEntry, error) {
	if _, exists := reader.metadata[directory]; !exists {
		return nil, os.ErrNotExist
	}
	entries := make([]os.DirEntry, 0)
	for name, item := range reader.metadata {
		if name == directory || path.Dir(name) != directory {
			continue
		}
		entries = append(entries, guideLogDirEntry{metadata: item})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

func (reader guideLogReader) Exists(name string) (bool, error) {
	_, exists := reader.metadata[name]
	return exists, nil
}

type guideLogDirEntry struct {
	metadata system.FileMetadata
}

func (entry guideLogDirEntry) Name() string      { return path.Base(entry.metadata.Path) }
func (entry guideLogDirEntry) IsDir() bool       { return entry.metadata.FileType == "directory" }
func (entry guideLogDirEntry) Type() os.FileMode { return entry.metadata.Mode.Type() }
func (entry guideLogDirEntry) Info() (os.FileInfo, error) {
	return guideLogFileInfo{entry.metadata}, nil
}

type guideLogFileInfo struct {
	metadata system.FileMetadata
}

func (info guideLogFileInfo) Name() string       { return path.Base(info.metadata.Path) }
func (info guideLogFileInfo) Size() int64        { return info.metadata.Size }
func (info guideLogFileInfo) Mode() os.FileMode  { return info.metadata.Mode }
func (info guideLogFileInfo) ModTime() time.Time { return info.metadata.ModTime }
func (info guideLogFileInfo) IsDir() bool        { return info.metadata.FileType == "directory" }
func (info guideLogFileInfo) Sys() any           { return nil }

func guideLogRule() model.ResolvedRule {
	return model.ResolvedRule{RuleDefinition: model.RuleDefinition{
		ID:       "U-67",
		Criteria: model.Criteria{Pass: "로그 파일의 소유자가 root이고 권한이 0644 이하인 경우"},
	}}
}

func TestEvaluateLogFilePermissionsPassesDirectGuideFiles(t *testing.T) {
	reader := newGuideLogReader(map[string]system.FileMetadata{
		"/var/log/messages": {UID: 0, GID: 0, Mode: 0o640, Device: 1, Inode: 10},
		"/var/log/secure":   {UID: 0, GID: 0, Mode: 0o600, Device: 1, Inode: 11},
	})
	outcome := evaluateLogFilePermissions(context.Background(), guideLogRule(), evaluator.Environment{Files: reader})
	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS: %#v", outcome.Status, outcome)
	}
}

func TestEvaluateLogFilePermissionsReportsGuideViolations(t *testing.T) {
	reader := newGuideLogReader(map[string]system.FileMetadata{
		"/var/log/messages": {UID: 1000, GID: 0, Mode: 0o666, Device: 1, Inode: 10},
	})
	outcome := evaluateLogFilePermissions(context.Background(), guideLogRule(), evaluator.Environment{Files: reader})
	if outcome.Status != model.StatusFail {
		t.Fatalf("status = %s, want FAIL: %#v", outcome.Status, outcome)
	}
	if outcome.Observed != "/var/log/messages: 권한 0666\n/var/log/messages: 소유자 UID=1000" {
		t.Fatalf("observed = %q", outcome.Observed)
	}
}

func TestEvaluateLogFilePermissionsDoesNotRecursivelyInspectSubdirectories(t *testing.T) {
	reader := newGuideLogReader(map[string]system.FileMetadata{
		"/var/log/messages":    {UID: 0, GID: 0, Mode: 0o644, Device: 1, Inode: 10},
		"/var/log/app":         {FileType: "directory", UID: 0, GID: 0, Mode: os.ModeDir | 0o755},
		"/var/log/app/app.log": {UID: 1000, GID: 0, Mode: 0o666, Device: 1, Inode: 11},
	})
	outcome := evaluateLogFilePermissions(context.Background(), guideLogRule(), evaluator.Environment{Files: reader})
	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS: %#v", outcome.Status, outcome)
	}
}

func TestEvaluateLogFilePermissionsPassesWhenDirectoryHasNoDirectRegularFiles(t *testing.T) {
	reader := newGuideLogReader(map[string]system.FileMetadata{
		"/var/log/app": {FileType: "directory", UID: 0, GID: 0, Mode: os.ModeDir | 0o755},
	})
	outcome := evaluateLogFilePermissions(context.Background(), guideLogRule(), evaluator.Environment{Files: reader})
	if outcome.Status != model.StatusPass {
		t.Fatalf("status = %s, want PASS: %#v", outcome.Status, outcome)
	}
}
