package filecheck

import (
	"context"
	"os"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type guideStartupReader struct {
	startupFixtureReader
	modes map[string]os.FileMode
	uids  map[string]int
}

type boundedGuideStartupReader struct {
	guideStartupReader
	boundedCalls int
}

func (reader *boundedGuideStartupReader) ReadDirBounded(name string, limit int) ([]os.DirEntry, bool, error) {
	reader.boundedCalls++
	entries, err := reader.guideStartupReader.ReadDir(name)
	if err != nil {
		return nil, false, err
	}
	if len(entries) > limit {
		return entries[:limit], true, nil
	}
	return entries, false, nil
}

func (reader guideStartupReader) Lstat(name string) (system.FileMetadata, error) {
	metadata, err := reader.startupFixtureReader.Lstat(name)
	if err != nil {
		return metadata, err
	}
	if mode, exists := reader.modes[name]; exists {
		metadata.Mode = mode
	}
	if uid, exists := reader.uids[name]; exists {
		metadata.UID = uid
	}
	return metadata, nil
}

func (reader guideStartupReader) Stat(name string) (system.FileMetadata, error) {
	return reader.Lstat(name)
}

func newGuideStartupReader(t *testing.T, files map[string]string, modes map[string]os.FileMode, uids map[string]int) system.Reader {
	t.Helper()
	base, ok := newStartupTestReader(t, files).(startupFixtureReader)
	if !ok {
		t.Fatal("unexpected startup fixture reader type")
	}
	return guideStartupReader{startupFixtureReader: base, modes: modes, uids: uids}
}

func TestEvaluateStartupPermissionsChecksOnlyGuideStartupPaths(t *testing.T) {
	reader := newGuideStartupReader(t, map[string]string{
		"/etc/systemd/system/custom.service":     "[Service]\nExecStart=/usr/bin/custom\n",
		"/usr/lib/systemd/system/vendor.service": "[Service]\nExecStart=/usr/bin/vendor\n",
	}, map[string]os.FileMode{
		"/etc/systemd/system/custom.service":     0o660,
		"/usr/lib/systemd/system/vendor.service": 0o666,
	}, nil)
	outcome := evaluateStartupPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{Files: reader})
	if outcome.Status != model.StatusPass {
		t.Fatalf("outcome = %#v, want PASS; group write is not the guide's chmod o-w condition and /usr/lib is outside the listed path", outcome)
	}
}

func TestEvaluateStartupPermissionsRejectsNonRootOrOtherWritableFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		mode os.FileMode
		uid  int
	}{
		{name: "other writable", mode: 0o602, uid: 0},
		{name: "non-root owner", mode: 0o600, uid: 1000},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader := newGuideStartupReader(t, map[string]string{
				"/etc/systemd/system/custom.service": "[Service]\n",
			}, map[string]os.FileMode{"/etc/systemd/system/custom.service": test.mode}, map[string]int{"/etc/systemd/system/custom.service": test.uid})
			outcome := evaluateStartupPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{Files: reader})
			if outcome.Status != model.StatusFail {
				t.Fatalf("outcome = %#v, want FAIL", outcome)
			}
		})
	}
}

func TestEvaluateStartupPermissionsReportsUninspectedDirectories(t *testing.T) {
	reader := newGuideStartupReader(t, map[string]string{
		"/etc/systemd/system/a/b/c/d/e/unsafe.service": "[Service]\n",
	}, map[string]os.FileMode{
		"/etc/systemd/system/a/b/c/d/e/unsafe.service": 0o666,
	}, nil)
	outcome := evaluateStartupPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{Files: reader})
	if outcome.Status != model.StatusUnknown {
		t.Fatalf("outcome = %#v, want UNKNOWN for an uninspected directory", outcome)
	}
}

func TestCollectStartupFilesBoundsDirectoryEnumeration(t *testing.T) {
	base := newGuideStartupReader(t, map[string]string{
		"/etc/systemd/system/a.service": "a",
		"/etc/systemd/system/b.service": "b",
		"/etc/systemd/system/c.service": "c",
	}, nil, nil).(guideStartupReader)
	reader := &boundedGuideStartupReader{guideStartupReader: base}
	files, unknowns, _, err := collectGuideStartupFilesWithLimit(context.Background(), reader, 2)
	if err != nil {
		t.Fatalf("collectGuideStartupFilesWithLimit() error = %v", err)
	}
	if reader.boundedCalls == 0 || len(files) != 2 || len(unknowns) == 0 {
		t.Fatalf("bounded calls = %d, files = %d, unknowns = %v; want bounded, incomplete scan", reader.boundedCalls, len(files), unknowns)
	}
}

func TestEvaluateGuideConfigPermissionsDoesNotRequireACL(t *testing.T) {
	reader := newStartupTestReader(t, map[string]string{"/etc/xinetd.conf": "defaults {}\n"})
	outcome := evaluateInetdPermissions(context.Background(), model.ResolvedRule{}, evaluator.Environment{
		Files: reader, Commands: nonOwnerACLFixtureRunner{},
	})
	if outcome.Status != model.StatusPass {
		t.Fatalf("outcome = %#v, want PASS without an ACL-specific condition", outcome)
	}
}
