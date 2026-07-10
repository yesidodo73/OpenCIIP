package filecheck

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const verifiedRockyProfileDLoop = `for i in /etc/profile.d/*.sh /etc/profile.d/sh.local ; do
    if [ -r "$i" ]; then
        if [ "${-#*i}" != "$-" ]; then
            . "$i"
        else
            . "$i" >/dev/null
        fi
    fi
done
`

func TestStartupContextsDoNotInjectUnreferencedProfileD(t *testing.T) {
	t.Parallel()

	reader := newStartupTestReader(t, map[string]string{
		"/etc/profile":                "PATH=/safe\nexport PATH\numask 0022\n",
		"/etc/profile.d/99-unread.sh": "PATH=.:/unsafe\numask 0000\n",
		"/root/.bashrc":               "PATH=/safe\nexport PATH\numask 0022\n",
	})
	inspector := newStartupInspector(context.Background(), evaluator.Environment{Files: reader})
	initial := uint32(0o022)
	contexts, err := inspector.contexts(support.PasswdEntry{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash"}, startupShellBash, &initial, nil)
	if err != nil {
		t.Fatalf("contexts() error = %v", err)
	}
	results, err := inspector.evaluateContexts(contexts)
	if err != nil {
		t.Fatalf("evaluateContexts() error = %v", err)
	}
	for _, result := range results {
		if len(result.Unknowns) != 0 {
			t.Errorf("%s unknowns = %#v, want none", result.Name, result.Unknowns)
		}
		if result.Variables["PATH"] != "/safe" {
			t.Errorf("%s PATH = %q, want /safe", result.Name, result.Variables["PATH"])
		}
		if result.Umask == nil || *result.Umask != 0o022 {
			t.Errorf("%s umask = %v, want 0022", result.Name, result.Umask)
		}
		for _, path := range result.Paths {
			if strings.HasPrefix(path, "/etc/profile.d/") {
				t.Errorf("%s unexpectedly applied unreferenced path %q", result.Name, path)
			}
		}
	}
}

func TestStartupContextsExpandOnlyVerifiedRockyProfileDLoopInShellOrder(t *testing.T) {
	t.Parallel()

	reader := newStartupTestReader(t, map[string]string{
		"/etc/profile":               "PATH=/before\nexport PATH\numask 0022\n" + verifiedRockyProfileDLoop,
		"/etc/profile.d/20-last.sh":  "PATH=/last\numask 0027\n",
		"/etc/profile.d/10-first.sh": "PATH=/first\numask 0000\n",
		"/etc/profile.d/sh.local":    "PATH=/local\numask 0077\n",
		"/root/.bashrc":              ":\n",
	})
	inspector := newStartupInspector(context.Background(), evaluator.Environment{Files: reader})
	contexts, err := inspector.contexts(support.PasswdEntry{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash"}, startupShellBash, nil, nil)
	if err != nil {
		t.Fatalf("contexts() error = %v", err)
	}
	results, err := inspector.evaluateContexts(contexts)
	if err != nil {
		t.Fatalf("evaluateContexts() error = %v", err)
	}
	login := results[0]
	if len(login.Unknowns) != 0 {
		t.Fatalf("login unknowns = %#v, want none", login.Unknowns)
	}
	wantPaths := []string{"/etc/profile", "/etc/profile.d/10-first.sh", "/etc/profile.d/20-last.sh", "/etc/profile.d/sh.local"}
	if !slices.Equal(login.Paths, wantPaths) {
		t.Errorf("login paths = %#v, want %#v", login.Paths, wantPaths)
	}
	if login.Variables["PATH"] != "/local" {
		t.Errorf("login PATH = %q, want /local", login.Variables["PATH"])
	}
	if login.Umask == nil || *login.Umask != 0o077 {
		t.Errorf("login umask = %v, want 0077", login.Umask)
	}
}

func TestStartupContextsRejectAlteredProfileDLoop(t *testing.T) {
	t.Parallel()

	altered := strings.Replace(verifiedRockyProfileDLoop, `[ -r "$i" ]`, `[ -f "$i" ]`, 1)
	reader := newStartupTestReader(t, map[string]string{
		"/etc/profile":              altered,
		"/etc/profile.d/10-good.sh": "PATH=/safe\numask 0022\n",
		"/root/.bashrc":             ":\n",
	})
	inspector := newStartupInspector(context.Background(), evaluator.Environment{Files: reader})
	contexts, err := inspector.contexts(support.PasswdEntry{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash"}, startupShellBash, nil, nil)
	if err != nil {
		t.Fatalf("contexts() error = %v", err)
	}
	results, err := inspector.evaluateContexts(contexts)
	if err != nil {
		t.Fatalf("evaluateContexts() error = %v", err)
	}
	if len(results[0].Unknowns) == 0 {
		t.Fatal("altered loop produced a deterministic login result")
	}
	if slices.Contains(results[0].Paths, "/etc/profile.d/10-good.sh") {
		t.Fatalf("altered loop applied profile.d script: paths = %#v", results[0].Paths)
	}
}

func TestStartupContextsFollowMatchingFixedFileGuards(t *testing.T) {
	t.Parallel()

	reader := newStartupTestReader(t, map[string]string{
		"/etc/profile":        "PATH=/profile\nexport PATH\n",
		"/root/.bash_profile": "if [ -f ~/.bashrc ]; then\n    . ~/.bashrc\nfi\n",
		"/root/.bashrc":       "if [ -f /etc/bashrc ]; then\n    . /etc/bashrc\nfi\n",
		"/etc/bashrc":         "PATH=/bashrc\nexport PATH\n",
	})
	inspector := newStartupInspector(context.Background(), evaluator.Environment{Files: reader})
	contexts, err := inspector.contexts(support.PasswdEntry{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash"}, startupShellBash, nil, nil)
	if err != nil {
		t.Fatalf("contexts() error = %v", err)
	}
	results, err := inspector.evaluateContexts(contexts)
	if err != nil {
		t.Fatalf("evaluateContexts() error = %v", err)
	}
	for _, result := range results {
		if len(result.Unknowns) != 0 {
			t.Errorf("%s unknowns = %#v, want none", result.Name, result.Unknowns)
		}
		if result.Variables["PATH"] != "/bashrc" {
			t.Errorf("%s PATH = %q, want /bashrc", result.Name, result.Variables["PATH"])
		}
	}
	wantLoginPaths := []string{"/etc/profile", "/root/.bash_profile", "/root/.bashrc", "/etc/bashrc"}
	if !slices.Equal(results[0].Paths, wantLoginPaths) {
		t.Errorf("login paths = %#v, want %#v", results[0].Paths, wantLoginPaths)
	}
}

func TestStartupContextsRejectMismatchedFixedFileGuard(t *testing.T) {
	t.Parallel()

	reader := newStartupTestReader(t, map[string]string{
		"/etc/profile":  "PATH=/profile\nexport PATH\n",
		"/root/.bashrc": "if [ -f /etc/bashrc ]; then\n    . /etc/profile\nfi\n",
		"/etc/bashrc":   "PATH=/bashrc\nexport PATH\n",
	})
	inspector := newStartupInspector(context.Background(), evaluator.Environment{Files: reader})
	contexts, err := inspector.contexts(support.PasswdEntry{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash"}, startupShellBash, nil, nil)
	if err != nil {
		t.Fatalf("contexts() error = %v", err)
	}
	results, err := inspector.evaluateContexts(contexts)
	if err != nil {
		t.Fatalf("evaluateContexts() error = %v", err)
	}
	if len(results[1].Unknowns) == 0 {
		t.Fatal("mismatched guard and source target produced a deterministic interactive result")
	}
	if slices.Contains(results[1].Paths, "/etc/bashrc") {
		t.Fatalf("mismatched guard applied /etc/bashrc: paths = %#v", results[1].Paths)
	}
}

func newStartupTestReader(t *testing.T, files map[string]string) system.Reader {
	t.Helper()
	source := make(fstest.MapFS, len(files))
	for systemPath, content := range files {
		source[strings.TrimPrefix(systemPath, "/")] = &fstest.MapFile{Data: []byte(content), Mode: 0o600}
	}
	return startupFixtureReader{files: source}
}

type startupFixtureReader struct {
	files fstest.MapFS
}

func (r startupFixtureReader) ReadFile(ctx context.Context, name string, limit int64) ([]byte, system.FileMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, system.FileMetadata{}, err
	}
	data, err := fs.ReadFile(r.files, strings.TrimPrefix(name, "/"))
	if err != nil {
		return nil, system.FileMetadata{}, err
	}
	if limit > 0 && int64(len(data)) > limit {
		return nil, system.FileMetadata{}, fmt.Errorf("%w: %s", system.ErrReadLimit, name)
	}
	metadata, err := r.Lstat(name)
	return data, metadata, err
}

func (r startupFixtureReader) Stat(name string) (system.FileMetadata, error) {
	return r.Lstat(name)
}

func (r startupFixtureReader) Lstat(name string) (system.FileMetadata, error) {
	info, err := fs.Stat(r.files, strings.TrimPrefix(name, "/"))
	if err != nil {
		return system.FileMetadata{}, err
	}
	fileType := "other"
	if info.Mode().IsRegular() {
		fileType = "regular"
	} else if info.IsDir() {
		fileType = "directory"
	}
	return system.FileMetadata{Path: name, FileType: fileType, Mode: info.Mode(), Size: info.Size(), UID: 0, GID: 0}, nil
}

func (r startupFixtureReader) ReadDir(name string) ([]os.DirEntry, error) {
	return fs.ReadDir(r.files, strings.TrimPrefix(name, "/"))
}

func (r startupFixtureReader) Exists(name string) (bool, error) {
	_, err := r.Lstat(name)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, err
}
