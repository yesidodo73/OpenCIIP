//go:build linux

package regularfile

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestReadOnlyMetadataPlanningPreservesFileIdentityAndContent(t *testing.T) {
	fixture := newReadOnlyLinuxFixture(t, 0o640)
	ctx := context.Background()

	resource, err := fixture.handler.Normalize(ctx, fixture.reference)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	before, err := fixture.handler.Capture(ctx, resource)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	desiredMode := before.File.Mode &^ 0o077
	desired, err := fixture.handler.BuildDesiredMetadata(ctx, resource, DesiredMetadata{
		UID:            before.File.UID,
		GID:            before.File.GID,
		Mode:           desiredMode,
		SELinuxContext: before.File.SELinuxContext,
	})
	if err != nil {
		t.Fatalf("BuildDesiredMetadata() error = %v", err)
	}

	if desired.File.Mode != desiredMode {
		t.Fatalf("desired mode = %#o, want %#o", desired.File.Mode, desiredMode)
	}
	if desired.File.SHA256 != before.File.SHA256 || desired.File.Size != before.File.Size {
		t.Fatal("desired metadata changed the captured content identity")
	}
	if desired.File.Device != before.File.Device || desired.File.Inode != before.File.Inode {
		t.Fatal("desired metadata changed the captured file identity")
	}
	if desired.File.GID != before.File.GID {
		t.Fatalf("desired GID = %d, want preserved GID %d", desired.File.GID, before.File.GID)
	}

	after, err := fixture.handler.Capture(ctx, resource)
	if err != nil {
		t.Fatalf("Capture() after planning error = %v", err)
	}
	assertReadOnlyFixtureUnchanged(t, fixture, before, after)
}

func TestNormalizeRejectsSymbolicLink(t *testing.T) {
	fixture := newReadOnlyLinuxFixture(t, 0o640)
	linkPath := filepath.Join(filepath.Dir(fixture.physicalPath), "link.conf")
	if err := os.Symlink(filepath.Base(fixture.physicalPath), linkPath); err != nil {
		t.Fatalf("create symbolic-link fixture: %v", err)
	}

	_, err := fixture.handler.Normalize(context.Background(), model.ResourceRef{
		Kind: model.ResourceFile,
		ID:   "/etc/link.conf",
	})
	if got := CodeOf(err); got != CodeSymlinkNotAllowed {
		t.Fatalf("Normalize() error code = %q, want %q (error: %v)", got, CodeSymlinkNotAllowed, err)
	}
}

func TestOpenedTargetIdentityRejectsReplacedParentPath(t *testing.T) {
	fixture := newReadOnlyLinuxFixture(t, 0o640)
	opened, err := fixture.handler.openCurrent(fixture.reference.ID, "test identity")
	if err != nil {
		t.Fatalf("openCurrent() error = %v", err)
	}
	defer opened.close()

	parent := filepath.Dir(fixture.physicalPath)
	detachedParent := parent + "-detached"
	if err := os.Rename(parent, detachedParent); err != nil {
		t.Fatalf("detach fixture parent: %v", err)
	}
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("replace fixture parent: %v", err)
	}
	if err := os.WriteFile(fixture.physicalPath, fixture.content, 0o640); err != nil {
		t.Fatalf("replace fixture target: %v", err)
	}

	err = fixture.handler.validateOpenedPathIdentity(opened, "test identity", fixture.reference.ID)
	if got := CodeOf(err); got != CodeFileChanged {
		t.Fatalf("validateOpenedPathIdentity() error code = %q, want %q (error: %v)", got, CodeFileChanged, err)
	}
}

func TestBuildDesiredMetadataRejectsHardLinkedFile(t *testing.T) {
	fixture := newReadOnlyLinuxFixture(t, 0o640)
	hardLinkPath := filepath.Join(filepath.Dir(fixture.physicalPath), "hard-link.conf")
	if err := os.Link(fixture.physicalPath, hardLinkPath); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}

	resource, err := fixture.handler.Normalize(context.Background(), fixture.reference)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	current, err := fixture.handler.Capture(context.Background(), resource)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}
	_, err = fixture.handler.BuildDesiredMetadata(context.Background(), resource, DesiredMetadata{
		UID:            current.File.UID,
		GID:            current.File.GID,
		Mode:           current.File.Mode &^ 0o077,
		SELinuxContext: current.File.SELinuxContext,
	})
	if got := CodeOf(err); got != CodeHardLinkNotSupported {
		t.Fatalf("BuildDesiredMetadata() error code = %q, want %q (error: %v)", got, CodeHardLinkNotSupported, err)
	}
	after, err := fixture.handler.Capture(context.Background(), resource)
	if err != nil {
		t.Fatalf("Capture() after hard-link rejection error = %v", err)
	}
	assertReadOnlyFixtureUnchanged(t, fixture, current, after)
}

func TestBuildDesiredMetadataRejectsPermissionWidening(t *testing.T) {
	fixture := newReadOnlyLinuxFixture(t, 0o640)
	ctx := context.Background()
	resource, err := fixture.handler.Normalize(ctx, fixture.reference)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	current, err := fixture.handler.Capture(ctx, resource)
	if err != nil {
		t.Fatalf("Capture() error = %v", err)
	}

	_, err = fixture.handler.BuildDesiredMetadata(ctx, resource, DesiredMetadata{
		UID:            current.File.UID,
		GID:            current.File.GID,
		Mode:           current.File.Mode | 0o020,
		SELinuxContext: current.File.SELinuxContext,
	})
	if got := CodeOf(err); got != CodeUnsupportedMetadata {
		t.Fatalf("BuildDesiredMetadata() error code = %q, want %q (error: %v)", got, CodeUnsupportedMetadata, err)
	}
	after, err := fixture.handler.Capture(ctx, resource)
	if err != nil {
		t.Fatalf("Capture() after permission-widening rejection error = %v", err)
	}
	assertReadOnlyFixtureUnchanged(t, fixture, current, after)
}

type readOnlyLinuxFixture struct {
	handler      *Handler
	reference    model.ResourceRef
	physicalPath string
	content      []byte
}

func newReadOnlyLinuxFixture(t *testing.T, mode os.FileMode) readOnlyLinuxFixture {
	t.Helper()
	systemRoot := t.TempDir()
	runDirectory := t.TempDir()
	if err := os.Chmod(runDirectory, 0o700); err != nil {
		t.Fatalf("protect run directory: %v", err)
	}
	parent := filepath.Join(systemRoot, "etc")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatalf("create fixture parent: %v", err)
	}
	physicalPath := filepath.Join(parent, "target.conf")
	content := []byte("regular-file remediation fixture\n")
	if err := os.WriteFile(physicalPath, content, 0o600); err != nil {
		t.Fatalf("create regular-file fixture: %v", err)
	}
	if err := os.Chmod(physicalPath, mode); err != nil {
		t.Fatalf("set regular-file fixture mode: %v", err)
	}
	handler, err := New(systemRoot, runDirectory)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return readOnlyLinuxFixture{
		handler:      handler,
		reference:    model.ResourceRef{Kind: model.ResourceFile, ID: "/etc/target.conf"},
		physicalPath: physicalPath,
		content:      content,
	}
}

func assertReadOnlyFixtureUnchanged(t *testing.T, fixture readOnlyLinuxFixture, before, after model.ResourceSnapshot) {
	t.Helper()
	if before.Fingerprint != after.Fingerprint || before.File.Device != after.File.Device || before.File.Inode != after.File.Inode || before.File.GID != after.File.GID || before.File.Mode != after.File.Mode {
		t.Fatal("read-only planning changed the fixture metadata or identity")
	}
	content, err := os.ReadFile(fixture.physicalPath)
	if err != nil {
		t.Fatalf("read fixture after planning: %v", err)
	}
	if string(content) != string(fixture.content) {
		t.Fatal("read-only planning changed the fixture content")
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(fixture.physicalPath, &stat); err != nil {
		t.Fatalf("stat fixture after planning: %v", err)
	}
	if uint64(stat.Dev) != before.File.Device || stat.Ino != before.File.Inode || int(stat.Gid) != before.File.GID {
		t.Fatal("read-only planning changed the on-disk inode or GID")
	}
}
