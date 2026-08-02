package buildinfo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

func TestEmbeddedVersionIsUsed(t *testing.T) {
	t.Parallel()
	want := strings.TrimSpace(string(embeddedVersion))
	if current := Current().Version; !strings.HasPrefix(current, want) {
		t.Fatalf("Current().Version = %q, want prefix %q", current, want)
	}
}

func TestIsPrerelease(t *testing.T) {
	t.Parallel()
	tests := map[string]bool{
		"0.1.0-alpha.1":       true,
		"v1.2.3-rc.1+build.5": true,
		"1.2.3":               false,
		"v1.2.3+build.5":      false,
	}
	for version, want := range tests {
		if got := IsPrerelease(version); got != want {
			t.Errorf("IsPrerelease(%q) = %t, want %t", version, got, want)
		}
	}
}

func TestResolveInfoPreservesGoVCSProvenance(t *testing.T) {
	t.Parallel()

	vcsRevision := strings.Repeat("a", 40)
	info := resolveInfo(strings.Repeat("b", 40), "release-date", []debug.BuildSetting{
		{Key: "vcs.revision", Value: vcsRevision},
		{Key: "vcs.time", Value: "vcs-date"},
		{Key: "vcs.modified", Value: "false"},
	})
	if info.Commit != strings.Repeat("b", 40) {
		t.Fatalf("Commit = %q, want ldflags identity", info.Commit)
	}
	if !info.VCS.RevisionPresent || info.VCS.Revision != vcsRevision {
		t.Fatalf("VCS revision = %+v, want present revision %q", info.VCS, vcsRevision)
	}
	if !info.VCS.ModifiedPresent || info.VCS.Modified != "false" || info.Modified {
		t.Fatalf("VCS modified = %+v, Modified = %t; want explicit clean provenance", info.VCS, info.Modified)
	}
}

func TestResolveInfoUsesGoVCSIdentityWhenLdflagsAreUnknown(t *testing.T) {
	t.Parallel()

	revision := strings.Repeat("a", 40)
	info := resolveInfo("unknown", "unknown", []debug.BuildSetting{
		{Key: "vcs.revision", Value: revision},
		{Key: "vcs.time", Value: "2026-07-31T00:00:00Z"},
		{Key: "vcs.modified", Value: "false"},
	})
	if info.Commit != revision || info.BuildDate != "2026-07-31T00:00:00Z" {
		t.Fatalf("Commit = %q, BuildDate = %q; want Go VCS identity", info.Commit, info.BuildDate)
	}
}

func TestResolveInfoRecordsMissingGoVCSProvenance(t *testing.T) {
	t.Parallel()

	info := resolveInfo(strings.Repeat("a", 40), "release-date", nil)
	if info.VCS.RevisionPresent || info.VCS.ModifiedPresent {
		t.Fatalf("VCS provenance = %+v, want settings to remain absent", info.VCS)
	}
}

func TestResolveInfoTreatsNonFalseVCSModifiedAsDirty(t *testing.T) {
	t.Parallel()

	wantVersion := strings.TrimSpace(string(embeddedVersion)) + "+dirty"
	for _, value := range []string{"true", "", "False", "invalid"} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			info := resolveInfo("unknown", "unknown", []debug.BuildSetting{
				{Key: "vcs.revision", Value: strings.Repeat("a", 40)},
				{Key: "vcs.modified", Value: value},
			})
			if !info.Modified || info.Version != wantVersion {
				t.Fatalf("Modified = %t, Version = %q; want fail-closed dirty build %q", info.Modified, info.Version, wantVersion)
			}
			if !info.VCS.ModifiedPresent || info.VCS.Modified != value {
				t.Fatalf("VCS provenance = %+v, want raw modified value %q", info.VCS, value)
			}
		})
	}
}

func TestExecutableSHA256MatchesRunningExecutable(t *testing.T) {
	path, err := runningExecutablePath()
	if err != nil {
		t.Fatalf("runningExecutablePath() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error = %v", path, err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])

	got, err := ExecutableSHA256(context.Background())
	if err != nil {
		t.Fatalf("ExecutableSHA256() error = %v", err)
	}
	if got != want {
		t.Fatalf("ExecutableSHA256() = %q, want %q", got, want)
	}
}

func TestExecutableSHA256HonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ExecutableSHA256(ctx); err == nil {
		t.Fatal("ExecutableSHA256() error = nil, want canceled context")
	}
}
