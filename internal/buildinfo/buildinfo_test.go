package buildinfo

import (
	"strings"
	"testing"
)

func TestEmbeddedVersionIsUsed(t *testing.T) {
	t.Parallel()
	want := strings.TrimSpace(embeddedVersion)
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
