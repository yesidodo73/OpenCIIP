package filecheck

import "testing"

func TestAmbiguousEligibleMountCountIgnoresStackedExcludedMounts(t *testing.T) {
	targets := map[string][]string{
		"/proc/sys/fs/binfmt_misc": {"transient", "transient"},
		"/run/remote":              {"remote", "transient"},
	}
	if got := ambiguousEligibleMountCount(targets); got != 0 {
		t.Fatalf("ambiguousEligibleMountCount() = %d, want 0", got)
	}
}

func TestAmbiguousEligibleMountCountPreservesPersistentMountAmbiguity(t *testing.T) {
	targets := map[string][]string{
		"/":     {"persistent-posix"},
		"/data": {"persistent-posix", "transient"},
	}
	if got := ambiguousEligibleMountCount(targets); got != 2 {
		t.Fatalf("ambiguousEligibleMountCount() = %d, want 2", got)
	}
}
