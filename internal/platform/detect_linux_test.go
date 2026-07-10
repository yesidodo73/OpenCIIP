//go:build linux

package platform

import (
	"context"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestDetectorDetectCollectsFactsWithoutHardcodingDistributionSupport(t *testing.T) {
	reader := &detectorReader{
		files: map[string][]byte{
			"/etc/os-release":            []byte("ID=rocky\nNAME=\"Rocky Linux\"\nPRETTY_NAME=\"Rocky Linux 9.8\"\nVERSION_ID=\"9.8\"\nID_LIKE=\"rhel centos fedora\"\n"),
			"/proc/sys/kernel/osrelease": []byte("5.14.0-test.el9.x86_64\n"),
		},
		exists: map[string]bool{
			"/run/systemd/system": true,
			"/usr/bin/dnf":        true,
		},
	}

	info, warnings, err := NewDetector(reader).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("Detect() warnings = %#v, want none", warnings)
	}
	if info.OS != "linux" || info.ID != "rocky" || info.Name != "Rocky Linux 9.8" || info.VersionID != "9.8" {
		t.Fatalf("Detect() distribution facts = %#v", info)
	}
	if info.Family != "rhel" || info.KernelRelease != "5.14.0-test.el9.x86_64" || info.InitSystem != "systemd" || info.PackageManager != "dnf" {
		t.Fatalf("Detect() host facts = %#v", info)
	}
	if info.Support != model.SupportUnsupported {
		t.Fatalf("Detect() support = %q, want %q before binding verification", info.Support, model.SupportUnsupported)
	}
}
