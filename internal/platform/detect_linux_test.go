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
	if info.ScanSupport != model.ScanSupportUnsupported {
		t.Fatalf("Detect() scan support = %q, want %q before rule resolution", info.ScanSupport, model.ScanSupportUnsupported)
	}
	if info.RemediationSupport != model.RemediationSupportUnsupported {
		t.Fatalf("Detect() remediation support = %q, want %q before rule resolution", info.RemediationSupport, model.RemediationSupportUnsupported)
	}
}

func TestDetectorDetectDistinguishesCentOSLinuxPointReleaseFromStream(t *testing.T) {
	tests := []struct {
		name       string
		osRelease  string
		centosLine string
		want       string
	}{
		{
			name:       "CentOS Linux point release",
			osRelease:  "ID=centos\nPRETTY_NAME=\"CentOS Linux 8\"\nVERSION_ID=\"8\"\nID_LIKE=\"rhel fedora\"\n",
			centosLine: "CentOS Linux release 8.5.2111\n",
			want:       "8.5.2111",
		},
		{
			name:       "CentOS Stream major release",
			osRelease:  "ID=centos\nPRETTY_NAME=\"CentOS Stream 8\"\nVERSION_ID=\"8\"\nID_LIKE=\"rhel fedora\"\n",
			centosLine: "CentOS Stream release 8\n",
			want:       "8",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &detectorReader{
				files: map[string][]byte{
					"/etc/os-release":            []byte(test.osRelease),
					"/etc/centos-release":        []byte(test.centosLine),
					"/proc/sys/kernel/osrelease": []byte("4.18.0-test.el8.x86_64\n"),
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
			if info.ID != "centos" || info.VersionID != test.want || info.Family != "rhel" {
				t.Fatalf("Detect() distribution facts = %#v, want CentOS %s", info, test.want)
			}
		})
	}
}
