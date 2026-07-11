package rules

import (
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestLoadBindingPlatformSupportSelectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		selector  string
		fields    string
		wantError bool
	}{
		{
			name:     "Linux wide scan support",
			selector: "  os: linux\n",
			fields:   "scan_support: supported\n",
		},
		{
			name:      "tested scan support requires architecture",
			selector:  "  id: rocky\n  version: \"9.8\"\n",
			fields:    "scan_support: tested\n",
			wantError: true,
		},
		{
			name:     "tested scan support accepts exact environment",
			selector: "  id: rocky\n  version: \"9.8\"\n  architecture: amd64\n",
			fields:   "scan_support: tested\n",
		},
		{
			name:      "remediation verification requires exact version",
			selector:  "  family: rhel\n  version_major: \"9\"\n",
			fields:    "platform_verification:\n  state: pending\n",
			wantError: true,
		},
		{
			name:     "remediation verification accepts exact environment",
			selector: "  id: rocky\n  version: \"9.8\"\n  architecture: amd64\n",
			fields:   "platform_verification:\n  state: pending\n",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data := "schema_version: 1\n" +
				"id: platform-layer\n" +
				"priority: 300\n" +
				"selector:\n" + test.selector +
				test.fields +
				"bindings: []\n"
			loader := NewLoader(fstest.MapFS{
				"platform.yaml": &fstest.MapFile{Data: []byte(data)},
			})
			_, err := loader.LoadBinding("platform.yaml")
			if test.wantError && err == nil {
				t.Fatal("LoadBinding() succeeded for invalid platform support metadata")
			}
			if !test.wantError && err != nil {
				t.Fatalf("LoadBinding() error = %v", err)
			}
		})
	}
}

func TestResolvePlatformSupportSeparatesScanAndRemediation(t *testing.T) {
	t.Parallel()

	supported := model.ScanSupportSupported
	tested := model.ScanSupportTested
	pending := model.Verification{State: model.VerificationPending}
	rejected := model.Verification{State: model.VerificationRejected}
	bundle := Bundle{Layers: []model.BindingLayer{
		{
			SchemaVersion: 1,
			ID:            "linux-common",
			Priority:      100,
			Selector:      model.PlatformSelector{OS: "linux"},
			ScanSupport:   &supported,
			Bindings:      []model.RuleBinding{},
		},
		{
			SchemaVersion:        1,
			ID:                   "rocky-9.8-amd64",
			Priority:             300,
			Selector:             model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
			ScanSupport:          &tested,
			PlatformVerification: &pending,
			Bindings:             []model.RuleBinding{},
		},
		{
			SchemaVersion:        1,
			ID:                   "rocky-9.8-amd64-rejected-remediation",
			Priority:             400,
			Selector:             model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
			PlatformVerification: &rejected,
			Bindings:             []model.RuleBinding{},
		},
	}}

	resolved, err := bundle.ResolvePlatformSupport(rockyLinux98Platform())
	if err != nil {
		t.Fatalf("ResolvePlatformSupport() error = %v", err)
	}
	if resolved.ScanSupport != model.ScanSupportTested {
		t.Fatalf("ScanSupport = %q, want %q", resolved.ScanSupport, model.ScanSupportTested)
	}
	if resolved.RemediationSupport != model.RemediationSupportUnsupported {
		t.Fatalf("RemediationSupport = %q, want %q", resolved.RemediationSupport, model.RemediationSupportUnsupported)
	}
}

func TestDefaultPlatformSupportUsesLinuxCommonAndExactTestedEnvironment(t *testing.T) {
	t.Parallel()

	bundle, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}

	rocky := rockyLinux98Platform()
	resolvedRocky, err := bundle.ResolvePlatformSupport(rocky)
	if err != nil {
		t.Fatalf("ResolvePlatformSupport(Rocky) error = %v", err)
	}
	if resolvedRocky.ScanSupport != model.ScanSupportTested {
		t.Fatalf("Rocky ScanSupport = %q, want %q", resolvedRocky.ScanSupport, model.ScanSupportTested)
	}
	if resolvedRocky.RemediationSupport != model.RemediationSupportTargeted {
		t.Fatalf("Rocky RemediationSupport = %q, want %q", resolvedRocky.RemediationSupport, model.RemediationSupportTargeted)
	}

	ubuntu := rocky
	ubuntu.ID = "ubuntu"
	ubuntu.Name = "Ubuntu 24.04 LTS"
	ubuntu.VersionID = "24.04"
	ubuntu.Family = "debian"
	ubuntu.PackageManager = "apt"
	resolvedUbuntu, err := bundle.ResolvePlatformSupport(ubuntu)
	if err != nil {
		t.Fatalf("ResolvePlatformSupport(Ubuntu) error = %v", err)
	}
	if resolvedUbuntu.ScanSupport != model.ScanSupportSupported {
		t.Fatalf("Ubuntu ScanSupport = %q, want %q", resolvedUbuntu.ScanSupport, model.ScanSupportSupported)
	}
	if resolvedUbuntu.RemediationSupport != model.RemediationSupportUnsupported {
		t.Fatalf("Ubuntu RemediationSupport = %q, want %q", resolvedUbuntu.RemediationSupport, model.RemediationSupportUnsupported)
	}

	arm64Rocky := rocky
	arm64Rocky.Architecture = "arm64"
	resolvedARM64, err := bundle.ResolvePlatformSupport(arm64Rocky)
	if err != nil {
		t.Fatalf("ResolvePlatformSupport(Rocky arm64) error = %v", err)
	}
	if resolvedARM64.ScanSupport != model.ScanSupportSupported {
		t.Fatalf("Rocky arm64 ScanSupport = %q, want %q", resolvedARM64.ScanSupport, model.ScanSupportSupported)
	}
	if resolvedARM64.RemediationSupport != model.RemediationSupportUnsupported {
		t.Fatalf("Rocky arm64 RemediationSupport = %q, want %q", resolvedARM64.RemediationSupport, model.RemediationSupportUnsupported)
	}
}

func rockyLinux98Platform() model.PlatformInfo {
	return model.PlatformInfo{
		OS:           "linux",
		Family:       "rhel",
		ID:           "rocky",
		Name:         "Rocky Linux 9.8",
		VersionID:    "9.8",
		Architecture: "amd64",
	}
}
