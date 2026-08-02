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
			name:      "tested scan support rejects extra os selector",
			selector:  "  os: linux\n  id: rocky\n  version: \"9.8\"\n  architecture: amd64\n",
			fields:    "scan_support: tested\n",
			wantError: true,
		},
		{
			name:      "remediation verification requires exact version",
			selector:  "  family: rhel\n  version_major: \"9\"\n",
			fields:    "platform_verification:\n  state: pending\n",
			wantError: true,
		},
		{
			name:      "remediation verification requires architecture",
			selector:  "  id: rocky\n  version: \"9.8\"\n",
			fields:    "platform_verification:\n  state: pending\n",
			wantError: true,
		},
		{
			name:      "remediation verification rejects uppercase exact id",
			selector:  "  id: Rocky\n  version: \"9.8\"\n  architecture: amd64\n",
			fields:    "platform_verification:\n  state: pending\n",
			wantError: true,
		},
		{
			name:      "remediation verification rejects Unicode exact id",
			selector:  "  id: Σ\n  version: \"9.8\"\n  architecture: amd64\n",
			fields:    "platform_verification:\n  state: pending\n",
			wantError: true,
		},
		{
			name:     "remediation verification accepts exact environment",
			selector: "  id: rocky\n  version: \"9.8\"\n  architecture: amd64\n",
			fields:   "platform_verification:\n  state: pending\n",
		},
		{
			name:      "remediation verification rejects extra family selector",
			selector:  "  family: rhel\n  id: rocky\n  version: \"9.8\"\n  architecture: amd64\n",
			fields:    "platform_verification:\n  state: pending\n",
			wantError: true,
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

func TestResolveScanOnlyTestedPlatformKeepsRemediationUnsupported(t *testing.T) {
	t.Parallel()

	tested := model.ScanSupportTested
	bundle := Bundle{Layers: []model.BindingLayer{{
		SchemaVersion: 1,
		ID:            "example-1.0-amd64",
		Priority:      300,
		Selector:      model.PlatformSelector{ID: "example", Version: "1.0", Architecture: "amd64"},
		ScanSupport:   &tested,
		Bindings:      []model.RuleBinding{},
	}}}
	platform := model.PlatformInfo{OS: "linux", ID: "example", VersionID: "1.0", Architecture: "amd64"}
	resolved, err := bundle.ResolvePlatformSupport(platform)
	if err != nil {
		t.Fatalf("ResolvePlatformSupport() error = %v", err)
	}
	if resolved.ScanSupport != model.ScanSupportTested {
		t.Fatalf("ScanSupport = %q, want tested", resolved.ScanSupport)
	}
	if resolved.RemediationSupport != model.RemediationSupportUnsupported {
		t.Fatalf("RemediationSupport = %q, want unsupported", resolved.RemediationSupport)
	}
}

func TestResolvePlatformSupportSeparatesScanAndRemediation(t *testing.T) {
	t.Parallel()

	supported := model.ScanSupportSupported
	tested := model.ScanSupportTested
	pending := model.Verification{State: model.VerificationPending}
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
	}}

	resolved, err := bundle.ResolvePlatformSupport(rockyLinux98Platform())
	if err != nil {
		t.Fatalf("ResolvePlatformSupport() error = %v", err)
	}
	if resolved.ScanSupport != model.ScanSupportTested {
		t.Fatalf("ScanSupport = %q, want %q", resolved.ScanSupport, model.ScanSupportTested)
	}
	if resolved.RemediationSupport != model.RemediationSupportTargeted {
		t.Fatalf("RemediationSupport = %q, want %q", resolved.RemediationSupport, model.RemediationSupportTargeted)
	}
}

func TestResolvePlatformSupportRejectsOverlappingExactVerificationSelectors(t *testing.T) {
	t.Parallel()

	pending := model.Verification{State: model.VerificationPending}
	rejected := model.Verification{State: model.VerificationRejected}
	bundle := Bundle{Layers: []model.BindingLayer{
		{
			SchemaVersion:        1,
			ID:                   "rocky-plain",
			Priority:             300,
			Selector:             model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
			PlatformVerification: &pending,
			Bindings:             []model.RuleBinding{},
		},
		{
			SchemaVersion:        1,
			ID:                   "rocky-linux",
			Priority:             400,
			Selector:             model.PlatformSelector{OS: "linux", Family: "rhel", ID: "rocky", Version: "9.8", Architecture: "amd64"},
			PlatformVerification: &rejected,
			Bindings:             []model.RuleBinding{},
		},
	}}

	if _, err := bundle.ResolvePlatformSupport(rockyLinux98Platform()); err == nil {
		t.Fatal("ResolvePlatformSupport() accepted overlapping exact platform verification selectors")
	}
}

func TestDefaultPlatformSupportUsesOnlyExactTestedEnvironments(t *testing.T) {
	t.Parallel()

	bundle, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}

	tested := []model.PlatformInfo{
		{OS: "linux", Family: "rhel", ID: "centos", VersionID: "8.5.2111", Architecture: "amd64"},
		{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.5", Architecture: "amd64"},
		{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.6", Architecture: "amd64"},
		{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.7", Architecture: "amd64"},
		rockyLinux98Platform(),
		{OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "18.04", Architecture: "amd64"},
		{OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "20.04", Architecture: "amd64"},
		{OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "22.04", Architecture: "amd64"},
		{OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "24.04", Architecture: "amd64"},
		{OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "26.04", Architecture: "amd64"},
	}
	for _, platform := range tested {
		platform := platform
		t.Run(platform.ID+"-"+platform.VersionID, func(t *testing.T) {
			resolved, resolveErr := bundle.ResolvePlatformSupport(platform)
			if resolveErr != nil {
				t.Fatalf("ResolvePlatformSupport() error = %v", resolveErr)
			}
			if resolved.ScanSupport != model.ScanSupportTested {
				t.Fatalf("ScanSupport = %q, want %q", resolved.ScanSupport, model.ScanSupportTested)
			}
			wantRemediation := defaultRemediationSupportForExactPlatform(t, bundle, platform)
			if resolved.RemediationSupport != wantRemediation {
				t.Fatalf("RemediationSupport = %q, want %q", resolved.RemediationSupport, wantRemediation)
			}
		})
	}

	broadOnly := []model.PlatformInfo{
		{OS: "linux", Family: "rhel", ID: "centos", VersionID: "8", Architecture: "amd64"},
		{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.4", Architecture: "amd64"},
		{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.8", Architecture: "arm64"},
		{OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "23.10", Architecture: "amd64"},
		{OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "24.04", Architecture: "arm64"},
	}
	for _, platform := range broadOnly {
		platform := platform
		t.Run("broad-"+platform.ID+"-"+platform.VersionID+"-"+platform.Architecture, func(t *testing.T) {
			resolved, resolveErr := bundle.ResolvePlatformSupport(platform)
			if resolveErr != nil {
				t.Fatalf("ResolvePlatformSupport() error = %v", resolveErr)
			}
			if resolved.ScanSupport != model.ScanSupportSupported {
				t.Fatalf("ScanSupport = %q, want %q", resolved.ScanSupport, model.ScanSupportSupported)
			}
			if resolved.RemediationSupport != model.RemediationSupportUnsupported {
				t.Fatalf("RemediationSupport = %q, want %q", resolved.RemediationSupport, model.RemediationSupportUnsupported)
			}
		})
	}
}

func defaultRemediationSupportForExactPlatform(t *testing.T, bundle Bundle, platform model.PlatformInfo) model.RemediationSupportLevel {
	t.Helper()
	for _, layer := range bundle.Layers {
		if layer.Selector.ID != platform.ID ||
			layer.Selector.Version != platform.VersionID ||
			layer.Selector.Architecture != platform.Architecture ||
			layer.PlatformVerification == nil {
			continue
		}
		switch layer.PlatformVerification.State {
		case model.VerificationPending:
			return model.RemediationSupportTargeted
		case model.VerificationVerified:
			return model.RemediationSupportVerified
		case model.VerificationRejected:
			return model.RemediationSupportUnsupported
		default:
			t.Fatalf("platform layer %s has invalid verification state %q", layer.ID, layer.PlatformVerification.State)
		}
	}
	return model.RemediationSupportUnsupported
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
