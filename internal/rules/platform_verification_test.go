package rules

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestLoadBindingPlatformVerificationRequiresExactSelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		selector  string
		wantError bool
	}{
		{
			name:      "operating system selector",
			selector:  "  os: linux\n",
			wantError: true,
		},
		{
			name:      "family major selector",
			selector:  "  family: rhel\n  version_major: \"9\"\n",
			wantError: true,
		},
		{
			name:      "exact selector mixed with major",
			selector:  "  id: rocky\n  version: \"9.8\"\n  version_major: \"9\"\n",
			wantError: true,
		},
		{
			name:     "exact distribution version selector",
			selector: "  id: rocky\n  version: \"9.8\"\n",
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
				"platform_verification:\n" +
				"  state: pending\n" +
				"  environments: [Rocky Linux 9.8]\n" +
				"bindings: []\n"
			loader := NewLoader(fstest.MapFS{
				"platform.yaml": &fstest.MapFile{Data: []byte(data)},
			})
			layer, err := loader.LoadBinding("platform.yaml")
			if test.wantError {
				if err == nil {
					t.Fatal("LoadBinding() succeeded for a non-exact platform verification selector")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadBinding() error = %v", err)
			}
			if layer.PlatformVerification == nil || layer.PlatformVerification.State != model.VerificationPending {
				t.Fatalf("PlatformVerification = %#v, want pending metadata", layer.PlatformVerification)
			}
		})
	}
}

func TestResolvePlatformSupportMapsVerificationState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		verification model.Verification
		wantSupport  model.SupportLevel
		wantWarning  bool
	}{
		{
			name: "pending",
			verification: model.Verification{
				State:        model.VerificationPending,
				Environments: []string{"Rocky Linux 9.8"},
			},
			wantSupport: model.SupportTargeted,
			wantWarning: true,
		},
		{
			name: "verified",
			verification: model.Verification{
				State:        model.VerificationVerified,
				Environments: []string{"Rocky Linux 9.8"},
				VerifiedAt:   "2026-07-11T00:00:00Z",
			},
			wantSupport: model.SupportVerified,
		},
		{
			name: "rejected",
			verification: model.Verification{
				State:        model.VerificationRejected,
				Environments: []string{"Rocky Linux 9.8"},
			},
			wantSupport: model.SupportUnsupported,
			wantWarning: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bundle := Bundle{Layers: []model.BindingLayer{
				platformVerificationLayer("rocky-9.8", 300, test.verification),
			}}
			resolved, err := bundle.ResolvePlatformSupport(rockyLinux98Platform())
			if err != nil {
				t.Fatalf("ResolvePlatformSupport() error = %v", err)
			}
			if resolved.Support != test.wantSupport {
				t.Fatalf("Support = %q, want %q", resolved.Support, test.wantSupport)
			}
			if got := strings.TrimSpace(resolved.VerificationWarning) != ""; got != test.wantWarning {
				t.Fatalf("warning present = %t, want %t; warning = %q", got, test.wantWarning, resolved.VerificationWarning)
			}
		})
	}
}

func TestResolvePlatformSupportUsesDeterministicLayerPrecedence(t *testing.T) {
	t.Parallel()

	pending := model.Verification{State: model.VerificationPending, Environments: []string{"pending environment"}}
	verified := model.Verification{State: model.VerificationVerified, Environments: []string{"verified environment"}, VerifiedAt: "2026-07-11T00:00:00Z"}
	rejected := model.Verification{State: model.VerificationRejected, Environments: []string{"rejected environment"}}
	bundle := Bundle{Layers: []model.BindingLayer{
		platformVerificationLayer("z-last-at-tied-priority", 400, rejected),
		platformVerificationLayer("lower-priority", 100, pending),
		platformVerificationLayer("a-first-at-tied-priority", 400, verified),
	}}

	resolved, err := bundle.ResolvePlatformSupport(rockyLinux98Platform())
	if err != nil {
		t.Fatalf("ResolvePlatformSupport() error = %v", err)
	}
	if resolved.Support != model.SupportUnsupported {
		t.Fatalf("Support = %q, want %q from lexically last tied layer", resolved.Support, model.SupportUnsupported)
	}
	if !strings.Contains(resolved.VerificationWarning, "rejected environment") {
		t.Fatalf("VerificationWarning = %q, want selected layer environment", resolved.VerificationWarning)
	}
}

func TestResolvePlatformSupportLeavesUnmatchedPlatformUnsupported(t *testing.T) {
	t.Parallel()

	bundle := Bundle{Layers: []model.BindingLayer{
		platformVerificationLayer("rocky-9.8", 300, model.Verification{
			State:        model.VerificationPending,
			Environments: []string{"Rocky Linux 9.8"},
		}),
	}}
	platform := rockyLinux98Platform()
	platform.VersionID = "9.7"

	resolved, err := bundle.ResolvePlatformSupport(platform)
	if err != nil {
		t.Fatalf("ResolvePlatformSupport() error = %v", err)
	}
	if resolved.Support != model.SupportUnsupported {
		t.Fatalf("Support = %q, want %q", resolved.Support, model.SupportUnsupported)
	}
	if resolved.VerificationWarning != unmatchedPlatformVerificationWarning {
		t.Fatalf("VerificationWarning = %q, want %q", resolved.VerificationWarning, unmatchedPlatformVerificationWarning)
	}
}

func TestResolvePlatformSupportDoesNotPromoteFromRuleVerification(t *testing.T) {
	t.Parallel()

	verified := model.Verification{
		State:        model.VerificationVerified,
		Environments: []string{"Rocky Linux 9.8"},
		VerifiedAt:   "2026-07-11T00:00:00Z",
	}
	bundle := Bundle{Layers: []model.BindingLayer{
		{
			SchemaVersion: 1,
			ID:            "rocky-rule-verification-only",
			Priority:      300,
			Selector:      model.PlatformSelector{ID: "rocky", Version: "9.8"},
			Defaults:      model.BindingDefaults{Verification: &verified},
			Bindings:      []model.RuleBinding{},
		},
	}}

	resolved, err := bundle.ResolvePlatformSupport(rockyLinux98Platform())
	if err != nil {
		t.Fatalf("ResolvePlatformSupport() error = %v", err)
	}
	if resolved.Support != model.SupportUnsupported {
		t.Fatalf("Support = %q, want %q without platform verification", resolved.Support, model.SupportUnsupported)
	}
}

func TestResolvePlatformSupportCanNarrowVerificationByArchitecture(t *testing.T) {
	t.Parallel()

	pending := model.Verification{State: model.VerificationPending, Environments: []string{"Rocky Linux 9.8"}}
	verified := model.Verification{State: model.VerificationVerified, Environments: []string{"Rocky Linux 9.8 amd64"}, VerifiedAt: "2026-07-11T00:00:00Z"}
	allArchitectures := platformVerificationLayer("rocky-9.8", 300, pending)
	amd64 := platformVerificationLayer("rocky-9.8-amd64", 400, verified)
	amd64.Selector.Architecture = "amd64"
	bundle := Bundle{Layers: []model.BindingLayer{amd64, allArchitectures}}

	resolvedAMD64, err := bundle.ResolvePlatformSupport(rockyLinux98Platform())
	if err != nil {
		t.Fatalf("ResolvePlatformSupport(amd64) error = %v", err)
	}
	if resolvedAMD64.Support != model.SupportVerified {
		t.Fatalf("amd64 Support = %q, want %q", resolvedAMD64.Support, model.SupportVerified)
	}

	arm64Platform := rockyLinux98Platform()
	arm64Platform.Architecture = "arm64"
	resolvedARM64, err := bundle.ResolvePlatformSupport(arm64Platform)
	if err != nil {
		t.Fatalf("ResolvePlatformSupport(arm64) error = %v", err)
	}
	if resolvedARM64.Support != model.SupportTargeted {
		t.Fatalf("arm64 Support = %q, want %q", resolvedARM64.Support, model.SupportTargeted)
	}
}

func TestDefaultRockyLinux98PlatformVerificationRemainsPending(t *testing.T) {
	t.Parallel()

	bundle, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	resolved, err := bundle.ResolvePlatformSupport(rockyLinux98Platform())
	if err != nil {
		t.Fatalf("ResolvePlatformSupport() error = %v", err)
	}
	if resolved.Support != model.SupportTargeted {
		t.Fatalf("Support = %q, want %q", resolved.Support, model.SupportTargeted)
	}
	if !strings.Contains(resolved.VerificationWarning, "Rocky Linux 9.8") {
		t.Fatalf("VerificationWarning = %q, want Rocky Linux 9.8 pending warning", resolved.VerificationWarning)
	}
}

func platformVerificationLayer(id string, priority int, verification model.Verification) model.BindingLayer {
	return model.BindingLayer{
		SchemaVersion:        1,
		ID:                   id,
		Priority:             priority,
		Selector:             model.PlatformSelector{ID: "rocky", Version: "9.8"},
		PlatformVerification: &verification,
		Bindings:             []model.RuleBinding{},
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
