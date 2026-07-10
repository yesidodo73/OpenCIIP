package workflow

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	recipecatalog "github.com/yesidodo73/OpenCIIP/internal/remediation/recipe"
)

func TestRequireVerifiedRecipeFailsClosed(t *testing.T) {
	t.Parallel()

	valid := model.RemediationRecipe{
		RuleID: "U-19",
		Verification: model.RemediationRecipeVerification{
			State:          model.RemediationRecipeVerificationVerified,
			Environments:   []string{"Rocky Linux 9.8 amd64"},
			VerifiedAt:     "2026-07-11T12:34:56Z",
			EvidenceSHA256: []string{strings.Repeat("a", 64)},
		},
	}
	tests := []struct {
		name    string
		value   model.RemediationRecipe
		wantErr bool
	}{
		{
			name:    "pending",
			value:   model.RemediationRecipe{RuleID: "U-19", Verification: model.RemediationRecipeVerification{State: model.RemediationRecipeVerificationPending}},
			wantErr: true,
		},
		{
			name:    "rejected",
			value:   model.RemediationRecipe{RuleID: "U-19", Verification: model.RemediationRecipeVerification{State: model.RemediationRecipeVerificationRejected}},
			wantErr: true,
		},
		{
			name: "verified without provenance",
			value: model.RemediationRecipe{
				RuleID:       "U-19",
				Verification: model.RemediationRecipeVerification{State: model.RemediationRecipeVerificationVerified},
			},
			wantErr: true,
		},
		{name: "verified with provenance", value: valid},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := requireVerifiedRecipe(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("requireVerifiedRecipe() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestEligibleRecipeRequiresVerifiedRecipe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    model.RemediationRecipeVerificationState
		eligible bool
	}{
		{state: model.RemediationRecipeVerificationPending},
		{state: model.RemediationRecipeVerificationRejected},
		{state: model.RemediationRecipeVerificationVerified, eligible: true},
	}

	for _, test := range tests {
		test := test
		t.Run(string(test.state), func(t *testing.T) {
			t.Parallel()
			registry := loadRecipeRegistryForVerificationTest(t, test.state)
			current := gateSnapshot{
				platform: model.PlatformInfo{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.8"},
				recipes:  registry,
			}
			resolved := model.ResolvedRule{
				RuleDefinition: model.RuleDefinition{ID: "U-19"},
				Applicable:     true,
				Verification: model.Verification{
					State:        model.VerificationVerified,
					Environments: []string{"Rocky Linux 9.8"},
					VerifiedAt:   "2026-07-11T12:34:56Z",
				},
			}
			_, eligible, reason := (&Workflow{}).eligibleRecipe(
				model.ScanRun{Metadata: model.RunMetadata{GuideYear: 2026}},
				model.CheckResult{RuleID: "U-19", Status: model.StatusFail},
				resolved,
				current,
			)
			if eligible != test.eligible {
				t.Fatalf("eligible = %t, want %t; reason = %q", eligible, test.eligible, reason)
			}
			if !test.eligible && !strings.Contains(reason, "조치 정의") {
				t.Fatalf("reason = %q, want recipe verification rejection", reason)
			}
		})
	}
}

func loadRecipeRegistryForVerificationTest(t *testing.T, state model.RemediationRecipeVerificationState) *recipecatalog.Registry {
	t.Helper()
	completed := ""
	if state == model.RemediationRecipeVerificationVerified {
		completed = fmt.Sprintf("      verified_at: \"2026-07-11T12:34:56Z\"\n      evidence_sha256: [%s]\n", strings.Repeat("a", 64))
	}
	data := fmt.Sprintf(`schema_version: 1
recipes:
  - id: u19-hosts-permissions-rocky-9.8
    guide_year: 2026
    rule_id: U-19
    selector:
      id: rocky
      version: "9.8"
    verification:
      state: %s
      environments: [Rocky Linux 9.8 amd64]
%s    risk: CAUTION
    expected_impact: 허용되지 않은 파일 메타데이터만 최소 변경합니다.
    operations:
      - type: preserve_content_file_metadata
        path: /etc/hosts
        allowed_owners: [root]
        remediation_owner: root
        maximum_mode: "0644"
`, state, completed)
	registry, err := recipecatalog.Load(fstest.MapFS{
		"recipes/catalog.yaml": {Data: []byte(data)},
	}, "recipes")
	if err != nil {
		t.Fatalf("recipe.Load() error = %v", err)
	}
	return registry
}
