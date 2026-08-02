package workflow

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/buildinfo"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	recipecatalog "github.com/yesidodo73/OpenCIIP/internal/remediation/recipe"
	rulecatalog "github.com/yesidodo73/OpenCIIP/internal/rules"
)

func TestLegacyJournalCannotBeApprovedOrApplied(t *testing.T) {
	t.Parallel()

	_, err := (&Workflow{}).verifyJournalExecutionState(context.Background(), &model.RemediationJournal{
		SchemaVersion: 2,
	}, false)
	if err == nil || !strings.Contains(err.Error(), "이전 형식") {
		t.Fatalf("verifyJournalExecutionState() error = %v, want legacy-plan rejection", err)
	}
}

func TestFreshEffectGateChecksOnlyCurrentChangeSet(t *testing.T) {
	t.Parallel()

	journalValue := &model.RemediationJournal{
		ChangeSets: []model.ChangeSet{
			{ID: "change-a", RuleID: "U-19"},
			{ID: "change-b", RuleID: "U-22"},
		},
	}
	freshResults := map[string]model.CheckResult{
		"U-19": {RuleID: "U-19", Status: model.StatusPass},
		"U-22": {RuleID: "U-22", Status: model.StatusFail},
	}
	current, err := selectExecutionChangeSets(journalValue, []string{"change-b"})
	if err != nil {
		t.Fatalf("selectExecutionChangeSets() error = %v", err)
	}
	if err := requireFreshFail(current, freshResults); err != nil {
		t.Fatalf("current change-set FAIL was rejected because an earlier change set is now PASS: %v", err)
	}
	all, err := selectExecutionChangeSets(journalValue, nil)
	if err != nil {
		t.Fatalf("selectExecutionChangeSets(all) error = %v", err)
	}
	if err := requireFreshFail(all, freshResults); err == nil || !strings.Contains(err.Error(), "U-19") {
		t.Fatalf("whole-run FAIL gate error = %v, want earlier PASS rejection", err)
	}
}

func TestExecutionBuildIdentityRequiresStableCleanRelease(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("a", 64)
	stable := model.RemediationBuildIdentity{
		Version:          "0.1.0",
		Commit:           "0123456789abcdef0123456789abcdef01234567",
		ExecutableSHA256: digest,
	}
	cleanProvenance := func(commit string) buildinfo.VCSProvenance {
		return buildinfo.VCSProvenance{
			Revision:        commit,
			RevisionPresent: true,
			Modified:        "false",
			ModifiedPresent: true,
		}
	}
	if err := validateExecutionBuildIdentity(stable, cleanProvenance(stable.Commit), true); err != nil {
		t.Fatalf("stable clean build was rejected: %v", err)
	}
	stable.Commit = strings.Repeat("0123456789abcdef", 4)
	if err := validateExecutionBuildIdentity(stable, cleanProvenance(stable.Commit), true); err != nil {
		t.Fatalf("stable clean SHA-256 build was rejected: %v", err)
	}
	stable.Commit = "0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name  string
		value model.RemediationBuildIdentity
	}{
		{name: "development version", value: model.RemediationBuildIdentity{Version: "dev", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "unknown version", value: model.RemediationBuildIdentity{Version: "unknown", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "missing patch version", value: model.RemediationBuildIdentity{Version: "1.2", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "leading zero", value: model.RemediationBuildIdentity{Version: "01.2.3", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "version prefix", value: model.RemediationBuildIdentity{Version: "v1.2.3", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "unknown commit", value: model.RemediationBuildIdentity{Version: stable.Version, Commit: "unknown", ExecutableSHA256: digest}},
		{name: "prerelease", value: model.RemediationBuildIdentity{Version: "0.1.0-alpha.37", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "build metadata", value: model.RemediationBuildIdentity{Version: "0.1.0+build.37", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "dirty metadata without modified flag", value: model.RemediationBuildIdentity{Version: "0.1.0+dirty", Commit: stable.Commit, ExecutableSHA256: digest}},
		{name: "modified", value: model.RemediationBuildIdentity{Version: stable.Version, Commit: stable.Commit, ExecutableSHA256: digest, Modified: true}},
		{name: "short commit", value: model.RemediationBuildIdentity{Version: stable.Version, Commit: strings.Repeat("0", 39), ExecutableSHA256: digest}},
		{name: "uppercase commit", value: model.RemediationBuildIdentity{Version: stable.Version, Commit: strings.Repeat("A", 40), ExecutableSHA256: digest}},
		{name: "non-hex commit", value: model.RemediationBuildIdentity{Version: stable.Version, Commit: strings.Repeat("g", 40), ExecutableSHA256: digest}},
		{name: "SHA-1 null commit", value: model.RemediationBuildIdentity{Version: stable.Version, Commit: strings.Repeat("0", 40), ExecutableSHA256: digest}},
		{name: "SHA-256 null commit", value: model.RemediationBuildIdentity{Version: stable.Version, Commit: strings.Repeat("0", 64), ExecutableSHA256: digest}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			provenance := cleanProvenance(test.value.Commit)
			if err := validateExecutionBuildIdentity(test.value, provenance, true); err == nil {
				t.Fatal("release-only execution accepted an unsafe build identity")
			}
			if err := validateExecutionBuildIdentity(test.value, provenance, false); err != nil {
				t.Fatalf("planning rejected a structurally valid build identity: %v", err)
			}
		})
	}
}

func TestExecutionBuildIdentityRequiresGoVCSProvenance(t *testing.T) {
	t.Parallel()

	commit := "0123456789abcdef0123456789abcdef01234567"
	build := model.RemediationBuildIdentity{
		Version:          "1.0.0",
		Commit:           commit,
		ExecutableSHA256: strings.Repeat("a", 64),
	}
	clean := buildinfo.VCSProvenance{
		Revision:        commit,
		RevisionPresent: true,
		Modified:        "false",
		ModifiedPresent: true,
	}
	tests := []struct {
		name       string
		provenance buildinfo.VCSProvenance
	}{
		{name: "buildvcs disabled with ldflags identity"},
		{
			name: "revision setting missing",
			provenance: buildinfo.VCSProvenance{
				Revision: commit, Modified: "false", ModifiedPresent: true,
			},
		},
		{
			name: "modified setting missing",
			provenance: buildinfo.VCSProvenance{
				Revision: commit, RevisionPresent: true,
			},
		},
		{
			name: "revision mismatch",
			provenance: buildinfo.VCSProvenance{
				Revision: strings.Repeat("b", 40), RevisionPresent: true,
				Modified: "false", ModifiedPresent: true,
			},
		},
		{
			name: "modified true",
			provenance: buildinfo.VCSProvenance{
				Revision: commit, RevisionPresent: true,
				Modified: "true", ModifiedPresent: true,
			},
		},
		{
			name: "modified value not canonical",
			provenance: buildinfo.VCSProvenance{
				Revision: commit, RevisionPresent: true,
				Modified: "False", ModifiedPresent: true,
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateExecutionBuildIdentity(build, test.provenance, true); err == nil {
				t.Fatal("release-only execution accepted missing or inconsistent Go VCS provenance")
			}
			if err := validateExecutionBuildIdentity(build, test.provenance, false); err != nil {
				t.Fatalf("planning rejected a structurally valid development build: %v", err)
			}
		})
	}
	if err := validateExecutionBuildIdentity(build, clean, true); err != nil {
		t.Fatalf("explicit clean Go VCS provenance was rejected: %v", err)
	}
}

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
			verification := model.Verification{
				State:        model.VerificationVerified,
				Environments: []string{"Rocky Linux 9.8"},
				VerifiedAt:   "2026-07-11T12:34:56Z",
			}
			current := gateSnapshot{
				platform: model.PlatformInfo{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.8", Architecture: "amd64"},
				recipes:  registry,
				rules: rulecatalog.Bundle{
					Catalog: model.Catalog{Rules: []model.RuleDefinition{{ID: "U-19"}}},
					Layers: []model.BindingLayer{
						{
							SchemaVersion: 1,
							ID:            "rocky-9.8-amd64",
							Priority:      300,
							Selector:      model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"},
							Bindings: []model.RuleBinding{
								{RuleID: "U-19", Verification: &verification},
							},
						},
					},
				},
			}
			resolved := model.ResolvedRule{
				RuleDefinition: model.RuleDefinition{ID: "U-19"},
				Applicable:     true,
				Verification:   verification,
				BindingSources: []string{"rocky-9.8-amd64"},
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

func TestEligibleRecipeRejectsBroadRuleVerificationProvenance(t *testing.T) {
	t.Parallel()

	verification := model.Verification{
		State:        model.VerificationVerified,
		Environments: []string{"Linux amd64"},
		VerifiedAt:   "2026-07-11T12:34:56Z",
	}
	current := gateSnapshot{
		platform: model.PlatformInfo{OS: "linux", Family: "rhel", ID: "rocky", VersionID: "9.8", Architecture: "amd64"},
		recipes:  loadRecipeRegistryForVerificationTest(t, model.RemediationRecipeVerificationVerified),
		rules: rulecatalog.Bundle{
			Catalog: model.Catalog{Rules: []model.RuleDefinition{{ID: "U-19"}}},
			Layers: []model.BindingLayer{
				{
					SchemaVersion: 1,
					ID:            "linux-wide",
					Priority:      100,
					Selector:      model.PlatformSelector{OS: "linux"},
					Bindings: []model.RuleBinding{
						{RuleID: "U-19", Verification: &verification},
					},
				},
			},
		},
	}
	_, eligible, reason := (&Workflow{}).eligibleRecipe(
		model.ScanRun{Metadata: model.RunMetadata{GuideYear: 2026}},
		model.CheckResult{RuleID: "U-19", Status: model.StatusFail},
		model.ResolvedRule{
			RuleDefinition: model.RuleDefinition{ID: "U-19"},
			Applicable:     true,
			Verification:   verification,
		},
		current,
	)
	if eligible || !strings.Contains(reason, "provenance") {
		t.Fatalf("eligible = %t, reason = %q; want broad rule verification rejection", eligible, reason)
	}
}

func TestValidateReportCompatibilityRequiresSameExecutableIdentity(t *testing.T) {
	t.Parallel()

	digest := strings.Repeat("a", 64)
	platform := model.PlatformInfo{
		OS:                 "linux",
		Family:             "rhel",
		ID:                 "rocky",
		VersionID:          "9.8",
		Architecture:       "amd64",
		ScanSupport:        model.ScanSupportTested,
		RemediationSupport: model.RemediationSupportVerified,
	}
	current := gateSnapshot{
		platform: platform,
		rules:    rulecatalog.Bundle{Version: "sha256:" + strings.Repeat("b", 64)},
		build: model.RemediationBuildIdentity{
			Version:          "0.1.0-alpha.36",
			Commit:           "commit-36",
			ExecutableSHA256: digest,
		},
	}
	base := model.ScanRun{Metadata: model.RunMetadata{
		ToolVersion:          current.build.Version,
		ToolCommit:           current.build.Commit,
		ToolExecutableSHA256: current.build.ExecutableSHA256,
		GuideYear:            2026,
		RuleSetVersion:       current.rules.Version,
		Platform:             platform,
		Redaction:            true,
		Complete:             true,
	}}
	if err := (&Workflow{}).validateReportCompatibility(base, current); err != nil {
		t.Fatalf("validateReportCompatibility() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*model.RunMetadata)
	}{
		{
			name: "version",
			mutate: func(metadata *model.RunMetadata) {
				metadata.ToolVersion = "0.1.0-alpha.35"
			},
		},
		{
			name: "commit",
			mutate: func(metadata *model.RunMetadata) {
				metadata.ToolCommit = "different-commit"
			},
		},
		{
			name: "executable digest",
			mutate: func(metadata *model.RunMetadata) {
				metadata.ToolExecutableSHA256 = strings.Repeat("c", 64)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			scan := base
			test.mutate(&scan.Metadata)
			err := (&Workflow{}).validateReportCompatibility(scan, current)
			if err == nil || !strings.Contains(err.Error(), "점검 실행 파일") {
				t.Fatalf("validateReportCompatibility() error = %v, want executable identity rejection", err)
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
      architecture: amd64
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
