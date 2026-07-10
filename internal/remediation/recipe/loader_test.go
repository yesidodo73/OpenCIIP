package recipe

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
)

func TestLoadPreservesRecipeVerification(t *testing.T) {
	evidenceDigest := strings.Repeat("a", 64)
	source := fstest.MapFS{
		"recipes/verified.yaml": {
			Data: []byte(fmt.Sprintf(`schema_version: 1
recipes:
  - id: u19-hosts-permissions-rocky-9.8
    guide_year: 2026
    rule_id: U-19
    selector:
      id: rocky
      version: "9.8"
    verification:
      state: verified
      environments:
        - Rocky Linux 9.8 amd64
      verified_at: "2026-07-11T12:34:56Z"
      evidence_sha256:
        - %s
    risk: CAUTION
    expected_impact: 허용되지 않은 파일 메타데이터만 최소 변경합니다.
    operations:
      - type: preserve_content_file_metadata
        path: /etc/hosts
        allowed_owners: [root]
        remediation_owner: root
        maximum_mode: "0644"
`, evidenceDigest)),
		},
	}

	registry, err := Load(source, "recipes")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	all := registry.All()
	if len(all) != 1 {
		t.Fatalf("All() returned %d recipes, want 1", len(all))
	}
	want := model.RemediationRecipeVerification{
		State:          model.RemediationRecipeVerificationVerified,
		Environments:   []string{"Rocky Linux 9.8 amd64"},
		VerifiedAt:     "2026-07-11T12:34:56Z",
		EvidenceSHA256: []string{evidenceDigest},
	}
	if !reflect.DeepEqual(all[0].Verification, want) {
		t.Fatalf("verification = %#v, want %#v", all[0].Verification, want)
	}

	matched, ok := registry.Match("U-19", model.PlatformInfo{ID: "rocky", VersionID: "9.8"})
	if !ok {
		t.Fatal("Match() did not return the loaded recipe")
	}
	if !reflect.DeepEqual(matched.Verification, want) {
		t.Fatalf("matched verification = %#v, want %#v", matched.Verification, want)
	}

	all[0].Verification.Environments[0] = "mutated environment"
	all[0].Verification.EvidenceSHA256[0] = strings.Repeat("b", 64)
	again := registry.All()
	if !reflect.DeepEqual(again[0].Verification, want) {
		t.Fatalf("registry verification changed through clone: %#v", again[0].Verification)
	}
}

func TestLoadDefaultsKeepsBuiltInRecipesPending(t *testing.T) {
	registry, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	recipes := registry.All()
	if len(recipes) != 3 {
		t.Fatalf("All() returned %d built-in recipes, want 3", len(recipes))
	}
	for _, item := range recipes {
		if item.Verification.State != model.RemediationRecipeVerificationPending {
			t.Errorf("recipe %s verification state = %q, want pending", item.ID, item.Verification.State)
		}
		if len(item.Verification.Environments) != 1 || item.Verification.Environments[0] != "Rocky Linux 9.8" {
			t.Errorf("recipe %s environments = %#v, want Rocky Linux 9.8", item.ID, item.Verification.Environments)
		}
		if item.Verification.VerifiedAt != "" || len(item.Verification.EvidenceSHA256) != 0 {
			t.Errorf("pending recipe %s contains completed verification provenance", item.ID)
		}
	}
}

func TestCloneRecipeDigestIncludesVerification(t *testing.T) {
	original := model.RemediationRecipe{
		ID:        "u19-hosts-permissions-rocky-9.8",
		GuideYear: 2026,
		RuleID:    "U-19",
		Selector: model.PlatformSelector{
			ID:      "rocky",
			Version: "9.8",
		},
		Verification: model.RemediationRecipeVerification{
			State:          model.RemediationRecipeVerificationVerified,
			Environments:   []string{"Rocky Linux 9.8 amd64"},
			VerifiedAt:     "2026-07-11T12:34:56Z",
			EvidenceSHA256: []string{strings.Repeat("a", 64)},
		},
		Risk:           model.RiskCaution,
		ExpectedImpact: "허용되지 않은 파일 메타데이터만 최소 변경합니다.",
		Operations: []model.FileMetadataRecipeEntry{
			{
				Type:             model.RecipePreserveContentFileMetadata,
				Path:             "/etc/hosts",
				AllowedOwners:    []string{"root"},
				RemediationOwner: "root",
				MaximumMode:      "0644",
			},
		},
	}
	clone := cloneRecipe(original)

	originalDigest, err := journal.Digest(original)
	if err != nil {
		t.Fatalf("Digest(original) error = %v", err)
	}
	cloneDigest, err := journal.Digest(clone)
	if err != nil {
		t.Fatalf("Digest(clone) error = %v", err)
	}
	if cloneDigest != originalDigest {
		t.Fatalf("clone digest = %s, want %s", cloneDigest, originalDigest)
	}

	clone.Verification.Environments[0] = "Rocky Linux 9.8 arm64"
	clone.Verification.EvidenceSHA256[0] = strings.Repeat("b", 64)
	if original.Verification.Environments[0] != "Rocky Linux 9.8 amd64" {
		t.Fatal("clone shares verification environments with original")
	}
	if original.Verification.EvidenceSHA256[0] != strings.Repeat("a", 64) {
		t.Fatal("clone shares verification evidence with original")
	}
	mutatedDigest, err := journal.Digest(clone)
	if err != nil {
		t.Fatalf("Digest(mutated clone) error = %v", err)
	}
	if mutatedDigest == originalDigest {
		t.Fatal("recipe digest did not include verification metadata")
	}
}

func TestLoadRejectsRecipeWithoutVerification(t *testing.T) {
	source := fstest.MapFS{
		"recipes/missing-verification.yaml": {
			Data: []byte(`schema_version: 1
recipes:
  - id: u19-hosts-permissions-rocky-9.8
    guide_year: 2026
    rule_id: U-19
    selector:
      id: rocky
      version: "9.8"
    risk: CAUTION
    expected_impact: 허용되지 않은 파일 메타데이터만 최소 변경합니다.
    operations:
      - type: preserve_content_file_metadata
        path: /etc/hosts
        allowed_owners: [root]
        remediation_owner: root
        maximum_mode: "0644"
`),
		},
	}

	if _, err := Load(source, "recipes"); err == nil {
		t.Fatal("Load() accepted a recipe without verification metadata")
	}
}
