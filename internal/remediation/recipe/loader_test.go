package recipe

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/journal"
	rulecatalog "github.com/yesidodo73/OpenCIIP/internal/rules"
)

func TestContributorRemediationTemplateLoads(t *testing.T) {
	t.Parallel()

	catalog, err := loadCatalog(os.DirFS("../../.."), "contrib/os-support/remediation.yaml")
	if err != nil {
		t.Fatalf("load contributor remediation template: %v", err)
	}
	if len(catalog.Recipes) != 1 {
		t.Fatalf("contributor remediation template contains %d recipes, want 1", len(catalog.Recipes))
	}
	if catalog.Recipes[0].Verification.State != model.RemediationRecipeVerificationPending {
		t.Fatalf("contributor remediation template state = %q, want pending", catalog.Recipes[0].Verification.State)
	}
}

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
      architecture: amd64
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

	matched, ok := registry.Match("U-19", model.PlatformInfo{ID: "rocky", VersionID: "9.8", Architecture: "amd64"})
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

func TestLoadDefaultsIncludesVerifiedBaselineRecipes(t *testing.T) {
	registry, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	recipes := registry.All()
	type expectedPlatform struct {
		environment string
		evidence    string
	}
	baselinePlatforms := map[string]expectedPlatform{
		"centos\x008.5.2111\x00amd64": {"CentOS Linux 8.5.2111 amd64", "df4a65dca7ffdde44d044b0e22278c2f689ec65e17923da1089278e747899a7a"},
		"rocky\x009.5\x00amd64":       {"Rocky Linux 9.5 amd64", "d0c1663b3a1b21603b6a87bae00d20f01194f288b9a6285cbd9de59864223fe7"},
		"rocky\x009.6\x00amd64":       {"Rocky Linux 9.6 amd64", "ca925a76a0ca9ddbb4de9fbdd841ebaf3a8ad8a2c0ac129c9c63e8c7b31db7ec"},
		"rocky\x009.7\x00amd64":       {"Rocky Linux 9.7 amd64", "a5aeb57ed649d1f3af16b6b5b44e6d147409f1692a44bf49a5cb28d60354dc4d"},
		"rocky\x009.8\x00amd64":       {"Rocky Linux 9.8 amd64", "b0158aa89909aa50b63616d8cdf0018866fe8677071b5aa6e6907dacf5fb0f43"},
		"ubuntu\x0018.04\x00amd64":    {"Ubuntu 18.04 LTS amd64", "6f558717dcc6d71af46956e37b99464bf63ddf346e0448a792cd4dcf82e46b83"},
		"ubuntu\x0020.04\x00amd64":    {"Ubuntu 20.04 LTS amd64", "dfa2caa86128f934ab062131d53bae680b64e1e610757338aaed08d265b02459"},
		"ubuntu\x0022.04\x00amd64":    {"Ubuntu 22.04 LTS amd64", "7b4a9564739c6f475ceabc6a148f1121044b3efe9eb05e76b05d82f098742075"},
		"ubuntu\x0024.04\x00amd64":    {"Ubuntu 24.04 LTS amd64", "7dcc43ec0fd59cc5471234d0a55693bcbad6f8a6b5330661c56b7c4a419de96b"},
		"ubuntu\x0026.04\x00amd64":    {"Ubuntu 26.04 LTS amd64", "1560ca3dbc88a1fd01bf680bea1973f984b78a578fb95bb0d3be8244c8f8e49f"},
	}
	baselineRules := map[string]bool{"U-19": true, "U-22": true, "U-29": true}
	found := make(map[string]bool, len(baselinePlatforms)*len(baselineRules))
	for _, item := range recipes {
		platformKey := remediationPlatformKey(item.Selector)
		expected, baselinePlatform := baselinePlatforms[platformKey]
		if !baselinePlatform || !baselineRules[item.RuleID] {
			continue
		}
		found[platformKey+"\x00"+item.RuleID] = true
		if item.Verification.State != model.RemediationRecipeVerificationVerified {
			t.Errorf("recipe %s verification state = %q, want verified", item.ID, item.Verification.State)
		}
		if !reflect.DeepEqual(item.Verification.Environments, []string{expected.environment}) {
			t.Errorf("recipe %s environments = %#v, want %q", item.ID, item.Verification.Environments, expected.environment)
		}
		if item.Verification.VerifiedAt != "2026-08-02T14:58:30.339056Z" ||
			!reflect.DeepEqual(item.Verification.EvidenceSHA256, []string{expected.evidence}) {
			t.Errorf("verified recipe %s provenance = %#v", item.ID, item.Verification)
		}
	}
	for platformKey := range baselinePlatforms {
		for ruleID := range baselineRules {
			key := platformKey + "\x00" + ruleID
			if !found[key] {
				t.Errorf("baseline remediation recipe is missing for %q %s", platformKey, ruleID)
			}
		}
	}
}

func TestDefaultRecipesMatchExactPlatformBindings(t *testing.T) {
	registry, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	bundle, err := rulecatalog.LoadDefaults()
	if err != nil {
		t.Fatalf("rules.LoadDefaults() error = %v", err)
	}

	catalogRules := make(map[string]bool, len(bundle.Catalog.Rules))
	for _, rule := range bundle.Catalog.Rules {
		catalogRules[rule.ID] = true
	}
	platformLayers := make(map[string]model.BindingLayer)
	for _, layer := range bundle.Layers {
		if layer.PlatformVerification != nil {
			platformLayers[remediationPlatformKey(layer.Selector)] = layer
		}
	}

	recipes := make(map[string]model.RemediationRecipe)
	for _, item := range registry.All() {
		if !catalogRules[item.RuleID] {
			t.Errorf("recipe %s references unknown catalog rule %s", item.ID, item.RuleID)
		}
		platformKey := remediationPlatformKey(item.Selector)
		layer, exists := platformLayers[platformKey]
		if !exists {
			t.Errorf("recipe %s has no exact platform verification layer", item.ID)
			continue
		}
		binding, exists := remediationRuleBinding(layer, item.RuleID)
		if !exists || binding.Verification == nil {
			t.Errorf("recipe %s has no verification binding in platform layer %s", item.ID, layer.ID)
			continue
		}
		if string(layer.PlatformVerification.State) != string(binding.Verification.State) ||
			string(binding.Verification.State) != string(item.Verification.State) {
			t.Errorf(
				"recipe %s verification states disagree: platform=%s rule=%s recipe=%s",
				item.ID,
				layer.PlatformVerification.State,
				binding.Verification.State,
				item.Verification.State,
			)
		}
		if !reflect.DeepEqual(layer.PlatformVerification.Environments, binding.Verification.Environments) ||
			!reflect.DeepEqual(binding.Verification.Environments, item.Verification.Environments) {
			t.Errorf(
				"recipe %s verification environments disagree: platform=%#v rule=%#v recipe=%#v",
				item.ID,
				layer.PlatformVerification.Environments,
				binding.Verification.Environments,
				item.Verification.Environments,
			)
		}
		recipes[platformKey+"\x00"+item.RuleID] = item
	}

	for platformKey, layer := range platformLayers {
		for _, binding := range layer.Bindings {
			if binding.Verification == nil {
				continue
			}
			if _, exists := recipes[platformKey+"\x00"+binding.RuleID]; !exists {
				t.Errorf("platform layer %s marks %s for remediation verification without a recipe", layer.ID, binding.RuleID)
			}
		}
	}
}

func remediationPlatformKey(selector model.PlatformSelector) string {
	return strings.ToLower(selector.ID) + "\x00" +
		strings.ToLower(selector.Version) + "\x00" +
		strings.ToLower(selector.Architecture)
}

func remediationRuleBinding(layer model.BindingLayer, ruleID string) (model.RuleBinding, bool) {
	for _, binding := range layer.Bindings {
		if binding.RuleID == ruleID {
			return binding, true
		}
	}
	return model.RuleBinding{}, false
}

func TestCloneRecipeDigestIncludesVerification(t *testing.T) {
	original := model.RemediationRecipe{
		ID:        "u19-hosts-permissions-rocky-9.8",
		GuideYear: 2026,
		RuleID:    "U-19",
		Selector: model.PlatformSelector{
			ID:           "rocky",
			Version:      "9.8",
			Architecture: "amd64",
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
      architecture: amd64
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

func TestLoadRejectsSemanticallyOverlappingRecipeSelectors(t *testing.T) {
	t.Parallel()

	source := fstest.MapFS{
		"recipes/plain.yaml": {
			Data: overlappingRecipeCatalog("u19-rocky-plain", ""),
		},
		"recipes/constrained.yaml": {
			Data: overlappingRecipeCatalog("u19-rocky-duplicate", ""),
		},
	}

	if _, err := Load(source, "recipes"); err == nil ||
		!strings.Contains(err.Error(), "same platform") {
		t.Fatalf("Load() overlap error = %v, want fail-closed semantic selector rejection", err)
	}
}

func overlappingRecipeCatalog(id, selectorPrefix string) []byte {
	return []byte(fmt.Sprintf(`schema_version: 1
recipes:
  - id: %s
    guide_year: 2026
    rule_id: U-19
    selector:
%s      id: rocky
      version: "9.8"
      architecture: amd64
    verification:
      state: pending
    risk: CAUTION
    expected_impact: 허용되지 않은 파일 메타데이터만 최소 변경합니다.
    operations:
      - type: preserve_content_file_metadata
        path: /etc/hosts
        allowed_owners: [root]
        remediation_owner: root
        maximum_mode: "0644"
`, id, selectorPrefix))
}
