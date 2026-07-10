package rules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestLoadDefaultsPreservesEmbeddedUnixContract(t *testing.T) {
	t.Parallel()

	bundle, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	if bundle.Catalog.Guide.Year != 2026 || bundle.Catalog.Guide.Domain != "Unix 서버" {
		t.Fatalf("guide = %#v, want the 2026 Unix server guide", bundle.Catalog.Guide)
	}
	if len(bundle.Catalog.Rules) != 67 {
		t.Fatalf("catalog rule count = %d, want 67", len(bundle.Catalog.Rules))
	}
	if len(bundle.Profiles.Profiles) != 6 {
		t.Fatalf("profile count = %d, want 6", len(bundle.Profiles.Profiles))
	}
	if len(bundle.Layers) != 3 {
		t.Fatalf("binding layer count = %d, want 3", len(bundle.Layers))
	}
	if len(bundle.Version) != len("sha256:")+64 || !strings.HasPrefix(bundle.Version, "sha256:") {
		t.Fatalf("bundle version = %q, want a sha256-prefixed digest", bundle.Version)
	}

	for index, rule := range bundle.Catalog.Rules {
		wantID := fmt.Sprintf("U-%02d", index+1)
		if rule.ID != wantID {
			t.Fatalf("catalog rule %d id = %q, want %q", index, rule.ID, wantID)
		}
		if rule.Reference.Guide != bundle.Catalog.Guide.Title || rule.Reference.Item != rule.ID {
			t.Fatalf("rule %s reference = %#v, want embedded guide and matching item", rule.ID, rule.Reference)
		}
	}

	assertDefaultProfilesPartitionCatalog(t, bundle)
	assertDefaultLayers(t, bundle)
}

func TestDefaultRockyLinux98ResolutionUsesAllApplicableLayers(t *testing.T) {
	t.Parallel()

	bundle, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	resolved, err := bundle.Resolve(rulesContractRockyLinux98Platform())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(resolved) != 67 {
		t.Fatalf("resolved rule count = %d, want 67", len(resolved))
	}
	if ids := bundle.EvaluatorIDs(); len(ids) != 67 {
		t.Fatalf("unique evaluator count = %d, want 67", len(ids))
	}

	byID := make(map[string]model.ResolvedRule, len(resolved))
	for index, rule := range resolved {
		wantID := fmt.Sprintf("U-%02d", index+1)
		if rule.ID != wantID {
			t.Fatalf("resolved rule %d id = %q, want %q", index, rule.ID, wantID)
		}
		if strings.TrimSpace(rule.Evaluator) == "" {
			t.Fatalf("resolved rule %s has no evaluator", rule.ID)
		}
		if !rule.Applicable {
			t.Fatalf("resolved rule %s unexpectedly became inapplicable", rule.ID)
		}
		if rule.Verification.State != model.VerificationPending ||
			!reflect.DeepEqual(rule.Verification.Environments, []string{"Rocky Linux 9.8"}) {
			t.Fatalf("resolved rule %s verification = %#v, want Rocky Linux 9.8 pending", rule.ID, rule.Verification)
		}
		byID[rule.ID] = rule
	}

	if got := byID["U-01"].BindingSources; !reflect.DeepEqual(got, []string{"linux-common", "rocky-linux-9.8"}) {
		t.Fatalf("U-01 binding sources = %v, want common and exact Rocky layers", got)
	}
	if got := byID["U-02"].BindingSources; !reflect.DeepEqual(got, []string{"linux-common", "rhel-9", "rocky-linux-9.8"}) {
		t.Fatalf("U-02 binding sources = %v, want common, RHEL 9, and exact Rocky layers", got)
	}
	if got := byID["U-02"].Parameters["min_password_length"]; got != 8 {
		t.Fatalf("U-02 min_password_length = %#v, want 8 from the RHEL 9 layer", got)
	}
}

func assertDefaultProfilesPartitionCatalog(t *testing.T, bundle Bundle) {
	t.Helper()

	profiles := make(map[string]model.Profile, len(bundle.Profiles.Profiles))
	for _, profile := range bundle.Profiles.Profiles {
		profiles[profile.ID] = profile
	}
	all, exists := profiles["all"]
	if !exists {
		t.Fatal("default profile set has no all profile")
	}
	if len(all.RuleIDs) != len(bundle.Catalog.Rules) {
		t.Fatalf("all profile rule count = %d, want %d", len(all.RuleIDs), len(bundle.Catalog.Rules))
	}
	for index, rule := range bundle.Catalog.Rules {
		if all.RuleIDs[index] != rule.ID {
			t.Fatalf("all profile rule %d = %q, want catalog order %q", index, all.RuleIDs[index], rule.ID)
		}
	}

	categoryProfiles := map[string]model.Category{
		"account":        model.CategoryAccount,
		"file-directory": model.CategoryFileDirectory,
		"service":        model.CategoryService,
		"patch":          model.CategoryPatch,
		"logging":        model.CategoryLogging,
	}
	rulesByID := make(map[string]model.RuleDefinition, len(bundle.Catalog.Rules))
	for _, rule := range bundle.Catalog.Rules {
		rulesByID[rule.ID] = rule
	}
	seen := make(map[string]string, len(bundle.Catalog.Rules))
	for profileID, category := range categoryProfiles {
		profile, exists := profiles[profileID]
		if !exists {
			t.Fatalf("default profile set has no %s profile", profileID)
		}
		for _, ruleID := range profile.RuleIDs {
			rule, exists := rulesByID[ruleID]
			if !exists {
				t.Fatalf("profile %s references unknown rule %s", profileID, ruleID)
			}
			if rule.Category != category {
				t.Fatalf("profile %s contains %s with category %s, want %s", profileID, ruleID, rule.Category, category)
			}
			if previous, duplicate := seen[ruleID]; duplicate {
				t.Fatalf("rule %s appears in category profiles %s and %s", ruleID, previous, profileID)
			}
			seen[ruleID] = profileID
		}
	}
	if len(seen) != len(bundle.Catalog.Rules) {
		t.Fatalf("category profiles cover %d rules, want %d", len(seen), len(bundle.Catalog.Rules))
	}
}

func assertDefaultLayers(t *testing.T, bundle Bundle) {
	t.Helper()

	want := []struct {
		id       string
		priority int
		selector model.PlatformSelector
	}{
		{id: "linux-common", priority: 100, selector: model.PlatformSelector{OS: "linux"}},
		{id: "rhel-9", priority: 200, selector: model.PlatformSelector{Family: "rhel", VersionMajor: "9"}},
		{id: "rocky-linux-9.8", priority: 300, selector: model.PlatformSelector{ID: "rocky", Version: "9.8"}},
	}
	for index, expected := range want {
		layer := bundle.Layers[index]
		if layer.ID != expected.id || layer.Priority != expected.priority || !reflect.DeepEqual(layer.Selector, expected.selector) {
			t.Fatalf("layer %d = %#v, want id=%s priority=%d selector=%#v", index, layer, expected.id, expected.priority, expected.selector)
		}
	}
}
