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
	if len(bundle.Layers) < 14 {
		t.Fatalf("binding layer count = %d, want at least the 14 baseline layers", len(bundle.Layers))
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
	remediationRules := map[string]bool{"U-19": true, "U-22": true, "U-29": true}
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
		wantState := model.VerificationPending
		wantEnvironments := []string(nil)
		wantVerifiedAt := ""
		if remediationRules[rule.ID] {
			wantState = model.VerificationVerified
			wantEnvironments = []string{"Rocky Linux 9.8 amd64"}
			wantVerifiedAt = "2026-08-02T14:58:30.339056Z"
		}
		if rule.Verification.State != wantState {
			t.Fatalf("resolved rule %s verification state = %q, want %q", rule.ID, rule.Verification.State, wantState)
		}
		if !reflect.DeepEqual(rule.Verification.Environments, wantEnvironments) {
			t.Fatalf("resolved rule %s verification environments = %#v, want %#v", rule.ID, rule.Verification.Environments, wantEnvironments)
		}
		if rule.Verification.VerifiedAt != wantVerifiedAt {
			t.Fatalf("resolved rule %s verified_at = %q, want %q", rule.ID, rule.Verification.VerifiedAt, wantVerifiedAt)
		}
		byID[rule.ID] = rule
	}

	if got := byID["U-01"].BindingSources; !reflect.DeepEqual(got, []string{"linux-common"}) {
		t.Fatalf("U-01 binding sources = %v, want the common layer", got)
	}
	if got := byID["U-02"].BindingSources; !reflect.DeepEqual(got, []string{"linux-common", "rhel-9"}) {
		t.Fatalf("U-02 binding sources = %v, want common and RHEL 9 layers", got)
	}
	if got := byID["U-02"].Parameters["min_password_length"]; got != 8 {
		t.Fatalf("U-02 min_password_length = %#v, want 8 from the RHEL 9 layer", got)
	}
	if got := byID["U-19"].BindingSources; !reflect.DeepEqual(got, []string{"linux-common", "rocky-linux-9.8"}) {
		t.Fatalf("U-19 binding sources = %v, want common and exact Rocky layers", got)
	}
}

func TestDefaultDebianResolutionUsesPlatformParameters(t *testing.T) {
	t.Parallel()

	bundle, err := LoadDefaults()
	if err != nil {
		t.Fatalf("LoadDefaults() error = %v", err)
	}
	resolved, err := bundle.Resolve(model.PlatformInfo{
		OS: "linux", Family: "debian", ID: "ubuntu", VersionID: "24.04", Architecture: "amd64",
	})
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	byID := make(map[string]model.ResolvedRule, len(resolved))
	for _, rule := range resolved {
		byID[rule.ID] = rule
	}
	if got := byID["U-02"].BindingSources; !reflect.DeepEqual(got, []string{"linux-common", "debian-common"}) {
		t.Fatalf("U-02 binding sources = %v, want common and Debian layers", got)
	}
	if got := byID["U-02"].Parameters["min_password_length"]; got != 8 {
		t.Fatalf("U-02 min_password_length = %#v, want 8", got)
	}
	if got := byID["U-06"].Parameters["allowed_su_groups"]; !reflect.DeepEqual(got, []any{"sudo"}) {
		t.Fatalf("U-06 allowed_su_groups = %#v, want sudo", got)
	}
	if got := byID["U-62"].BindingSources; !reflect.DeepEqual(got, []string{"linux-common", "ubuntu-24.04"}) {
		t.Fatalf("U-62 binding sources = %v, want common and exact Ubuntu layers", got)
	}
	if got := byID["U-62"].Parameters["known_inadequate_issue_hashes"]; !reflect.DeepEqual(got, []any{
		"0f42739b4fee9ba3ea7768ddf304853467e394265dc2dfde4a9531156e57ceb8",
	}) {
		t.Fatalf("U-62 known_inadequate_issue_hashes = %#v, want the tested Ubuntu default digest", got)
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
		{id: "debian-common", priority: 200, selector: model.PlatformSelector{Family: "debian"}},
		{id: "rhel-8", priority: 200, selector: model.PlatformSelector{Family: "rhel", VersionMajor: "8"}},
		{id: "rhel-9", priority: 200, selector: model.PlatformSelector{Family: "rhel", VersionMajor: "9"}},
		{id: "centos-linux-8.5.2111", priority: 300, selector: model.PlatformSelector{ID: "centos", Version: "8.5.2111", Architecture: "amd64"}},
		{id: "rocky-linux-9.5", priority: 300, selector: model.PlatformSelector{ID: "rocky", Version: "9.5", Architecture: "amd64"}},
		{id: "rocky-linux-9.6", priority: 300, selector: model.PlatformSelector{ID: "rocky", Version: "9.6", Architecture: "amd64"}},
		{id: "rocky-linux-9.7", priority: 300, selector: model.PlatformSelector{ID: "rocky", Version: "9.7", Architecture: "amd64"}},
		{id: "rocky-linux-9.8", priority: 300, selector: model.PlatformSelector{ID: "rocky", Version: "9.8", Architecture: "amd64"}},
		{id: "ubuntu-18.04", priority: 300, selector: model.PlatformSelector{ID: "ubuntu", Version: "18.04", Architecture: "amd64"}},
		{id: "ubuntu-20.04", priority: 300, selector: model.PlatformSelector{ID: "ubuntu", Version: "20.04", Architecture: "amd64"}},
		{id: "ubuntu-22.04", priority: 300, selector: model.PlatformSelector{ID: "ubuntu", Version: "22.04", Architecture: "amd64"}},
		{id: "ubuntu-24.04", priority: 300, selector: model.PlatformSelector{ID: "ubuntu", Version: "24.04", Architecture: "amd64"}},
		{id: "ubuntu-26.04", priority: 300, selector: model.PlatformSelector{ID: "ubuntu", Version: "26.04", Architecture: "amd64"}},
	}
	byID := make(map[string]model.BindingLayer, len(bundle.Layers))
	for _, layer := range bundle.Layers {
		byID[layer.ID] = layer
	}
	for _, expected := range want {
		layer, exists := byID[expected.id]
		if !exists {
			t.Fatalf("default bindings are missing baseline layer %s", expected.id)
		}
		if layer.ID != expected.id || layer.Priority != expected.priority || !reflect.DeepEqual(layer.Selector, expected.selector) {
			t.Fatalf("layer %s = %#v, want priority=%d selector=%#v", expected.id, layer, expected.priority, expected.selector)
		}
	}
}
