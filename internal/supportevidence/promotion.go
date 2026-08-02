package supportevidence

import (
	"fmt"
	"slices"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func ValidateScanPromotion(layer model.BindingLayer, manifest *Manifest) error {
	if err := validateFinalScanManifest(layer, manifest); err != nil {
		return err
	}
	if layer.ScanSupport == nil || *layer.ScanSupport != model.ScanSupportTested {
		return nil
	}
	if manifest.Remediation != nil {
		return fmt.Errorf("scan-only platform verification does not accept remediation evidence; use verify-promotion or the remediation verify-final path")
	}
	digest, err := PromotionSemanticsDigest(layer, nil)
	if err != nil {
		return err
	}
	if digest != manifest.Source.PromotionSemanticsSHA256 {
		return fmt.Errorf("platform semantics do not match the final evidence manifest")
	}
	return nil
}

func validateFinalScanManifest(layer model.BindingLayer, manifest *Manifest) error {
	if layer.ScanSupport == nil || *layer.ScanSupport != model.ScanSupportTested {
		return nil
	}
	if manifest == nil {
		return fmt.Errorf("tested scan support requires a normalized OS support evidence manifest")
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if manifest.ArtifactStage != ArtifactStageFinal {
		return fmt.Errorf("tested scan support requires final post-promotion evidence")
	}
	if layer.Selector.OS != "" || layer.Selector.Family != "" ||
		layer.Selector.VersionMajor != "" ||
		layer.Selector.ID == "" || layer.Selector.Version == "" ||
		layer.Selector.Architecture == "" {
		return fmt.Errorf("tested scan support requires only exact id, version, and architecture selectors")
	}
	if layer.Selector.ID != manifest.Platform.ID ||
		layer.Selector.Version != manifest.Platform.Version ||
		layer.Selector.Architecture != manifest.Platform.Architecture {
		return fmt.Errorf("tested platform selector does not match the evidence manifest")
	}
	return nil
}

func ValidateVerifiedPromotion(
	layer model.BindingLayer,
	recipes []model.RemediationRecipe,
	manifest *Manifest,
) error {
	if layer.ScanSupport == nil || *layer.ScanSupport != model.ScanSupportTested {
		return fmt.Errorf("verified remediation support requires tested scan support")
	}
	if manifest == nil || manifest.Remediation == nil {
		return fmt.Errorf("verified remediation support requires remediation evidence")
	}
	if err := validateFinalScanManifest(layer, manifest); err != nil {
		return err
	}
	semanticsDigest, err := PromotionSemanticsDigest(layer, recipes)
	if err != nil {
		return err
	}
	if semanticsDigest != manifest.Source.PromotionSemanticsSHA256 {
		return fmt.Errorf("platform and recipe semantics do not match the final evidence manifest")
	}
	if layer.PlatformVerification == nil ||
		layer.PlatformVerification.State != model.VerificationVerified {
		return fmt.Errorf("platform verification state is not verified")
	}
	if layer.PlatformVerification.VerifiedAt != manifest.VerifiedAt ||
		!slices.Equal(layer.PlatformVerification.Environments, []string{manifest.Environment}) {
		return fmt.Errorf("platform verification metadata does not match the evidence manifest")
	}

	digest, err := Digest(*manifest)
	if err != nil {
		return err
	}
	required := map[string]bool{"U-19": false, "U-22": false, "U-29": false}
	for _, binding := range layer.Bindings {
		if _, expected := required[binding.RuleID]; !expected {
			continue
		}
		if binding.Verification == nil ||
			binding.Verification.State != model.VerificationVerified ||
			binding.Verification.VerifiedAt != manifest.VerifiedAt ||
			!slices.Equal(binding.Verification.Environments, []string{manifest.Environment}) {
			return fmt.Errorf("%s rule verification metadata does not match the evidence manifest", binding.RuleID)
		}
		required[binding.RuleID] = true
	}
	for ruleID, found := range required {
		if !found {
			return fmt.Errorf("verified platform layer has no matching %s verification", ruleID)
		}
	}

	matchedRecipes := make(map[string]bool, len(required))
	for _, recipe := range recipes {
		if recipe.Selector.ID != manifest.Platform.ID ||
			recipe.Selector.Version != manifest.Platform.Version ||
			recipe.Selector.Architecture != manifest.Platform.Architecture {
			continue
		}
		if recipe.Selector.OS != "" || recipe.Selector.Family != "" ||
			recipe.Selector.VersionMajor != "" {
			return fmt.Errorf("%s recipe must use only exact id, version, and architecture selectors", recipe.RuleID)
		}
		if _, expected := required[recipe.RuleID]; !expected {
			continue
		}
		if matchedRecipes[recipe.RuleID] {
			return fmt.Errorf("multiple verified recipes target %s", recipe.RuleID)
		}
		if recipe.Verification.State != model.RemediationRecipeVerificationVerified ||
			recipe.Verification.VerifiedAt != manifest.VerifiedAt ||
			!slices.Equal(recipe.Verification.Environments, []string{manifest.Environment}) ||
			!slices.Contains(recipe.Verification.EvidenceSHA256, digest) {
			return fmt.Errorf("%s recipe verification does not reference the normalized evidence digest", recipe.RuleID)
		}
		matchedRecipes[recipe.RuleID] = true
	}
	for ruleID := range required {
		if !matchedRecipes[ruleID] {
			return fmt.Errorf("verified promotion has no matching %s recipe", ruleID)
		}
	}
	return nil
}
