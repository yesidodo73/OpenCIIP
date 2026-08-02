package supportevidence_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/recipe"
	"github.com/yesidodo73/OpenCIIP/internal/supportevidence"
)

func TestPromotionSemanticsIgnoreOnlyVerificationMetadata(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "remediation-verified", "platform.yaml"))
	registry, err := recipe.Load(
		os.DirFS(filepath.Join("..", "..")),
		filepath.ToSlash(filepath.Join("contrib", "os-support", "examples", "remediation-verified", "remediation")),
	)
	if err != nil {
		t.Fatalf("recipe.Load(example) error = %v", err)
	}
	recipes := registry.All()
	finalDigest, err := supportevidence.PromotionSemanticsDigest(layer, recipes)
	if err != nil {
		t.Fatalf("PromotionSemanticsDigest(final) error = %v", err)
	}
	if finalDigest != "ccb6be5e54488e5763cff54bfa3e8910423ab5a15e5cb51e0cda794216608acb" {
		t.Fatalf("PromotionSemanticsDigest(final) = %s", finalDigest)
	}

	supported := model.ScanSupportSupported
	pending := model.Verification{State: model.VerificationPending, Environments: []string{"Example Linux 1.0 amd64"}}
	candidateLayer := layer
	candidateLayer.ScanSupport = &supported
	candidateLayer.PlatformVerification = &pending
	candidateLayer.Bindings = append([]model.RuleBinding(nil), layer.Bindings...)
	for index := range candidateLayer.Bindings {
		candidateLayer.Bindings[index].Verification = &pending
	}
	candidateRecipes := append([]model.RemediationRecipe(nil), recipes...)
	for index := range candidateRecipes {
		candidateRecipes[index].Verification = model.RemediationRecipeVerification{
			State:        model.RemediationRecipeVerificationPending,
			Environments: []string{"Example Linux 1.0 amd64"},
		}
	}
	candidateDigest, err := supportevidence.PromotionSemanticsDigest(candidateLayer, candidateRecipes)
	if err != nil {
		t.Fatalf("PromotionSemanticsDigest(candidate) error = %v", err)
	}
	if candidateDigest != finalDigest {
		t.Fatalf("verification-only change altered semantics from %s to %s", candidateDigest, finalDigest)
	}

	changed := append([]model.RemediationRecipe(nil), recipes...)
	changed[0].ExpectedImpact += " 변경"
	changedDigest, err := supportevidence.PromotionSemanticsDigest(layer, changed)
	if err != nil {
		t.Fatalf("PromotionSemanticsDigest(changed behavior) error = %v", err)
	}
	if changedDigest == finalDigest {
		t.Fatal("recipe semantic change did not alter promotion semantics")
	}
}

func TestPrepareClaimsAcceptsPendingVerificationTargets(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "remediation-verified", "platform.yaml"))
	pending := model.Verification{State: model.VerificationPending, Environments: []string{"Example Linux 1.0 amd64"}}
	layer.PlatformVerification = &pending
	for index := range layer.Bindings {
		layer.Bindings[index].Verification = &pending
	}
	prepared, err := supportevidence.PrepareClaims(layer, "Example Linux 1.0 amd64", true)
	if err != nil {
		t.Fatalf("PrepareClaims(pending) error = %v", err)
	}
	if strings.Contains(string(prepared), "verified_at") {
		t.Fatal("prepared claims contain a verification timestamp")
	}
}
