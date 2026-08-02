package supportevidence_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/recipe"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
	"github.com/yesidodo73/OpenCIIP/internal/supportevidence"
)

func TestContributorTemplateStartsWithoutATestedClaim(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "platform.yaml"))
	if layer.ScanSupport == nil || *layer.ScanSupport != model.ScanSupportSupported {
		t.Fatalf("contributor template scan support = %#v, want supported", layer.ScanSupport)
	}
	if layer.PlatformVerification != nil {
		t.Fatalf("contributor template platform verification = %#v, want none", layer.PlatformVerification)
	}
	if err := supportevidence.ValidateScanPromotion(layer, nil); err != nil {
		t.Fatalf("ValidateScanPromotion(supported) error = %v", err)
	}
}

func TestTestedClaimRequiresMatchingNormalizedEvidence(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "tested", "platform.yaml"))
	if err := supportevidence.ValidateScanPromotion(layer, nil); err == nil ||
		!strings.Contains(err.Error(), "requires a normalized") {
		t.Fatalf("ValidateScanPromotion(nil) error = %v", err)
	}
	manifest := loadScanExampleManifest(t)
	if err := supportevidence.ValidateScanPromotion(layer, &manifest); err != nil {
		t.Fatalf("ValidateScanPromotion() error = %v", err)
	}
	candidate := manifest
	candidate.ArtifactStage = supportevidence.ArtifactStageCandidate
	candidate.VerifiedAt = ""
	if err := supportevidence.ValidateScanPromotion(layer, &candidate); err == nil ||
		!strings.Contains(err.Error(), "final post-promotion") {
		t.Fatalf("ValidateScanPromotion(candidate) error = %v", err)
	}
	manifest.Platform.Version = "2.0"
	if err := supportevidence.ValidateScanPromotion(layer, &manifest); err == nil ||
		!strings.Contains(err.Error(), "does not match") {
		t.Fatalf("ValidateScanPromotion(mismatch) error = %v", err)
	}
}

func TestScanOnlyPromotionDoesNotRequireOrOpenRemediationVerification(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "platform.yaml"))
	if layer.PlatformVerification != nil {
		t.Fatal("scan-only tested example unexpectedly has platform remediation verification")
	}
	manifest := loadScanExampleManifest(t)
	prepared, err := supportevidence.PrepareClaims(layer, manifest.Environment, false)
	if err != nil {
		t.Fatalf("PrepareClaims(scan-only) error = %v", err)
	}
	want, err := supportevidence.EvidenceBytes(manifest)
	if err != nil {
		t.Fatalf("EvidenceBytes(scan-only) error = %v", err)
	}
	if string(prepared) != string(want) || strings.Contains(string(prepared), "remediation") {
		t.Fatal("scan-only prepared claims differ from the final scan projection")
	}

	testedLayer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "tested", "platform.yaml"))
	withRemediation := loadRemediationExampleManifest(t)
	if err := supportevidence.ValidateScanPromotion(testedLayer, &withRemediation); err == nil ||
		!strings.Contains(err.Error(), "does not accept remediation evidence") {
		t.Fatalf("ValidateScanPromotion(remediation evidence) error = %v", err)
	}
}

func TestTestedEvidenceInventoryRequiresCanonicalFinalScanManifest(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "tested", "platform.yaml"))
	canonical, err := supportevidence.CanonicalBytes(loadScanExampleManifest(t))
	if err != nil {
		t.Fatalf("CanonicalBytes(scan example) error = %v", err)
	}
	path := "evidence/os-support/example-1.0-amd64.json"
	if err := supportevidence.ValidateTestedEvidenceInventory(
		[]model.BindingLayer{layer},
		nil,
		fstest.MapFS{path: &fstest.MapFile{Data: canonical}},
	); err != nil {
		t.Fatalf("ValidateTestedEvidenceInventory() error = %v", err)
	}
	if err := supportevidence.ValidateTestedEvidenceInventory([]model.BindingLayer{layer}, nil, fstest.MapFS{}); err == nil ||
		!strings.Contains(err.Error(), path) {
		t.Fatalf("ValidateTestedEvidenceInventory(missing) error = %v", err)
	}

	candidate := loadScanExampleManifest(t)
	candidate.ArtifactStage = supportevidence.ArtifactStageCandidate
	candidate.VerifiedAt = ""
	candidateBytes, err := supportevidence.CanonicalBytes(candidate)
	if err != nil {
		t.Fatalf("CanonicalBytes(candidate) error = %v", err)
	}
	if err := supportevidence.ValidateTestedEvidenceInventory(
		[]model.BindingLayer{layer},
		nil,
		fstest.MapFS{path: &fstest.MapFile{Data: candidateBytes}},
	); err == nil || !strings.Contains(err.Error(), "final post-promotion") {
		t.Fatalf("ValidateTestedEvidenceInventory(candidate) error = %v", err)
	}
}

func TestTestedEvidenceInventoryAcceptsFullyVerifiedRemediationManifest(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "remediation-verified", "platform.yaml"))
	registry, err := recipe.Load(
		os.DirFS(filepath.Join("..", "..")),
		filepath.ToSlash(filepath.Join("contrib", "os-support", "examples", "remediation-verified", "remediation")),
	)
	if err != nil {
		t.Fatalf("recipe.Load(example) error = %v", err)
	}
	canonical, err := supportevidence.CanonicalBytes(loadRemediationExampleManifest(t))
	if err != nil {
		t.Fatalf("CanonicalBytes(remediation example) error = %v", err)
	}
	path := "evidence/os-support/example-1.0-amd64.json"
	source := fstest.MapFS{path: &fstest.MapFile{Data: canonical}}
	if err := supportevidence.ValidateTestedEvidenceInventory(
		[]model.BindingLayer{layer},
		registry.All(),
		source,
	); err != nil {
		t.Fatalf("ValidateTestedEvidenceInventory(remediation) error = %v", err)
	}
	if err := supportevidence.ValidateTestedEvidenceInventory(
		[]model.BindingLayer{layer},
		nil,
		source,
	); err == nil || !strings.Contains(err.Error(), "requires remediation recipes") {
		t.Fatalf("ValidateTestedEvidenceInventory(remediation without recipes) error = %v", err)
	}
}

func TestVerifiedPromotionRequiresManifestLinkedRecipes(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "remediation-verified", "platform.yaml"))
	registry, err := recipe.Load(
		os.DirFS(filepath.Join("..", "..")),
		filepath.ToSlash(filepath.Join("contrib", "os-support", "examples", "remediation-verified", "remediation")),
	)
	if err != nil {
		t.Fatalf("recipe.Load(example) error = %v", err)
	}
	manifest := loadRemediationExampleManifest(t)
	recipes := registry.All()
	if err := supportevidence.ValidateVerifiedPromotion(layer, recipes, &manifest); err != nil {
		t.Fatalf("ValidateVerifiedPromotion() error = %v", err)
	}

	recipes[0].Verification.EvidenceSHA256[0] = strings.Repeat("0", 64)
	if err := supportevidence.ValidateVerifiedPromotion(layer, recipes, &manifest); err == nil ||
		!strings.Contains(err.Error(), "does not reference") {
		t.Fatalf("ValidateVerifiedPromotion(wrong digest) error = %v", err)
	}
}

func TestPreparedClaimsMatchTheFinalEvidenceProjection(t *testing.T) {
	t.Parallel()

	layer := loadExampleLayer(t, filepath.Join("contrib", "os-support", "examples", "remediation-verified", "platform.yaml"))
	prepared, err := supportevidence.PrepareClaims(layer, "Example Linux 1.0 amd64", true)
	if err != nil {
		t.Fatalf("PrepareClaims() error = %v", err)
	}
	manifestClaims, err := supportevidence.EvidenceBytes(loadRemediationExampleManifest(t))
	if err != nil {
		t.Fatalf("EvidenceBytes() error = %v", err)
	}
	if string(prepared) != string(manifestClaims) {
		t.Fatal("prepared claim contract differs from the final evidence projection")
	}
	committed, err := os.ReadFile(
		filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "claims.json"),
	)
	if err != nil {
		t.Fatalf("ReadFile(prepared claim example) error = %v", err)
	}
	if string(prepared) != string(committed) {
		t.Fatal("prepared claim contract differs from the committed example")
	}
}

func loadExampleLayer(t *testing.T, path string) model.BindingLayer {
	t.Helper()
	loader := rules.NewLoader(os.DirFS(filepath.Join("..", "..")))
	layer, err := loader.LoadBinding(filepath.ToSlash(path))
	if err != nil {
		t.Fatalf("LoadBinding(%s) error = %v", path, err)
	}
	return layer
}
