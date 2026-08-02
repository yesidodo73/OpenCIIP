package supportevidence_test

import (
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/supportevidence"
)

func TestValidateFinalEvidenceBridgesClaimsAndNonVerificationSemantics(t *testing.T) {
	t.Parallel()

	final := loadRemediationExampleManifest(t)
	candidate := candidateFromFinal(final)
	artifacts := artifactsForFinal(final)
	if err := supportevidence.ValidateFinalEvidence(candidate, final, artifacts); err != nil {
		t.Fatalf("ValidateFinalEvidence() error = %v", err)
	}

	changedBundle := final
	changedBundle.Source.RuleBundleSHA256 = candidate.Source.RuleBundleSHA256
	if err := supportevidence.ValidateFinalEvidence(candidate, changedBundle, artifacts); err == nil ||
		!strings.Contains(err.Error(), "completed verification metadata") {
		t.Fatalf("ValidateFinalEvidence(changed bundle) error = %v", err)
	}

	changedClaims := final
	changedClaims.Environment = "Example Linux 1.0 alternate amd64"
	if err := supportevidence.ValidateFinalEvidence(candidate, changedClaims, artifacts); err == nil ||
		!strings.Contains(err.Error(), "claims differ") {
		t.Fatalf("ValidateFinalEvidence(changed claims) error = %v", err)
	}

	changedSemantics := final
	changedSemantics.Source.PromotionSemanticsSHA256 = strings.Repeat("0", 64)
	if err := supportevidence.ValidateFinalEvidence(candidate, changedSemantics, artifacts); err == nil ||
		!strings.Contains(err.Error(), "semantics differ") {
		t.Fatalf("ValidateFinalEvidence(changed semantics) error = %v", err)
	}

	wrongBinary := artifacts
	wrongBinary.Binary.SHA256 = strings.Repeat("0", 64)
	if err := supportevidence.ValidateFinalEvidence(candidate, final, wrongBinary); err == nil ||
		!strings.Contains(err.Error(), "binary hash") {
		t.Fatalf("ValidateFinalEvidence(wrong binary) error = %v", err)
	}
}

func TestValidateFinalEvidenceRejectsReusedCandidateArtifacts(t *testing.T) {
	t.Parallel()

	final := loadRemediationExampleManifest(t)
	candidate := candidateFromFinal(final)
	artifacts := artifactsForFinal(final)

	reusedScan := final
	reusedScan.Scan.ResultsSHA256 = candidate.Scan.ResultsSHA256
	if err := supportevidence.ValidateFinalEvidence(candidate, reusedScan, artifacts); err == nil ||
		!strings.Contains(err.Error(), "fresh run") {
		t.Fatalf("ValidateFinalEvidence(reused scan) error = %v", err)
	}

	reusedArchive := final
	reusedArchive.Remediation.Archives[0].ArchiveSHA256 =
		candidate.Remediation.Archives[0].ArchiveSHA256
	reusedArtifacts := artifactsForFinal(reusedArchive)
	if err := supportevidence.ValidateFinalEvidence(candidate, reusedArchive, reusedArtifacts); err == nil ||
		!strings.Contains(err.Error(), "fresh run") {
		t.Fatalf("ValidateFinalEvidence(reused remediation archive) error = %v", err)
	}
}

func candidateFromFinal(final supportevidence.Manifest) supportevidence.Manifest {
	candidate := final
	candidate.ArtifactStage = supportevidence.ArtifactStageCandidate
	candidate.VerifiedAt = ""
	candidate.CapturedAt = "2026-01-02T03:00:00Z"
	candidate.Source.ToolCommit = strings.Repeat("9", 40)
	candidate.Source.BinarySHA256 = strings.Repeat("8", 64)
	candidate.Source.RuleBundleSHA256 = strings.Repeat("0", 64)
	candidate.Scan.MetadataSHA256 = strings.Repeat("7", 64)
	candidate.Scan.ResultsSHA256 = strings.Repeat("6", 64)
	candidate.Scan.ArchiveSHA256 = strings.Repeat("4", 64)
	candidate.Scan.ArchiveSizeBytes = 12000
	if candidate.Remediation != nil {
		remediation := *candidate.Remediation
		remediation.BinarySHA256 = candidate.Source.BinarySHA256
		remediation.Rules = append([]supportevidence.RemediationRuleEvidence(nil), remediation.Rules...)
		remediation.Archives = append([]supportevidence.ArchiveEvidence(nil), remediation.Archives...)
		for index := range remediation.Archives {
			remediation.Archives[index].ArchiveSHA256 = strings.Repeat(string(rune('8'+index)), 64)
			remediation.Archives[index].ManifestSHA256 = strings.Repeat(string(rune('6'+index)), 64)
			remediation.Archives[index].SizeBytes -= 100
		}
		candidate.Remediation = &remediation
	}
	return candidate
}

func artifactsForFinal(final supportevidence.Manifest) supportevidence.FinalArtifacts {
	artifacts := supportevidence.FinalArtifacts{
		SourceCommit:             final.Source.ToolCommit,
		PromotionSemanticsSHA256: final.Source.PromotionSemanticsSHA256,
		Binary: supportevidence.ArtifactIdentity{
			SHA256:    final.Source.BinarySHA256,
			SizeBytes: 1000,
		},
		BinaryBuild: supportevidence.GoBinaryBuildIdentity{
			GoVersion:     "go1.26.5",
			CommandPath:   "github.com/yesidodo73/OpenCIIP/cmd/openciip",
			ModulePath:    "github.com/yesidodo73/OpenCIIP",
			ModuleVersion: "v0.1.0",
			BuildMode:     "exe",
			Compiler:      "gc",
			Trimpath:      "true",
			CGOEnabled:    "0",
			GOOS:          "linux",
			GOARCH:        final.Platform.Architecture,
			GOAMD64:       "v1",
			VCS:           "git",
			VCSRevision:   final.Source.ToolCommit,
			VCSModified:   "false",
		},
		RuleBundle: supportevidence.ArtifactIdentity{
			SHA256:    final.Source.RuleBundleSHA256,
			SizeBytes: 1000,
		},
		ScanArchive: supportevidence.ArtifactIdentity{
			SHA256:    final.Scan.ArchiveSHA256,
			SizeBytes: final.Scan.ArchiveSizeBytes,
		},
		RemediationArchive: make(map[string]supportevidence.ArtifactIdentity),
	}
	if final.Remediation != nil {
		artifacts.Runner = supportevidence.ArtifactIdentity{
			SHA256:    final.Remediation.RunnerSHA256,
			SizeBytes: 1000,
		}
		for _, archive := range final.Remediation.Archives {
			artifacts.RemediationArchive[archive.Scenario] = supportevidence.ArtifactIdentity{
				SHA256:    archive.ArchiveSHA256,
				SizeBytes: archive.SizeBytes,
			}
		}
	}
	return artifacts
}
