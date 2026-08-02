package supportevidence

import (
	"fmt"
	"time"
)

type ArtifactIdentity struct {
	SHA256    string
	SizeBytes int64
}

type FinalArtifacts struct {
	SourceCommit             string
	PromotionSemanticsSHA256 string
	Binary                   ArtifactIdentity
	BinaryBuild              GoBinaryBuildIdentity
	RuleBundle               ArtifactIdentity
	Runner                   ArtifactIdentity
	ScanArchive              ArtifactIdentity
	RemediationArchive       map[string]ArtifactIdentity
}

func ValidateFinalEvidence(candidate, final Manifest, artifacts FinalArtifacts) error {
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("validate candidate evidence: %w", err)
	}
	if err := final.Validate(); err != nil {
		return fmt.Errorf("validate final evidence: %w", err)
	}
	if candidate.ArtifactStage != ArtifactStageCandidate {
		return fmt.Errorf("candidate evidence artifact_stage must be candidate")
	}
	if final.ArtifactStage != ArtifactStageFinal {
		return fmt.Errorf("final evidence artifact_stage must be final")
	}
	candidateClaims, err := Digest(candidate)
	if err != nil {
		return err
	}
	finalClaims, err := Digest(final)
	if err != nil {
		return err
	}
	if candidateClaims != finalClaims {
		return fmt.Errorf("final evidence claims differ from the promoted candidate")
	}
	candidateCaptured, _ := time.Parse(time.RFC3339, candidate.CapturedAt)
	finalCaptured, _ := time.Parse(time.RFC3339, final.CapturedAt)
	if !finalCaptured.After(candidateCaptured) {
		return fmt.Errorf("final captured_at must be later than candidate captured_at")
	}
	verifiedAt, _ := time.Parse(time.RFC3339, final.VerifiedAt)
	if verifiedAt.Before(candidateCaptured) || verifiedAt.After(finalCaptured) {
		return fmt.Errorf("final verified_at must be between candidate and final capture times")
	}
	if final.Source.ToolCommit == candidate.Source.ToolCommit {
		return fmt.Errorf("final source commit must be updated after candidate verification")
	}
	if final.Source.RuleBundleSHA256 == candidate.Source.RuleBundleSHA256 {
		return fmt.Errorf("final rule bundle must include the completed verification metadata")
	}
	if final.Source.PromotionSemanticsSHA256 != candidate.Source.PromotionSemanticsSHA256 {
		return fmt.Errorf("candidate and final platform or recipe semantics differ")
	}
	if final.Source.BinarySHA256 == candidate.Source.BinarySHA256 ||
		(candidate.Remediation != nil && final.Source.BinarySHA256 == candidate.Remediation.BinarySHA256) {
		return fmt.Errorf("final binary identity was not updated after promotion")
	}
	if final.Scan.MetadataSHA256 == candidate.Scan.MetadataSHA256 ||
		final.Scan.ResultsSHA256 == candidate.Scan.ResultsSHA256 ||
		final.Scan.ArchiveSHA256 == candidate.Scan.ArchiveSHA256 {
		return fmt.Errorf("final scan metadata, results, and archive hashes must come from a fresh run")
	}

	if err := validateArtifactIdentity("final binary", artifacts.Binary, false); err != nil {
		return err
	}
	if artifacts.SourceCommit != final.Source.ToolCommit {
		return fmt.Errorf("final source commit does not match the manifest")
	}
	if artifacts.PromotionSemanticsSHA256 != final.Source.PromotionSemanticsSHA256 {
		return fmt.Errorf("final platform and recipe semantics do not match the manifest")
	}
	if artifacts.Binary.SHA256 != final.Source.BinarySHA256 {
		return fmt.Errorf("final binary hash does not match the scan source")
	}
	if err := artifacts.BinaryBuild.Validate(final.Platform, final.Source); err != nil {
		return err
	}
	if err := validateArtifactIdentity("final rule bundle", artifacts.RuleBundle, false); err != nil {
		return err
	}
	if artifacts.RuleBundle.SHA256 != final.Source.RuleBundleSHA256 {
		return fmt.Errorf("final rule bundle hash does not match the manifest")
	}
	if err := validateArtifactIdentity("final scan archive", artifacts.ScanArchive, true); err != nil {
		return err
	}
	if artifacts.ScanArchive.SHA256 != final.Scan.ArchiveSHA256 ||
		artifacts.ScanArchive.SizeBytes != final.Scan.ArchiveSizeBytes {
		return fmt.Errorf("final scan archive identity does not match the manifest")
	}

	if final.Remediation == nil {
		if candidate.Remediation != nil || len(artifacts.RemediationArchive) != 0 {
			return fmt.Errorf("final scan-only evidence has unexpected remediation artifacts")
		}
		return nil
	}
	if candidate.Remediation == nil {
		return fmt.Errorf("candidate and final remediation evidence differ")
	}
	if artifacts.Binary.SHA256 != final.Remediation.BinarySHA256 {
		return fmt.Errorf("final remediation did not use the verified final binary")
	}
	if err := validateArtifactIdentity("final runner", artifacts.Runner, false); err != nil {
		return err
	}
	if artifacts.Runner.SHA256 != final.Remediation.RunnerSHA256 {
		return fmt.Errorf("final runner hash does not match the manifest")
	}
	if len(artifacts.RemediationArchive) != len(final.Remediation.Archives) {
		return fmt.Errorf("final remediation archive set is incomplete")
	}
	candidateArchives := make(map[string]ArchiveEvidence, len(candidate.Remediation.Archives))
	for _, archive := range candidate.Remediation.Archives {
		candidateArchives[archive.Scenario] = archive
	}
	for _, archive := range final.Remediation.Archives {
		identity, exists := artifacts.RemediationArchive[archive.Scenario]
		if !exists {
			return fmt.Errorf("final remediation archive %s is missing", archive.Scenario)
		}
		if err := validateArtifactIdentity("final remediation archive "+archive.Scenario, identity, true); err != nil {
			return err
		}
		if identity.SHA256 != archive.ArchiveSHA256 || identity.SizeBytes != archive.SizeBytes {
			return fmt.Errorf("final remediation archive %s identity does not match the manifest", archive.Scenario)
		}
		if previous, exists := candidateArchives[archive.Scenario]; !exists ||
			previous.ArchiveSHA256 == archive.ArchiveSHA256 ||
			previous.ManifestSHA256 == archive.ManifestSHA256 {
			return fmt.Errorf("final remediation archive %s does not come from a fresh run", archive.Scenario)
		}
	}
	return nil
}

func validateArtifactIdentity(name string, identity ArtifactIdentity, requireSize bool) error {
	if !sha256Pattern.MatchString(identity.SHA256) {
		return fmt.Errorf("%s has no lowercase SHA-256", name)
	}
	if requireSize && identity.SizeBytes <= 0 {
		return fmt.Errorf("%s size must be positive", name)
	}
	return nil
}
