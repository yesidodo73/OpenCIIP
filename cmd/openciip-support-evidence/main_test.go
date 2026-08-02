package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/supportevidence"
)

func TestNormalizeWritesCanonicalManifestAndSemanticDigest(t *testing.T) {
	input := filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.yaml")
	want, err := os.ReadFile(filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.normalized.json"))
	if err != nil {
		t.Fatalf("ReadFile(normalized example) error = %v", err)
	}
	output := filepath.Join(t.TempDir(), "normalized.json")
	var stdout bytes.Buffer
	if err := run([]string{
		"normalize",
		"--input", input,
		"--output", output,
	}, &stdout); err != nil {
		t.Fatalf("run(normalize) error = %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile(output) error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("normalize output differs from the canonical example")
	}
	for _, expected := range []string{
		"path=evidence/os-support/example-1.0-amd64.json",
		"evidence_sha256=43b836fc9ff27622b3c23fa9cc0700e798854fd1a34609297a19485493f36499",
		"manifest_sha256=c111ef0c61987cddbccc3179ea6db7224b23d8c03ded9083f6eca1c28e75f1ca",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("normalize output %q does not contain %q", stdout.String(), expected)
		}
	}
}

func TestPrepareWritesStableClaimsAndPromotionSemantics(t *testing.T) {
	output := filepath.Join(t.TempDir(), "claims.json")
	var stdout bytes.Buffer
	if err := run([]string{
		"prepare",
		"--platform", filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "platform.yaml"),
		"--recipes", filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "remediation"),
		"--environment", "Example Linux 1.0 amd64",
		"--remediation",
		"--output", output,
	}, &stdout); err != nil {
		t.Fatalf("run(prepare) error = %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("ReadFile(prepared claims) error = %v", err)
	}
	want, err := os.ReadFile(
		filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "claims.json"),
	)
	if err != nil {
		t.Fatalf("ReadFile(claim example) error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("prepare output differs from the committed claim example")
	}
	for _, expected := range []string{
		"evidence_sha256=a3f7c721fc684e46bdad501149df946c8eee899ef29fd708da8fae3a467ac1ea",
		"promotion_semantics_sha256=ccb6be5e54488e5763cff54bfa3e8910423ab5a15e5cb51e0cda794216608acb",
	} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("prepare output %q does not contain %q", stdout.String(), expected)
		}
	}
}

func TestVerifyPromotionChecksRepositoryPathAndLinkedExamples(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "evidence", "os-support", "example-1.0-amd64.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	manifest, err := os.ReadFile(filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "evidence-manifest.normalized.json"))
	if err != nil {
		t.Fatalf("ReadFile(manifest) error = %v", err)
	}
	if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
		t.Fatalf("WriteFile(manifest) error = %v", err)
	}

	platform := filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "platform.yaml")
	recipes := filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "remediation")
	var stdout bytes.Buffer
	if err := run([]string{
		"verify-promotion",
		"--repository-root", root,
		"--manifest", manifestPath,
		"--platform", platform,
		"--recipes", recipes,
	}, &stdout); err != nil {
		t.Fatalf("run(verify-promotion) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "evidence_sha256=a3f7c721fc684e46bdad501149df946c8eee899ef29fd708da8fae3a467ac1ea") {
		t.Fatalf("verify-promotion output = %q", stdout.String())
	}

	renamed := filepath.Join(root, "evidence", "os-support", "renamed.json")
	if err := os.Rename(manifestPath, renamed); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	scanOnly, err := os.ReadFile(filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.normalized.json"))
	if err != nil {
		t.Fatalf("ReadFile(scan-only manifest) error = %v", err)
	}
	if err := os.WriteFile(renamed, scanOnly, 0o644); err != nil {
		t.Fatalf("WriteFile(scan-only manifest) error = %v", err)
	}
	scanPlatform := filepath.Join("..", "..", "contrib", "os-support", "examples", "tested", "platform.yaml")
	if err := run([]string{
		"verify-platform",
		"--repository-root", root,
		"--manifest", renamed,
		"--platform", scanPlatform,
	}, &stdout); err == nil || !strings.Contains(err.Error(), "must be") {
		t.Fatalf("run(verify-platform wrong path) error = %v", err)
	}
}

func TestValidateRepositoryPathRejectsRedirectedEvidenceDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	manifest, err := supportevidence.LoadFile(
		filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.normalized.json"),
	)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	outsidePath := filepath.Join(outside, "example-1.0-amd64.json")
	data, err := supportevidence.CanonicalBytes(manifest)
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	if err := os.WriteFile(outsidePath, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "evidence"), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	linkedDirectory := filepath.Join(root, "evidence", "os-support")
	if err := os.Symlink(outside, linkedDirectory); err != nil {
		t.Skipf("symbolic links are unavailable in this environment: %v", err)
	}
	linkedPath := filepath.Join(linkedDirectory, "example-1.0-amd64.json")
	if err := validateRepositoryPath(root, linkedPath, manifest); err == nil ||
		!strings.Contains(err.Error(), "linked or redirected") {
		t.Fatalf("validateRepositoryPath(linked directory) error = %v", err)
	}
}

func TestVerifyPlatformAcceptsOnlyScanOnlyEvidence(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "evidence", "os-support", "example-1.0-amd64.json")
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	scanOnly, err := os.ReadFile(filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.normalized.json"))
	if err != nil {
		t.Fatalf("ReadFile(scan-only manifest) error = %v", err)
	}
	if err := os.WriteFile(manifestPath, scanOnly, 0o644); err != nil {
		t.Fatalf("WriteFile(scan-only manifest) error = %v", err)
	}
	platform := filepath.Join("..", "..", "contrib", "os-support", "examples", "tested", "platform.yaml")
	var stdout bytes.Buffer
	if err := run([]string{
		"verify-platform",
		"--repository-root", root,
		"--manifest", manifestPath,
		"--platform", platform,
	}, &stdout); err != nil {
		t.Fatalf("run(verify-platform scan-only) error = %v", err)
	}

	remediation, err := os.ReadFile(filepath.Join(
		"..", "..", "contrib", "os-support", "examples", "remediation-verified", "evidence-manifest.normalized.json",
	))
	if err != nil {
		t.Fatalf("ReadFile(remediation manifest) error = %v", err)
	}
	if err := os.WriteFile(manifestPath, remediation, 0o644); err != nil {
		t.Fatalf("WriteFile(remediation manifest) error = %v", err)
	}
	if err := run([]string{
		"verify-platform",
		"--repository-root", root,
		"--manifest", manifestPath,
		"--platform", platform,
	}, &stdout); err == nil || !strings.Contains(err.Error(), "scan-only evidence") {
		t.Fatalf("run(verify-platform remediation) error = %v", err)
	}
}

func TestVerifyFinalSupportsScanOnlyPromotion(t *testing.T) {
	root := t.TempDir()
	writeArtifact := func(name, content string) (string, supportevidence.ArtifactIdentity) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
		identity, err := fileIdentity(path)
		if err != nil {
			t.Fatalf("fileIdentity(%s) error = %v", name, err)
		}
		return path, identity
	}
	binaryPath, binary := writeArtifact("openciip", "scan-only-final-binary")
	bundlePath, bundle := writeArtifact("rules.bundle", "scan-only-final-rules")
	scanPath, scan := writeArtifact("scan.archive", "scan-only-final-scan")

	final, err := supportevidence.LoadFile(filepath.Join("..", "..", "contrib", "os-support", "evidence-manifest.yaml"))
	if err != nil {
		t.Fatalf("LoadFile(scan-only example) error = %v", err)
	}
	final.Source.BinarySHA256 = binary.SHA256
	final.Source.RuleBundleSHA256 = bundle.SHA256
	final.Scan.MetadataSHA256 = strings.Repeat("a", 64)
	final.Scan.ResultsSHA256 = strings.Repeat("b", 64)
	final.Scan.ArchiveSHA256 = scan.SHA256
	final.Scan.ArchiveSizeBytes = scan.SizeBytes
	candidate := final
	candidate.ArtifactStage = supportevidence.ArtifactStageCandidate
	candidate.VerifiedAt = ""
	candidate.CapturedAt = "2026-01-02T03:00:00Z"
	candidate.Source.ToolCommit = strings.Repeat("9", 40)
	candidate.Source.BinarySHA256 = strings.Repeat("8", 64)
	candidate.Source.RuleBundleSHA256 = strings.Repeat("7", 64)
	candidate.Scan.MetadataSHA256 = strings.Repeat("6", 64)
	candidate.Scan.ResultsSHA256 = strings.Repeat("5", 64)
	candidate.Scan.ArchiveSHA256 = strings.Repeat("4", 64)
	candidate.Scan.ArchiveSizeBytes++

	candidatePath := filepath.Join(root, "candidate.json")
	finalPath := filepath.Join(root, "evidence", "os-support", "example-1.0-amd64.json")
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(final evidence) error = %v", err)
	}
	for path, manifest := range map[string]supportevidence.Manifest{candidatePath: candidate, finalPath: final} {
		data, err := supportevidence.CanonicalBytes(manifest)
		if err != nil {
			t.Fatalf("CanonicalBytes(%s) error = %v", path, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}

	var stdout bytes.Buffer
	if err := runWithDependencies([]string{
		"verify-final",
		"--repository-root", root,
		"--candidate", candidatePath,
		"--final", finalPath,
		"--platform", filepath.Join("..", "..", "contrib", "os-support", "examples", "tested", "platform.yaml"),
		"--source-commit", final.Source.ToolCommit,
		"--binary", binaryPath,
		"--rule-bundle", bundlePath,
		"--scan-archive", scanPath,
	}, &stdout, testCommandDependencies(final)); err != nil {
		t.Fatalf("run(verify-final scan-only) error = %v", err)
	}
}

func TestVerifyFinalChecksActualArtifactsAndFreshEvidence(t *testing.T) {
	root := t.TempDir()
	writeArtifact := func(name, content string) (string, supportevidence.ArtifactIdentity) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
		identity, err := fileIdentity(path)
		if err != nil {
			t.Fatalf("fileIdentity(%s) error = %v", name, err)
		}
		return path, identity
	}
	binaryPath, binary := writeArtifact("openciip", "final-binary")
	bundlePath, bundle := writeArtifact("rules.bundle", "final-verified-rules")
	runnerPath, runner := writeArtifact("runner", "final-runner")
	scanPath, scan := writeArtifact("scan.archive", "final-scan")
	itemPath, item := writeArtifact("item.archive", "final-item-rollback")
	rebootPath, reboot := writeArtifact("reboot.archive", "final-reboot-rollback")

	final, err := supportevidence.LoadFile(
		filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "evidence-manifest.yaml"),
	)
	if err != nil {
		t.Fatalf("LoadFile(example) error = %v", err)
	}
	final.Source.BinarySHA256 = binary.SHA256
	final.Source.RuleBundleSHA256 = bundle.SHA256
	final.Remediation.BinarySHA256 = binary.SHA256
	final.Remediation.RunnerSHA256 = runner.SHA256
	final.Scan.MetadataSHA256 = strings.Repeat("a", 64)
	final.Scan.ResultsSHA256 = strings.Repeat("b", 64)
	final.Scan.ArchiveSHA256 = scan.SHA256
	final.Scan.ArchiveSizeBytes = scan.SizeBytes
	final.Remediation.Archives[0].ArchiveSHA256 = item.SHA256
	final.Remediation.Archives[0].ManifestSHA256 = strings.Repeat("c", 64)
	final.Remediation.Archives[0].SizeBytes = item.SizeBytes
	final.Remediation.Archives[1].ArchiveSHA256 = reboot.SHA256
	final.Remediation.Archives[1].ManifestSHA256 = strings.Repeat("d", 64)
	final.Remediation.Archives[1].SizeBytes = reboot.SizeBytes

	candidate := final
	candidate.ArtifactStage = supportevidence.ArtifactStageCandidate
	candidate.VerifiedAt = ""
	candidate.CapturedAt = "2026-01-02T03:00:00Z"
	candidate.Source.ToolCommit = strings.Repeat("9", 40)
	candidate.Source.BinarySHA256 = strings.Repeat("8", 64)
	candidate.Source.RuleBundleSHA256 = strings.Repeat("7", 64)
	candidate.Scan.MetadataSHA256 = strings.Repeat("6", 64)
	candidate.Scan.ResultsSHA256 = strings.Repeat("5", 64)
	candidate.Scan.ArchiveSHA256 = strings.Repeat("4", 64)
	candidate.Scan.ArchiveSizeBytes++
	candidateRemediation := *candidate.Remediation
	candidateRemediation.BinarySHA256 = candidate.Source.BinarySHA256
	candidateRemediation.Rules = append(
		[]supportevidence.RemediationRuleEvidence(nil),
		candidateRemediation.Rules...,
	)
	candidateRemediation.Archives = append(
		[]supportevidence.ArchiveEvidence(nil),
		candidateRemediation.Archives...,
	)
	candidateRemediation.Archives[0].ArchiveSHA256 = strings.Repeat("3", 64)
	candidateRemediation.Archives[0].ManifestSHA256 = strings.Repeat("2", 64)
	candidateRemediation.Archives[1].ArchiveSHA256 = strings.Repeat("1", 64)
	candidateRemediation.Archives[1].ManifestSHA256 = strings.Repeat("0", 64)
	candidate.Remediation = &candidateRemediation

	candidatePath := filepath.Join(root, "candidate.json")
	finalPath := filepath.Join(root, "evidence", "os-support", "example-1.0-amd64.json")
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		t.Fatalf("MkdirAll(final evidence) error = %v", err)
	}
	for path, manifest := range map[string]supportevidence.Manifest{
		candidatePath: candidate,
		finalPath:     final,
	} {
		data, err := supportevidence.CanonicalBytes(manifest)
		if err != nil {
			t.Fatalf("CanonicalBytes(%s) error = %v", path, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}

	var stdout bytes.Buffer
	if err := runWithDependencies([]string{
		"verify-final",
		"--repository-root", root,
		"--candidate", candidatePath,
		"--final", finalPath,
		"--platform", filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "platform.yaml"),
		"--recipes", filepath.Join("..", "..", "contrib", "os-support", "examples", "remediation-verified", "remediation"),
		"--source-commit", final.Source.ToolCommit,
		"--binary", binaryPath,
		"--rule-bundle", bundlePath,
		"--runner", runnerPath,
		"--scan-archive", scanPath,
		"--item-archive", itemPath,
		"--reboot-archive", rebootPath,
	}, &stdout, testCommandDependencies(final)); err != nil {
		t.Fatalf("run(verify-final) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "path=evidence/os-support/example-1.0-amd64.json") {
		t.Fatalf("verify-final output = %q", stdout.String())
	}
}

func testCommandDependencies(final supportevidence.Manifest) commandDependencies {
	return commandDependencies{
		inspectGoBinary: func(path string) (
			supportevidence.ArtifactIdentity,
			supportevidence.GoBinaryBuildIdentity,
			error,
		) {
			identity, err := supportevidence.InspectArtifact(path)
			if err != nil {
				return supportevidence.ArtifactIdentity{}, supportevidence.GoBinaryBuildIdentity{}, err
			}
			return identity, supportevidence.GoBinaryBuildIdentity{
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
			}, nil
		},
	}
}
