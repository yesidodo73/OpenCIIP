package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/recipe"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
	"github.com/yesidodo73/OpenCIIP/internal/supportevidence"
)

type commandDependencies struct {
	inspectGoBinary func(string) (supportevidence.ArtifactIdentity, supportevidence.GoBinaryBuildIdentity, error)
}

var productionDependencies = commandDependencies{
	inspectGoBinary: supportevidence.InspectGoBinary,
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	return runWithDependencies(args, stdout, productionDependencies)
}

func runWithDependencies(args []string, stdout io.Writer, dependencies commandDependencies) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "prepare":
		return prepare(args[1:], stdout)
	case "semantics":
		return semantics(args[1:], stdout)
	case "normalize":
		return normalize(args[1:], stdout)
	case "validate":
		return validate(args[1:], stdout)
	case "verify-platform":
		return verifyPlatform(args[1:], stdout)
	case "verify-promotion":
		return verifyPromotion(args[1:], stdout)
	case "verify-final":
		return verifyFinal(args[1:], stdout, dependencies.inspectGoBinary)
	default:
		return usageError()
	}
}

func prepare(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	platformPath := flags.String("platform", "", "exact verified platform binding")
	recipesPath := flags.String("recipes", "", "directory containing remediation recipes")
	environment := flags.String("environment", "", "canonical public environment name")
	includeRemediation := flags.Bool("remediation", false, "include verified remediation claims")
	output := flags.String("output", "-", "canonical claim output or - for stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *platformPath == "" || strings.TrimSpace(*environment) == "" {
		return fmt.Errorf("prepare requires --platform and --environment")
	}
	layer, err := loadBinding(*platformPath)
	if err != nil {
		return err
	}
	var recipes []model.RemediationRecipe
	if *includeRemediation {
		if *recipesPath == "" {
			return fmt.Errorf("prepare --remediation requires --recipes")
		}
		recipes, err = loadRecipes(*recipesPath)
		if err != nil {
			return err
		}
	}
	claims, err := supportevidence.PrepareClaims(layer, *environment, *includeRemediation)
	if err != nil {
		return err
	}
	if *output == "-" {
		_, err = stdout.Write(claims)
		return err
	}
	if err := writeRegularFile(*output, claims); err != nil {
		return err
	}
	semanticsDigest, err := supportevidence.PromotionSemanticsDigest(layer, recipes)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		stdout,
		"evidence_sha256=%s\npromotion_semantics_sha256=%s\n",
		digestData(claims),
		semanticsDigest,
	)
	return err
}

func semantics(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("semantics", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	platformPath := flags.String("platform", "", "exact platform binding")
	recipesPath := flags.String("recipes", "", "directory containing remediation recipes")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *platformPath == "" {
		return fmt.Errorf("semantics requires --platform")
	}
	layer, err := loadBinding(*platformPath)
	if err != nil {
		return err
	}
	var recipes []model.RemediationRecipe
	if *recipesPath != "" {
		registry, err := loadRecipes(*recipesPath)
		if err != nil {
			return err
		}
		recipes = registry
	}
	digest, err := supportevidence.PromotionSemanticsDigest(layer, recipes)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "promotion_semantics_sha256=%s\n", digest)
	return err
}

func normalize(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("normalize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "safe manifest draft")
	output := flags.String("output", "-", "canonical JSON output or - for stdout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*input) == "" {
		return fmt.Errorf("normalize requires --input and accepts optional --output")
	}
	manifest, err := supportevidence.LoadFile(*input)
	if err != nil {
		return err
	}
	canonical, err := supportevidence.CanonicalBytes(manifest)
	if err != nil {
		return err
	}
	digest, err := supportevidence.Digest(manifest)
	if err != nil {
		return err
	}
	manifestDigest, err := supportevidence.ManifestDigest(manifest)
	if err != nil {
		return err
	}
	expectedPath, err := supportevidence.RelativePath(manifest)
	if err != nil {
		return err
	}
	if *output == "-" {
		_, err = stdout.Write(canonical)
		return err
	}
	if err := writeRegularFile(*output, canonical); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		stdout,
		"path=%s\nevidence_sha256=%s\nmanifest_sha256=%s\n",
		expectedPath,
		digest,
		manifestDigest,
	)
	return err
}

func validate(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "normalized evidence manifest")
	repositoryRoot := flags.String("repository-root", "", "repository root used to enforce the public path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || strings.TrimSpace(*input) == "" {
		return fmt.Errorf("validate requires --input")
	}
	manifest, err := supportevidence.LoadFile(*input)
	if err != nil {
		return err
	}
	if *repositoryRoot != "" {
		if err := validateRepositoryPath(*repositoryRoot, *input, manifest); err != nil {
			return err
		}
	}
	return printIdentity(stdout, manifest)
}

func verifyPlatform(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify-platform", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "normalized evidence manifest")
	platformPath := flags.String("platform", "", "exact platform binding")
	repositoryRoot := flags.String("repository-root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *platformPath == "" {
		return fmt.Errorf("verify-platform requires --manifest and --platform")
	}
	manifest, err := supportevidence.LoadFile(*manifestPath)
	if err != nil {
		return err
	}
	if manifest.Remediation != nil {
		return fmt.Errorf("verify-platform accepts scan-only evidence; use verify-promotion or verify-final for remediation evidence")
	}
	if err := validateRepositoryPath(*repositoryRoot, *manifestPath, manifest); err != nil {
		return err
	}
	layer, err := loadBinding(*platformPath)
	if err != nil {
		return err
	}
	if layer.ScanSupport == nil || *layer.ScanSupport != model.ScanSupportTested {
		return fmt.Errorf("verify-platform requires tested scan support")
	}
	if err := supportevidence.ValidateScanPromotion(layer, &manifest); err != nil {
		return err
	}
	return printIdentity(stdout, manifest)
}

func verifyPromotion(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify-promotion", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "normalized evidence manifest")
	platformPath := flags.String("platform", "", "exact platform binding")
	recipesPath := flags.String("recipes", "", "directory containing remediation recipes")
	repositoryRoot := flags.String("repository-root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *manifestPath == "" || *platformPath == "" || *recipesPath == "" {
		return fmt.Errorf("verify-promotion requires --manifest, --platform, and --recipes")
	}
	manifest, err := supportevidence.LoadFile(*manifestPath)
	if err != nil {
		return err
	}
	if err := validateRepositoryPath(*repositoryRoot, *manifestPath, manifest); err != nil {
		return err
	}
	layer, err := loadBinding(*platformPath)
	if err != nil {
		return err
	}
	recipes, err := loadRecipes(*recipesPath)
	if err != nil {
		return err
	}
	if err := supportevidence.ValidateVerifiedPromotion(layer, recipes, &manifest); err != nil {
		return err
	}
	return printIdentity(stdout, manifest)
}

func verifyFinal(
	args []string,
	stdout io.Writer,
	inspectGoBinary func(string) (supportevidence.ArtifactIdentity, supportevidence.GoBinaryBuildIdentity, error),
) error {
	flags := flag.NewFlagSet("verify-final", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "pre-promotion candidate evidence")
	finalPath := flags.String("final", "", "post-promotion final evidence")
	platformPath := flags.String("platform", "", "exact platform binding")
	recipesPath := flags.String("recipes", "", "directory containing remediation recipes")
	repositoryRoot := flags.String("repository-root", ".", "repository root")
	sourceCommit := flags.String("source-commit", "", "commit used to build the final binary")
	binaryPath := flags.String("binary", "", "final OpenCIIP binary")
	ruleBundlePath := flags.String("rule-bundle", "", "final embedded rule bundle source")
	runnerPath := flags.String("runner", "", "final remediation runner")
	scanArchivePath := flags.String("scan-archive", "", "final read-only scan archive")
	itemArchivePath := flags.String("item-archive", "", "final item rollback archive")
	rebootArchivePath := flags.String("reboot-archive", "", "final reboot rollback archive")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *candidatePath == "" || *finalPath == "" ||
		*platformPath == "" || *sourceCommit == "" || *binaryPath == "" ||
		*ruleBundlePath == "" || *scanArchivePath == "" {
		return fmt.Errorf("verify-final requires candidate, final, platform, source, binary, rule bundle, and scan archive inputs")
	}
	candidate, err := supportevidence.LoadFile(*candidatePath)
	if err != nil {
		return err
	}
	final, err := supportevidence.LoadFile(*finalPath)
	if err != nil {
		return err
	}
	if err := validateRepositoryPath(*repositoryRoot, *finalPath, final); err != nil {
		return err
	}
	artifacts := supportevidence.FinalArtifacts{
		SourceCommit:       *sourceCommit,
		RemediationArchive: make(map[string]supportevidence.ArtifactIdentity),
	}
	if inspectGoBinary == nil {
		return fmt.Errorf("final binary inspector is unavailable")
	}
	if artifacts.Binary, artifacts.BinaryBuild, err = inspectGoBinary(*binaryPath); err != nil {
		return fmt.Errorf("identify final binary: %w", err)
	}
	if artifacts.RuleBundle, err = fileIdentity(*ruleBundlePath); err != nil {
		return fmt.Errorf("identify final rule bundle: %w", err)
	}
	if artifacts.ScanArchive, err = fileIdentity(*scanArchivePath); err != nil {
		return fmt.Errorf("identify final scan archive: %w", err)
	}
	if final.Remediation != nil {
		if *recipesPath == "" || *runnerPath == "" || *itemArchivePath == "" || *rebootArchivePath == "" {
			return fmt.Errorf("final remediation evidence requires recipes, runner, item archive, and reboot archive inputs")
		}
		if artifacts.Runner, err = fileIdentity(*runnerPath); err != nil {
			return fmt.Errorf("identify final runner: %w", err)
		}
		if artifacts.RemediationArchive["item_then_run_rollback"], err = fileIdentity(*itemArchivePath); err != nil {
			return fmt.Errorf("identify final item rollback archive: %w", err)
		}
		if artifacts.RemediationArchive["reboot_then_run_rollback"], err = fileIdentity(*rebootArchivePath); err != nil {
			return fmt.Errorf("identify final reboot rollback archive: %w", err)
		}
	}
	layer, err := loadBinding(*platformPath)
	if err != nil {
		return err
	}
	var recipes []model.RemediationRecipe
	if final.Remediation != nil {
		recipes, err = loadRecipes(*recipesPath)
		if err != nil {
			return err
		}
	}
	artifacts.PromotionSemanticsSHA256, err =
		supportevidence.PromotionSemanticsDigest(layer, recipes)
	if err != nil {
		return err
	}
	if err := supportevidence.ValidateFinalEvidence(candidate, final, artifacts); err != nil {
		return err
	}
	if final.Remediation == nil {
		if err := supportevidence.ValidateScanPromotion(layer, &final); err != nil {
			return err
		}
	} else {
		if err := supportevidence.ValidateVerifiedPromotion(layer, recipes, &final); err != nil {
			return err
		}
	}
	return printIdentity(stdout, final)
}

func loadBinding(path string) (model.BindingLayer, error) {
	clean := filepath.Clean(path)
	loader := rules.NewLoader(os.DirFS(filepath.Dir(clean)))
	return loader.LoadBinding(filepath.Base(clean))
}

func loadRecipes(directory string) ([]model.RemediationRecipe, error) {
	clean := filepath.Clean(directory)
	parent := filepath.Dir(clean)
	name := filepath.Base(clean)
	registry, err := recipe.Load(os.DirFS(parent), filepath.ToSlash(name))
	if err != nil {
		return nil, err
	}
	return registry.All(), nil
}

func validateRepositoryPath(root, path string, manifest supportevidence.Manifest) error {
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	pathAbsolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve evidence path: %w", err)
	}
	relative, err := filepath.Rel(rootAbsolute, pathAbsolute)
	if err != nil {
		return fmt.Errorf("resolve repository evidence path: %w", err)
	}
	if err := supportevidence.ValidateRelativePath(relative, manifest); err != nil {
		return err
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbsolute)
	if err != nil {
		return fmt.Errorf("resolve repository root links: %w", err)
	}
	pathResolved, err := filepath.EvalSymlinks(pathAbsolute)
	if err != nil {
		return fmt.Errorf("resolve repository evidence links: %w", err)
	}
	resolvedRelative, err := filepath.Rel(rootResolved, pathResolved)
	if err != nil {
		return fmt.Errorf("resolve linked repository evidence path: %w", err)
	}
	if err := supportevidence.ValidateRelativePath(resolvedRelative, manifest); err != nil {
		return fmt.Errorf("repository evidence must not use a linked or redirected path: %w", err)
	}
	return nil
}

func printIdentity(writer io.Writer, manifest supportevidence.Manifest) error {
	path, err := supportevidence.RelativePath(manifest)
	if err != nil {
		return err
	}
	digest, err := supportevidence.Digest(manifest)
	if err != nil {
		return err
	}
	manifestDigest, err := supportevidence.ManifestDigest(manifest)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		writer,
		"path=%s\nevidence_sha256=%s\nmanifest_sha256=%s\n",
		path,
		digest,
		manifestDigest,
	)
	return err
}

func fileIdentity(path string) (supportevidence.ArtifactIdentity, error) {
	return supportevidence.InspectArtifact(path)
}

func digestData(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeRegularFile(path string, data []byte) error {
	parent := filepath.Dir(filepath.Clean(path))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	info, err := os.Lstat(path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return fmt.Errorf("refusing to replace non-regular output %q", path)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("inspect output: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write canonical evidence: %w", err)
	}
	return nil
}

func usageError() error {
	return fmt.Errorf("usage: openciip-support-evidence <prepare|semantics|normalize|validate|verify-platform|verify-promotion|verify-final> [options]")
}
