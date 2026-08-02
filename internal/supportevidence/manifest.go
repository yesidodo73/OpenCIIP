package supportevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const (
	SchemaVersion       = 1
	maximumManifestSize = 1 << 20
)

type ArtifactStage string

const (
	ArtifactStageCandidate ArtifactStage = "candidate"
	ArtifactStageFinal     ArtifactStage = "final"
)

var (
	exactTokenPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,127}$`)
	versionTokenPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$`)
	commitPattern       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	environmentPattern  = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z ._()+-]{0,127}$`)
	ipv4Pattern         = regexp.MustCompile(`(?:^|[^0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:$|[^0-9])`)
)

type Manifest struct {
	SchemaVersion int                  `json:"schema_version" yaml:"schema_version"`
	ArtifactStage ArtifactStage        `json:"artifact_stage" yaml:"artifact_stage"`
	Platform      Platform             `json:"platform" yaml:"platform"`
	Environment   string               `json:"environment" yaml:"environment"`
	VerifiedAt    string               `json:"verified_at" yaml:"verified_at"`
	CapturedAt    string               `json:"captured_at" yaml:"captured_at"`
	Source        SourceIdentity       `json:"source" yaml:"source"`
	Scan          ReadOnlyScanEvidence `json:"scan" yaml:"scan"`
	Remediation   *RemediationEvidence `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

type Platform struct {
	OS           string `json:"os" yaml:"os"`
	ID           string `json:"id" yaml:"id"`
	Version      string `json:"version" yaml:"version"`
	Architecture string `json:"architecture" yaml:"architecture"`
}

type SourceIdentity struct {
	ToolVersion              string `json:"tool_version" yaml:"tool_version"`
	ToolCommit               string `json:"tool_commit" yaml:"tool_commit"`
	BinarySHA256             string `json:"binary_sha256" yaml:"binary_sha256"`
	RuleBundleSHA256         string `json:"rule_bundle_sha256" yaml:"rule_bundle_sha256"`
	PromotionSemanticsSHA256 string `json:"promotion_semantics_sha256" yaml:"promotion_semantics_sha256"`
}

type ReadOnlyScanEvidence struct {
	ReadOnly             bool             `json:"read_only" yaml:"read_only"`
	Complete             bool             `json:"complete" yaml:"complete"`
	SystemStateUnchanged bool             `json:"system_state_unchanged" yaml:"system_state_unchanged"`
	ResultCount          int              `json:"result_count" yaml:"result_count"`
	UniqueRuleCount      int              `json:"unique_rule_count" yaml:"unique_rule_count"`
	ErrorCount           int              `json:"error_count" yaml:"error_count"`
	StatusCounts         ScanStatusCounts `json:"status_counts" yaml:"status_counts"`
	MetadataSHA256       string           `json:"metadata_sha256" yaml:"metadata_sha256"`
	ResultsSHA256        string           `json:"results_sha256" yaml:"results_sha256"`
	ArchiveSHA256        string           `json:"archive_sha256" yaml:"archive_sha256"`
	ArchiveSizeBytes     int64            `json:"archive_size_bytes" yaml:"archive_size_bytes"`
}

type ScanStatusCounts struct {
	Fail          int `json:"fail" yaml:"fail"`
	Unknown       int `json:"unknown" yaml:"unknown"`
	Error         int `json:"error" yaml:"error"`
	Pass          int `json:"pass" yaml:"pass"`
	NotApplicable int `json:"not_applicable" yaml:"not_applicable"`
	Skipped       int `json:"skipped" yaml:"skipped"`
}

type RemediationEvidence struct {
	BinarySHA256    string                    `json:"binary_sha256" yaml:"binary_sha256"`
	RunnerSHA256    string                    `json:"runner_sha256" yaml:"runner_sha256"`
	Rules           []RemediationRuleEvidence `json:"rules" yaml:"rules"`
	Reboot          RebootEvidence            `json:"reboot" yaml:"reboot"`
	CleanupVerified bool                      `json:"cleanup_verified" yaml:"cleanup_verified"`
	Archives        []ArchiveEvidence         `json:"archives" yaml:"archives"`
}

type RemediationRuleEvidence struct {
	RuleID               string `json:"rule_id" yaml:"rule_id"`
	ApplyVerified        bool   `json:"apply_verified" yaml:"apply_verified"`
	RecheckStatus        string `json:"recheck_status" yaml:"recheck_status"`
	ItemRollbackVerified bool   `json:"item_rollback_verified" yaml:"item_rollback_verified"`
	RunRollbackVerified  bool   `json:"run_rollback_verified" yaml:"run_rollback_verified"`
}

type RebootEvidence struct {
	Performed        bool `json:"performed" yaml:"performed"`
	BootIDChanged    bool `json:"boot_id_changed" yaml:"boot_id_changed"`
	RollbackVerified bool `json:"rollback_verified" yaml:"rollback_verified"`
}

type ArchiveEvidence struct {
	Scenario       string `json:"scenario" yaml:"scenario"`
	Result         string `json:"result" yaml:"result"`
	ArchiveSHA256  string `json:"archive_sha256" yaml:"archive_sha256"`
	ManifestSHA256 string `json:"manifest_sha256" yaml:"manifest_sha256"`
	SizeBytes      int64  `json:"size_bytes" yaml:"size_bytes"`
}

func LoadFile(path string) (Manifest, error) {
	data, err := readStableRegular(path, maximumManifestSize)
	if err != nil {
		return Manifest{}, fmt.Errorf("read OS support evidence: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (Manifest, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode OS support evidence: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple YAML or JSON documents are not allowed")
		}
		return Manifest{}, fmt.Errorf("decode trailing OS support evidence: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported OS support evidence schema version %d", m.SchemaVersion)
	}
	if m.ArtifactStage != ArtifactStageCandidate && m.ArtifactStage != ArtifactStageFinal {
		return fmt.Errorf("artifact_stage must be candidate or final")
	}
	if err := m.Platform.Validate(); err != nil {
		return fmt.Errorf("validate evidence platform: %w", err)
	}
	if !environmentPattern.MatchString(m.Environment) || ipv4Pattern.MatchString(m.Environment) {
		return fmt.Errorf("evidence environment must contain only a public OS description without an IP address or path")
	}
	switch m.ArtifactStage {
	case ArtifactStageCandidate:
		if m.VerifiedAt != "" {
			return fmt.Errorf("candidate evidence verified_at must be empty")
		}
	case ArtifactStageFinal:
		if _, err := time.Parse(time.RFC3339, m.VerifiedAt); err != nil {
			return fmt.Errorf("final evidence verified_at must be RFC3339: %w", err)
		}
	}
	if _, err := time.Parse(time.RFC3339, m.CapturedAt); err != nil {
		return fmt.Errorf("evidence captured_at must be RFC3339: %w", err)
	}
	if err := m.Source.Validate(); err != nil {
		return fmt.Errorf("validate evidence source: %w", err)
	}
	if err := m.Scan.Validate(); err != nil {
		return fmt.Errorf("validate read-only scan evidence: %w", err)
	}
	if m.Remediation != nil {
		if err := m.Remediation.Validate(); err != nil {
			return fmt.Errorf("validate remediation evidence: %w", err)
		}
		if m.Source.BinarySHA256 != m.Remediation.BinarySHA256 {
			return fmt.Errorf("scan and remediation evidence must use the same binary_sha256")
		}
	}
	return nil
}

func (p Platform) Validate() error {
	if p.OS != "linux" {
		return fmt.Errorf("os must be linux")
	}
	for name, value := range map[string]string{
		"id":           p.ID,
		"version":      p.Version,
		"architecture": p.Architecture,
	} {
		if !exactTokenPattern.MatchString(value) {
			return fmt.Errorf("%s %q is not a canonical exact selector", name, value)
		}
	}
	return nil
}

func (s SourceIdentity) Validate() error {
	if !versionTokenPattern.MatchString(s.ToolVersion) {
		return fmt.Errorf("tool_version %q is not canonical", s.ToolVersion)
	}
	if !commitPattern.MatchString(s.ToolCommit) {
		return fmt.Errorf("tool_commit must be a lowercase 40-character Git commit")
	}
	for name, value := range map[string]string{
		"binary_sha256":              s.BinarySHA256,
		"rule_bundle_sha256":         s.RuleBundleSHA256,
		"promotion_semantics_sha256": s.PromotionSemanticsSHA256,
	} {
		if !sha256Pattern.MatchString(value) {
			return fmt.Errorf("%s must be a lowercase SHA-256", name)
		}
	}
	return nil
}

func (s ReadOnlyScanEvidence) Validate() error {
	if !s.ReadOnly {
		return fmt.Errorf("read_only must be true")
	}
	if !s.Complete {
		return fmt.Errorf("complete must be true")
	}
	if !s.SystemStateUnchanged {
		return fmt.Errorf("system_state_unchanged must be true")
	}
	if s.ResultCount != 67 || s.UniqueRuleCount != 67 {
		return fmt.Errorf("result_count and unique_rule_count must both be 67")
	}
	if s.ErrorCount != 0 || s.StatusCounts.Error != 0 {
		return fmt.Errorf("error_count and status_counts.error must both be 0")
	}
	counts := []int{
		s.StatusCounts.Fail,
		s.StatusCounts.Unknown,
		s.StatusCounts.Error,
		s.StatusCounts.Pass,
		s.StatusCounts.NotApplicable,
		s.StatusCounts.Skipped,
	}
	total := 0
	for _, count := range counts {
		if count < 0 {
			return fmt.Errorf("status counts must not be negative")
		}
		total += count
	}
	if total != s.ResultCount {
		return fmt.Errorf("status counts total %d does not match result_count %d", total, s.ResultCount)
	}
	if !sha256Pattern.MatchString(s.MetadataSHA256) ||
		!sha256Pattern.MatchString(s.ResultsSHA256) ||
		!sha256Pattern.MatchString(s.ArchiveSHA256) {
		return fmt.Errorf("scan metadata, results, and archive hashes must be lowercase SHA-256 values")
	}
	if s.ArchiveSizeBytes <= 0 {
		return fmt.Errorf("scan archive_size_bytes must be positive")
	}
	return nil
}

func (r RemediationEvidence) Validate() error {
	if !sha256Pattern.MatchString(r.BinarySHA256) || !sha256Pattern.MatchString(r.RunnerSHA256) {
		return fmt.Errorf("binary_sha256 and runner_sha256 must be lowercase SHA-256 values")
	}
	requiredRules := map[string]bool{"U-19": false, "U-22": false, "U-29": false}
	if len(r.Rules) != len(requiredRules) {
		return fmt.Errorf("remediation evidence must contain exactly U-19, U-22, and U-29")
	}
	for _, rule := range r.Rules {
		if _, expected := requiredRules[rule.RuleID]; !expected {
			return fmt.Errorf("unexpected remediation rule %s", rule.RuleID)
		}
		if requiredRules[rule.RuleID] {
			return fmt.Errorf("duplicate remediation rule %s", rule.RuleID)
		}
		requiredRules[rule.RuleID] = true
		if !rule.ApplyVerified || rule.RecheckStatus != "PASS" ||
			!rule.ItemRollbackVerified || !rule.RunRollbackVerified {
			return fmt.Errorf("%s does not prove apply, PASS recheck, item rollback, and run rollback", rule.RuleID)
		}
	}
	if !r.Reboot.Performed || !r.Reboot.BootIDChanged || !r.Reboot.RollbackVerified {
		return fmt.Errorf("reboot evidence must prove a changed boot and verified rollback")
	}
	if !r.CleanupVerified {
		return fmt.Errorf("cleanup_verified must be true")
	}

	requiredScenarios := map[string]bool{
		"item_then_run_rollback":   false,
		"reboot_then_run_rollback": false,
	}
	if len(r.Archives) != len(requiredScenarios) {
		return fmt.Errorf("remediation evidence must contain exactly item and reboot rollback archives")
	}
	for _, archive := range r.Archives {
		if _, expected := requiredScenarios[archive.Scenario]; !expected {
			return fmt.Errorf("unexpected remediation archive scenario %q", archive.Scenario)
		}
		if requiredScenarios[archive.Scenario] {
			return fmt.Errorf("duplicate remediation archive scenario %q", archive.Scenario)
		}
		requiredScenarios[archive.Scenario] = true
		if archive.Result != "PASS" {
			return fmt.Errorf("remediation archive %s result must be PASS", archive.Scenario)
		}
		if !sha256Pattern.MatchString(archive.ArchiveSHA256) ||
			!sha256Pattern.MatchString(archive.ManifestSHA256) {
			return fmt.Errorf("remediation archive %s hashes must be lowercase SHA-256 values", archive.Scenario)
		}
		if archive.SizeBytes <= 0 {
			return fmt.Errorf("remediation archive %s size_bytes must be positive", archive.Scenario)
		}
	}
	return nil
}

func CanonicalBytes(manifest Manifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	normalized := manifest
	if normalized.Remediation != nil {
		remediation := *normalized.Remediation
		remediation.Rules = append([]RemediationRuleEvidence(nil), remediation.Rules...)
		sort.Slice(remediation.Rules, func(i, j int) bool {
			return remediation.Rules[i].RuleID < remediation.Rules[j].RuleID
		})
		remediation.Archives = append([]ArchiveEvidence(nil), remediation.Archives...)
		sort.Slice(remediation.Archives, func(i, j int) bool {
			return remediation.Archives[i].Scenario < remediation.Archives[j].Scenario
		})
		normalized.Remediation = &remediation
	}
	data, err := json.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("encode canonical OS support evidence: %w", err)
	}
	return append(data, '\n'), nil
}

func Digest(manifest Manifest) (string, error) {
	data, err := EvidenceBytes(manifest)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

func ManifestDigest(manifest Manifest) (string, error) {
	data, err := CanonicalBytes(manifest)
	if err != nil {
		return "", err
	}
	return digestBytes(data), nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func RelativePath(manifest Manifest) (string, error) {
	if err := manifest.Platform.Validate(); err != nil {
		return "", err
	}
	name := strings.Join([]string{
		manifest.Platform.ID,
		manifest.Platform.Version,
		manifest.Platform.Architecture,
	}, "-") + ".json"
	return filepath.ToSlash(filepath.Join("evidence", "os-support", name)), nil
}

func ValidateRelativePath(path string, manifest Manifest) error {
	expected, err := RelativePath(manifest)
	if err != nil {
		return err
	}
	canonical := filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(path) || canonical != expected {
		return fmt.Errorf("OS support evidence path %q must be %q", canonical, expected)
	}
	return nil
}
