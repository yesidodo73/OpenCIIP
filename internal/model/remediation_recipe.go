package model

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

const RemediationRecipeSchemaVersion = 1

const RecipePreserveContentFileMetadata = "preserve_content_file_metadata"

var recipeIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

type RemediationRecipeCatalog struct {
	SchemaVersion int                 `json:"schema_version" yaml:"schema_version"`
	Recipes       []RemediationRecipe `json:"recipes" yaml:"recipes"`
}

type RemediationRecipe struct {
	ID             string                        `json:"id" yaml:"id"`
	GuideYear      int                           `json:"guide_year" yaml:"guide_year"`
	RuleID         string                        `json:"rule_id" yaml:"rule_id"`
	Selector       PlatformSelector              `json:"selector" yaml:"selector"`
	Verification   RemediationRecipeVerification `json:"verification" yaml:"verification"`
	Risk           RemediationRisk               `json:"risk" yaml:"risk"`
	ExpectedImpact string                        `json:"expected_impact" yaml:"expected_impact"`
	Operations     []FileMetadataRecipeEntry     `json:"operations" yaml:"operations"`
}

type RemediationRecipeVerificationState string

const (
	RemediationRecipeVerificationPending  RemediationRecipeVerificationState = "pending"
	RemediationRecipeVerificationVerified RemediationRecipeVerificationState = "verified"
	RemediationRecipeVerificationRejected RemediationRecipeVerificationState = "rejected"
)

func (s RemediationRecipeVerificationState) Valid() bool {
	return s == RemediationRecipeVerificationPending ||
		s == RemediationRecipeVerificationVerified ||
		s == RemediationRecipeVerificationRejected
}

type RemediationRecipeVerification struct {
	State          RemediationRecipeVerificationState `json:"state" yaml:"state"`
	Environments   []string                           `json:"environments,omitempty" yaml:"environments,omitempty"`
	VerifiedAt     string                             `json:"verified_at,omitempty" yaml:"verified_at,omitempty"`
	EvidenceSHA256 []string                           `json:"evidence_sha256,omitempty" yaml:"evidence_sha256,omitempty"`
}

func (v RemediationRecipeVerification) Validate() error {
	if !v.State.Valid() {
		return fmt.Errorf("invalid remediation recipe verification state %q", v.State)
	}
	environments := make(map[string]struct{}, len(v.Environments))
	for index, environment := range v.Environments {
		if strings.TrimSpace(environment) == "" || strings.TrimSpace(environment) != environment || strings.ContainsAny(environment, "\x00\r\n") {
			return fmt.Errorf("remediation recipe verification environment %d is empty or non-canonical", index)
		}
		if _, duplicate := environments[environment]; duplicate {
			return fmt.Errorf("remediation recipe verification environment %q is duplicated", environment)
		}
		environments[environment] = struct{}{}
	}

	evidence := make(map[string]struct{}, len(v.EvidenceSHA256))
	for index, digest := range v.EvidenceSHA256 {
		if !validSHA256(digest) {
			return fmt.Errorf("remediation recipe verification evidence digest %d is not a lowercase SHA-256", index)
		}
		if _, duplicate := evidence[digest]; duplicate {
			return fmt.Errorf("remediation recipe verification evidence digest %q is duplicated", digest)
		}
		evidence[digest] = struct{}{}
	}

	if v.State == RemediationRecipeVerificationVerified {
		if len(v.Environments) == 0 {
			return fmt.Errorf("verified remediation recipe requires at least one environment")
		}
		if _, err := time.Parse(time.RFC3339, v.VerifiedAt); err != nil {
			return fmt.Errorf("verified remediation recipe requires an RFC3339 verified_at: %w", err)
		}
		if len(v.EvidenceSHA256) == 0 {
			return fmt.Errorf("verified remediation recipe requires at least one evidence SHA-256")
		}
		return nil
	}
	if v.VerifiedAt != "" {
		return fmt.Errorf("verified_at is only valid for a verified remediation recipe")
	}
	if len(v.EvidenceSHA256) != 0 {
		return fmt.Errorf("evidence SHA-256 values are only valid for a verified remediation recipe")
	}
	return nil
}

type FileMetadataRecipeEntry struct {
	Type             string   `json:"type" yaml:"type"`
	Path             string   `json:"path" yaml:"path"`
	AllowedOwners    []string `json:"allowed_owners" yaml:"allowed_owners"`
	RemediationOwner string   `json:"remediation_owner" yaml:"remediation_owner"`
	MaximumMode      string   `json:"maximum_mode" yaml:"maximum_mode"`
}

func (c RemediationRecipeCatalog) Validate() error {
	if c.SchemaVersion != RemediationRecipeSchemaVersion {
		return fmt.Errorf("unsupported remediation recipe schema version %d", c.SchemaVersion)
	}
	if len(c.Recipes) == 0 {
		return fmt.Errorf("remediation recipe catalog is empty")
	}
	ids := make(map[string]struct{}, len(c.Recipes))
	keys := make(map[string]struct{}, len(c.Recipes))
	for _, recipe := range c.Recipes {
		if err := recipe.Validate(); err != nil {
			return err
		}
		if _, duplicate := ids[recipe.ID]; duplicate {
			return fmt.Errorf("remediation recipe id %s is duplicated", recipe.ID)
		}
		ids[recipe.ID] = struct{}{}
		key := recipe.MatchKey()
		if _, duplicate := keys[key]; duplicate {
			return fmt.Errorf("more than one remediation recipe targets %s", recipe.RuleID)
		}
		keys[key] = struct{}{}
	}
	return nil
}

func (r RemediationRecipe) Validate() error {
	if !recipeIdentifierPattern.MatchString(r.ID) {
		return fmt.Errorf("remediation recipe id %q is invalid", r.ID)
	}
	if r.GuideYear < 1 || !bindingRuleIDPatternForRecipe.MatchString(r.RuleID) {
		return fmt.Errorf("remediation recipe %s has an invalid guide year or rule id", r.ID)
	}
	if !r.Risk.Valid() || r.Risk == RiskUnsupported {
		return fmt.Errorf("remediation recipe %s has an invalid risk", r.ID)
	}
	if strings.TrimSpace(r.ExpectedImpact) == "" || strings.TrimSpace(r.ExpectedImpact) != r.ExpectedImpact {
		return fmt.Errorf("remediation recipe %s has no canonical impact description", r.ID)
	}
	if err := validateExactRemediationSelector(r.Selector); err != nil {
		return fmt.Errorf("remediation recipe %s: %w", r.ID, err)
	}
	if err := r.Verification.Validate(); err != nil {
		return fmt.Errorf("remediation recipe %s: %w", r.ID, err)
	}
	if len(r.Operations) == 0 {
		return fmt.Errorf("remediation recipe %s has no operations", r.ID)
	}
	paths := make(map[string]struct{}, len(r.Operations))
	for index, operation := range r.Operations {
		if err := operation.Validate(); err != nil {
			return fmt.Errorf("remediation recipe %s operation %d: %w", r.ID, index, err)
		}
		if _, duplicate := paths[operation.Path]; duplicate {
			return fmt.Errorf("remediation recipe %s repeats path %s", r.ID, operation.Path)
		}
		paths[operation.Path] = struct{}{}
	}
	return nil
}

func (r RemediationRecipe) MatchKey() string {
	selector := r.Selector
	values := []string{
		r.RuleID,
		selector.OS,
		selector.Family,
		selector.ID,
		selector.Version,
		selector.VersionMajor,
		selector.Architecture,
	}
	for index := range values {
		values[index] = strings.ToLower(values[index])
	}
	return strings.Join(values, "\x00")
}

func validateExactRemediationSelector(selector PlatformSelector) error {
	values := []string{selector.OS, selector.Family, selector.ID, selector.Version, selector.VersionMajor, selector.Architecture}
	for _, value := range values {
		if value != strings.TrimSpace(value) || strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("selector is not canonical")
		}
	}
	if selector.VersionMajor != "" {
		return fmt.Errorf("selector must not use version_major; remediation requires an exact version")
	}
	if selector.ID == "" || selector.Version == "" {
		return fmt.Errorf("selector must bind an OS id and exact version")
	}
	return nil
}

var bindingRuleIDPatternForRecipe = regexp.MustCompile(`^U-[0-9]{2}$`)
var octalModePattern = regexp.MustCompile(`^0[0-7]{3,4}$`)
var accountNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?$`)

func (e FileMetadataRecipeEntry) Validate() error {
	if e.Type != RecipePreserveContentFileMetadata {
		return fmt.Errorf("unsupported operation type %q", e.Type)
	}
	if !path.IsAbs(e.Path) || path.Clean(e.Path) != e.Path || strings.ContainsAny(e.Path, "\x00\r\n") {
		return fmt.Errorf("path %q is not a canonical absolute path", e.Path)
	}
	if len(e.AllowedOwners) == 0 || !accountNamePattern.MatchString(e.RemediationOwner) || !octalModePattern.MatchString(e.MaximumMode) {
		return fmt.Errorf("allowed owners, remediation owner, or maximum mode is invalid")
	}
	seen := make(map[string]struct{}, len(e.AllowedOwners))
	remediationOwnerAllowed := false
	for _, owner := range e.AllowedOwners {
		if !accountNamePattern.MatchString(owner) {
			return fmt.Errorf("allowed owner %q is invalid", owner)
		}
		if _, duplicate := seen[owner]; duplicate {
			return fmt.Errorf("allowed owner %q is duplicated", owner)
		}
		seen[owner] = struct{}{}
		if owner == e.RemediationOwner {
			remediationOwnerAllowed = true
		}
	}
	if !remediationOwnerAllowed {
		return fmt.Errorf("remediation owner must be one of the allowed owners")
	}
	return nil
}
