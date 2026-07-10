package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

var unixRuleIDPattern = regexp.MustCompile(`^U-[0-9]{2}$`)

type Guide struct {
	Year   int    `json:"year" yaml:"year"`
	Title  string `json:"title" yaml:"title"`
	Domain string `json:"domain" yaml:"domain"`
}

type Criteria struct {
	Summary              string `json:"summary" yaml:"summary"`
	Pass                 string `json:"pass" yaml:"pass"`
	Fail                 string `json:"fail" yaml:"fail"`
	ManualReviewRequired bool   `json:"manual_review_required,omitempty" yaml:"manual_review_required,omitempty"`
}

type Reference struct {
	Guide   string `json:"guide" yaml:"guide"`
	Section string `json:"section" yaml:"section"`
	Item    string `json:"item" yaml:"item"`
	Pages   []int  `json:"pages" yaml:"pages"`
}

// RuleDefinition contains guide metadata and no executable commands.
type RuleDefinition struct {
	ID         string         `json:"id" yaml:"id"`
	Title      string         `json:"title" yaml:"title"`
	Category   Category       `json:"category" yaml:"category"`
	Severity   Severity       `json:"severity" yaml:"severity"`
	Evaluator  string         `json:"evaluator,omitempty" yaml:"evaluator,omitempty"`
	Criteria   Criteria       `json:"criteria" yaml:"criteria"`
	Reference  Reference      `json:"reference" yaml:"reference"`
	Parameters map[string]any `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

func (r RuleDefinition) ValidateMetadata() error {
	if !unixRuleIDPattern.MatchString(r.ID) {
		return fmt.Errorf("rule id %q must match U-NN", r.ID)
	}
	if strings.TrimSpace(r.Title) == "" {
		return fmt.Errorf("rule %s has an empty title", r.ID)
	}
	if !r.Category.Valid() {
		return fmt.Errorf("rule %s has invalid category %q", r.ID, r.Category)
	}
	if !r.Severity.Valid() {
		return fmt.Errorf("rule %s has invalid severity %q", r.ID, r.Severity)
	}
	if r.Reference.Item != "" && r.Reference.Item != r.ID {
		return fmt.Errorf("rule %s reference item is %q", r.ID, r.Reference.Item)
	}
	for _, page := range r.Reference.Pages {
		if page < 1 {
			return fmt.Errorf("rule %s has invalid reference page %d", r.ID, page)
		}
	}
	return nil
}

type Catalog struct {
	SchemaVersion int              `json:"schema_version" yaml:"schema_version"`
	Guide         Guide            `json:"guide" yaml:"guide"`
	Rules         []RuleDefinition `json:"rules" yaml:"rules"`
}

func (c Catalog) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("unsupported rule catalog schema version %d", c.SchemaVersion)
	}
	if c.Guide.Year < 1 || strings.TrimSpace(c.Guide.Title) == "" || strings.TrimSpace(c.Guide.Domain) == "" {
		return fmt.Errorf("rule catalog guide metadata is incomplete")
	}

	seen := make(map[string]struct{}, len(c.Rules))
	for _, rule := range c.Rules {
		if err := rule.ValidateMetadata(); err != nil {
			return err
		}
		if _, exists := seen[rule.ID]; exists {
			return fmt.Errorf("duplicate rule id %s", rule.ID)
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

type Profile struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
	RuleIDs     []string `json:"rule_ids" yaml:"rule_ids"`
}

type ProfileSet struct {
	SchemaVersion int       `json:"schema_version" yaml:"schema_version"`
	Profiles      []Profile `json:"profiles" yaml:"profiles"`
}

func (p ProfileSet) Validate(catalog Catalog) error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("unsupported profile schema version %d", p.SchemaVersion)
	}
	known := make(map[string]struct{}, len(catalog.Rules))
	for _, rule := range catalog.Rules {
		known[rule.ID] = struct{}{}
	}
	profileIDs := make(map[string]struct{}, len(p.Profiles))
	for _, profile := range p.Profiles {
		if strings.TrimSpace(profile.ID) == "" || strings.TrimSpace(profile.Title) == "" {
			return fmt.Errorf("profile id and title are required")
		}
		if _, exists := profileIDs[profile.ID]; exists {
			return fmt.Errorf("duplicate profile id %q", profile.ID)
		}
		profileIDs[profile.ID] = struct{}{}
		selected := make(map[string]struct{}, len(profile.RuleIDs))
		for _, ruleID := range profile.RuleIDs {
			if _, exists := known[ruleID]; !exists {
				return fmt.Errorf("profile %s references unknown rule %s", profile.ID, ruleID)
			}
			if _, exists := selected[ruleID]; exists {
				return fmt.Errorf("profile %s references rule %s more than once", profile.ID, ruleID)
			}
			selected[ruleID] = struct{}{}
		}
	}
	return nil
}

type PlatformSelector struct {
	OS           string `json:"os,omitempty" yaml:"os,omitempty"`
	Family       string `json:"family,omitempty" yaml:"family,omitempty"`
	ID           string `json:"id,omitempty" yaml:"id,omitempty"`
	Version      string `json:"version,omitempty" yaml:"version,omitempty"`
	VersionMajor string `json:"version_major,omitempty" yaml:"version_major,omitempty"`
	Architecture string `json:"architecture,omitempty" yaml:"architecture,omitempty"`
}

type VerificationState string

const (
	VerificationPending  VerificationState = "pending"
	VerificationVerified VerificationState = "verified"
	VerificationRejected VerificationState = "rejected"
)

func (s VerificationState) Valid() bool {
	return s == VerificationPending || s == VerificationVerified || s == VerificationRejected
}

type Verification struct {
	State        VerificationState `json:"state" yaml:"state"`
	Environments []string          `json:"environments,omitempty" yaml:"environments,omitempty"`
	VerifiedAt   string            `json:"verified_at,omitempty" yaml:"verified_at,omitempty"`
}

func (v Verification) Validate() error {
	if !v.State.Valid() {
		return fmt.Errorf("invalid verification state %q", v.State)
	}
	environments := make(map[string]struct{}, len(v.Environments))
	for index, environment := range v.Environments {
		if strings.TrimSpace(environment) == "" || strings.TrimSpace(environment) != environment || strings.ContainsAny(environment, "\x00\r\n") {
			return fmt.Errorf("verification environment %d is empty or non-canonical", index)
		}
		if _, duplicate := environments[environment]; duplicate {
			return fmt.Errorf("verification environment %q is duplicated", environment)
		}
		environments[environment] = struct{}{}
	}
	if v.State == VerificationVerified {
		if len(v.Environments) == 0 {
			return fmt.Errorf("verified state requires at least one environment")
		}
		if _, err := time.Parse(time.RFC3339, v.VerifiedAt); err != nil {
			return fmt.Errorf("verified state requires an RFC3339 verified_at: %w", err)
		}
		return nil
	}
	if v.VerifiedAt != "" {
		return fmt.Errorf("verified_at is only valid for verified state")
	}
	return nil
}

type RuleBinding struct {
	RuleID       string         `json:"rule_id" yaml:"rule_id"`
	Evaluator    *string        `json:"evaluator,omitempty" yaml:"evaluator,omitempty"`
	Parameters   map[string]any `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Applicable   *bool          `json:"applicable,omitempty" yaml:"applicable,omitempty"`
	Verification *Verification  `json:"verification,omitempty" yaml:"verification,omitempty"`
}

type BindingDefaults struct {
	Applicable   *bool         `json:"applicable,omitempty" yaml:"applicable,omitempty"`
	Verification *Verification `json:"verification,omitempty" yaml:"verification,omitempty"`
}

type BindingLayer struct {
	SchemaVersion        int              `json:"schema_version" yaml:"schema_version"`
	ID                   string           `json:"id" yaml:"id"`
	Priority             int              `json:"priority" yaml:"priority"`
	Selector             PlatformSelector `json:"selector" yaml:"selector"`
	PlatformVerification *Verification    `json:"platform_verification,omitempty" yaml:"platform_verification,omitempty"`
	Defaults             BindingDefaults  `json:"defaults,omitempty" yaml:"defaults,omitempty"`
	Bindings             []RuleBinding    `json:"bindings" yaml:"bindings"`
}

type ResolvedRule struct {
	RuleDefinition
	Applicable     bool         `json:"applicable"`
	Verification   Verification `json:"verification"`
	BindingSources []string     `json:"binding_sources"`
}

func SortedRules(rules []ResolvedRule) []ResolvedRule {
	result := append([]ResolvedRule(nil), rules...)
	sort.SliceStable(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
