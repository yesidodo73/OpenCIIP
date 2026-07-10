package model

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const RemediationSchemaVersion = 1

type RemediationRisk string

const (
	RiskSafe        RemediationRisk = "SAFE"
	RiskCaution     RemediationRisk = "CAUTION"
	RiskDangerous   RemediationRisk = "DANGEROUS"
	RiskUnsupported RemediationRisk = "UNSUPPORTED"
)

func (r RemediationRisk) Valid() bool {
	switch r {
	case RiskSafe, RiskCaution, RiskDangerous, RiskUnsupported:
		return true
	default:
		return false
	}
}

type RollbackScope string

const (
	RollbackItem RollbackScope = "item"
	RollbackRun  RollbackScope = "run"
)

func (s RollbackScope) Valid() bool {
	return s == RollbackItem || s == RollbackRun
}

type RunState string

const (
	RunPlanned                RunState = "planned"
	RunApproved               RunState = "approved"
	RunApplying               RunState = "applying"
	RunVerifying              RunState = "verifying"
	RunCompleted              RunState = "completed"
	RunRollingBack            RunState = "rolling_back"
	RunRolledBack             RunState = "rolled_back"
	RunCompletedWithRollbacks RunState = "completed_with_rollbacks"
	RunCanceling              RunState = "canceling"
	RunCanceled               RunState = "canceled"
	RunCancelFailed           RunState = "cancel_failed"
	RunFailed                 RunState = "failed"
	RunRollbackFailed         RunState = "rollback_failed"
	RunPartiallyRolledBack    RunState = "partially_rolled_back"
	RunRecoveryRequired       RunState = "recovery_required"
)

func (s RunState) Valid() bool {
	switch s {
	case RunPlanned,
		RunApproved,
		RunApplying,
		RunVerifying,
		RunCompleted,
		RunRollingBack,
		RunRolledBack,
		RunCompletedWithRollbacks,
		RunCanceling,
		RunCanceled,
		RunCancelFailed,
		RunFailed,
		RunRollbackFailed,
		RunPartiallyRolledBack,
		RunRecoveryRequired:
		return true
	default:
		return false
	}
}

func (s RunState) CanTransitionTo(next RunState) bool {
	if s == next {
		return s.Valid()
	}
	switch s {
	case RunPlanned:
		return next == RunApproved || next == RunCanceling || next == RunFailed
	case RunApproved:
		return next == RunApplying || next == RunCanceling || next == RunFailed
	case RunCanceling:
		return next == RunCanceled || next == RunCancelFailed
	case RunCancelFailed:
		return next == RunCanceling
	case RunApplying:
		return next == RunVerifying || next == RunRollingBack || next == RunFailed || next == RunRecoveryRequired
	case RunVerifying:
		return next == RunCompleted || next == RunRollingBack || next == RunFailed || next == RunRecoveryRequired
	case RunCompleted, RunCompletedWithRollbacks, RunFailed:
		return next == RunRollingBack
	case RunRollbackFailed, RunPartiallyRolledBack:
		return next == RunRollingBack || next == RunFailed
	case RunRecoveryRequired:
		return next == RunRollingBack || next == RunFailed
	case RunRollingBack:
		return next == RunRolledBack || next == RunCompletedWithRollbacks || next == RunFailed || next == RunRollbackFailed || next == RunPartiallyRolledBack || next == RunRecoveryRequired
	default:
		return false
	}
}

func (s RunState) Terminal() bool {
	switch s {
	case RunCompleted, RunRolledBack, RunCompletedWithRollbacks, RunCanceled, RunCancelFailed, RunFailed, RunRollbackFailed, RunPartiallyRolledBack, RunRecoveryRequired:
		return true
	default:
		return false
	}
}

func (s RunState) NeedsOperatorAction() bool {
	return s == RunCancelFailed || s == RunRollbackFailed || s == RunPartiallyRolledBack || s == RunRecoveryRequired
}

type ChangeSetState string

const (
	ChangePlanned             ChangeSetState = "planned"
	ChangePrepared            ChangeSetState = "prepared"
	ChangeApplying            ChangeSetState = "applying"
	ChangeApplied             ChangeSetState = "applied"
	ChangeVerifying           ChangeSetState = "verifying"
	ChangeVerified            ChangeSetState = "verified"
	ChangeApplyFailed         ChangeSetState = "apply_failed"
	ChangeRollingBack         ChangeSetState = "rolling_back"
	ChangeRolledBack          ChangeSetState = "rolled_back"
	ChangeRollbackBlocked     ChangeSetState = "rollback_blocked"
	ChangeRollbackFailed      ChangeSetState = "rollback_failed"
	ChangePartiallyRolledBack ChangeSetState = "partially_rolled_back"
	ChangeRecoveryRequired    ChangeSetState = "recovery_required"
)

func (s ChangeSetState) Valid() bool {
	switch s {
	case ChangePlanned,
		ChangePrepared,
		ChangeApplying,
		ChangeApplied,
		ChangeVerifying,
		ChangeVerified,
		ChangeApplyFailed,
		ChangeRollingBack,
		ChangeRolledBack,
		ChangeRollbackBlocked,
		ChangeRollbackFailed,
		ChangePartiallyRolledBack,
		ChangeRecoveryRequired:
		return true
	default:
		return false
	}
}

func (s ChangeSetState) CanTransitionTo(next ChangeSetState) bool {
	if s == next {
		return s.Valid()
	}
	switch s {
	case ChangePlanned:
		return next == ChangePrepared || next == ChangeApplyFailed
	case ChangePrepared:
		return next == ChangeApplying || next == ChangeApplyFailed
	case ChangeApplying:
		return next == ChangeApplied || next == ChangeApplyFailed || next == ChangeRollingBack || next == ChangeRecoveryRequired
	case ChangeApplied:
		return next == ChangeVerifying || next == ChangeRollingBack || next == ChangeRollbackBlocked || next == ChangeRecoveryRequired
	case ChangeVerifying:
		return next == ChangeVerified || next == ChangeRollingBack || next == ChangeRecoveryRequired
	case ChangeVerified:
		return next == ChangeRollingBack || next == ChangeRollbackBlocked || next == ChangeRecoveryRequired
	case ChangeApplyFailed, ChangeRollbackBlocked, ChangeRollbackFailed, ChangePartiallyRolledBack:
		return next == ChangeRollingBack || next == ChangeApplyFailed
	case ChangeRecoveryRequired:
		return next == ChangeRollingBack || next == ChangeApplyFailed
	case ChangeRolledBack:
		return next == ChangeRecoveryRequired
	case ChangeRollingBack:
		return next == ChangeApplyFailed || next == ChangeRolledBack || next == ChangeRollbackBlocked || next == ChangeRollbackFailed || next == ChangePartiallyRolledBack || next == ChangeRecoveryRequired
	default:
		return false
	}
}

func (s ChangeSetState) NeedsOperatorAction() bool {
	return s == ChangeRollbackBlocked || s == ChangeRollbackFailed || s == ChangePartiallyRolledBack || s == ChangeRecoveryRequired
}

type OperationState string

const (
	OperationPlanned               OperationState = "planned"
	OperationApplyIntentDurable    OperationState = "apply_intent_durable"
	OperationApplied               OperationState = "applied"
	OperationVerified              OperationState = "verified"
	OperationRollbackIntentDurable OperationState = "rollback_intent_durable"
	OperationRolledBack            OperationState = "rolled_back"
	OperationFailed                OperationState = "failed"
	OperationAmbiguous             OperationState = "ambiguous"
)

func (s OperationState) Valid() bool {
	switch s {
	case OperationPlanned,
		OperationApplyIntentDurable,
		OperationApplied,
		OperationVerified,
		OperationRollbackIntentDurable,
		OperationRolledBack,
		OperationFailed,
		OperationAmbiguous:
		return true
	default:
		return false
	}
}

func (s OperationState) CanTransitionTo(next OperationState) bool {
	if s == next {
		return s.Valid()
	}
	switch s {
	case OperationPlanned:
		return next == OperationApplyIntentDurable || next == OperationFailed
	case OperationApplyIntentDurable:
		return next == OperationApplied || next == OperationFailed || next == OperationAmbiguous || next == OperationRollbackIntentDurable
	case OperationApplied:
		return next == OperationVerified || next == OperationRollbackIntentDurable || next == OperationAmbiguous
	case OperationVerified, OperationFailed:
		return next == OperationRollbackIntentDurable
	case OperationAmbiguous:
		return next == OperationApplied || next == OperationRolledBack || next == OperationFailed
	case OperationRollbackIntentDurable:
		return next == OperationRolledBack || next == OperationFailed || next == OperationAmbiguous
	default:
		return false
	}
}

type ResourceKind string

const (
	ResourceFile    ResourceKind = "file"
	ResourceService ResourceKind = "service"
)

func (k ResourceKind) Valid() bool {
	return k == ResourceFile || k == ResourceService
}

type ResourceRef struct {
	Kind ResourceKind `json:"kind"`
	ID   string       `json:"id"`
}

func (r ResourceRef) Validate() error {
	if !r.Kind.Valid() {
		return fmt.Errorf("invalid resource kind %q", r.Kind)
	}
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("resource id is required")
	}
	if strings.IndexByte(r.ID, 0) >= 0 {
		return fmt.Errorf("resource id contains a NUL byte")
	}
	return nil
}

type CanonicalResource struct {
	Reference ResourceRef `json:"reference"`
	Key       string      `json:"key"`
	AliasKeys []string    `json:"alias_keys,omitempty"`
}

func (r CanonicalResource) Validate() error {
	if err := r.Reference.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(r.Key) == "" {
		return fmt.Errorf("canonical resource key is required")
	}
	if strings.IndexByte(r.Key, 0) >= 0 {
		return fmt.Errorf("canonical resource key contains a NUL byte")
	}
	seen := map[string]struct{}{r.Key: {}}
	for _, alias := range r.AliasKeys {
		if strings.TrimSpace(alias) == "" {
			return fmt.Errorf("canonical resource %s has an empty alias", r.Key)
		}
		if strings.IndexByte(alias, 0) >= 0 {
			return fmt.Errorf("canonical resource %s has an alias containing a NUL byte", r.Key)
		}
		if _, exists := seen[alias]; exists {
			return fmt.Errorf("canonical resource %s repeats key %s", r.Key, alias)
		}
		seen[alias] = struct{}{}
	}
	return nil
}

func (r CanonicalResource) Keys() []string {
	keys := make([]string, 0, len(r.AliasKeys)+1)
	keys = append(keys, r.Key)
	keys = append(keys, r.AliasKeys...)
	sort.Strings(keys)
	return keys
}

type FileSnapshot struct {
	Path           string    `json:"path"`
	Exists         bool      `json:"exists"`
	FileType       string    `json:"file_type"`
	Mode           uint32    `json:"mode"`
	UID            int       `json:"uid"`
	GID            int       `json:"gid"`
	Size           int64     `json:"size"`
	SHA256         string    `json:"sha256,omitempty"`
	LinkTarget     string    `json:"link_target,omitempty"`
	Device         uint64    `json:"device"`
	Inode          uint64    `json:"inode"`
	NLink          uint64    `json:"nlink"`
	ParentDevice   uint64    `json:"parent_device"`
	ParentInode    uint64    `json:"parent_inode"`
	XAttrDigest    string    `json:"xattr_digest,omitempty"`
	ACLDigest      string    `json:"acl_digest,omitempty"`
	SELinuxContext string    `json:"selinux_context,omitempty"`
	MetadataDigest string    `json:"metadata_digest,omitempty"`
	CapturedAt     time.Time `json:"captured_at"`
}

func (s FileSnapshot) Validate() error {
	if strings.TrimSpace(s.Path) == "" {
		return fmt.Errorf("file snapshot path is required")
	}
	if strings.IndexByte(s.Path, 0) >= 0 {
		return fmt.Errorf("file snapshot path contains a NUL byte")
	}
	if !s.Exists {
		return nil
	}
	if strings.TrimSpace(s.FileType) == "" {
		return fmt.Errorf("file snapshot %s has no file type", s.Path)
	}
	if s.UID < 0 || s.GID < 0 {
		return fmt.Errorf("file snapshot %s has invalid ownership", s.Path)
	}
	if s.Size < 0 {
		return fmt.Errorf("file snapshot %s has a negative size", s.Path)
	}
	if s.FileType == "regular" && !validSHA256(s.SHA256) {
		return fmt.Errorf("file snapshot %s has an invalid content digest", s.Path)
	}
	if s.CapturedAt.IsZero() {
		return fmt.Errorf("file snapshot %s has no capture time", s.Path)
	}
	for name, digest := range map[string]string{
		"xattr":    s.XAttrDigest,
		"acl":      s.ACLDigest,
		"metadata": s.MetadataDigest,
	} {
		if digest != "" && !validSHA256(digest) {
			return fmt.Errorf("file snapshot %s has an invalid %s digest", s.Path, name)
		}
	}
	return nil
}

type BackupArtifact struct {
	ID             string `json:"id"`
	ContentPath    string `json:"content_path,omitempty"`
	MetadataPath   string `json:"metadata_path"`
	ContentSize    int64  `json:"content_size"`
	ContentSHA256  string `json:"content_sha256,omitempty"`
	MetadataSHA256 string `json:"metadata_sha256"`
	Durable        bool   `json:"durable"`
}

func (a BackupArtifact) Validate() error {
	if strings.TrimSpace(a.ID) == "" {
		return fmt.Errorf("backup artifact id is required")
	}
	if strings.TrimSpace(a.MetadataPath) == "" || !validSHA256(a.MetadataSHA256) {
		return fmt.Errorf("backup artifact %s has invalid metadata", a.ID)
	}
	for name, artifactPath := range map[string]string{"content": a.ContentPath, "metadata": a.MetadataPath} {
		if artifactPath == "" && name == "content" {
			continue
		}
		if filepath.IsAbs(artifactPath) || strings.IndexByte(artifactPath, 0) >= 0 || containsParentReference(artifactPath) {
			return fmt.Errorf("backup artifact %s has an unsafe %s path", a.ID, name)
		}
	}
	if a.ContentPath != "" {
		if a.ContentSize < 0 || !validSHA256(a.ContentSHA256) {
			return fmt.Errorf("backup artifact %s has invalid content metadata", a.ID)
		}
	}
	if !a.Durable {
		return fmt.Errorf("backup artifact %s is not durable", a.ID)
	}
	return nil
}

type ServiceSnapshot struct {
	Manager          string    `json:"manager"`
	Name             string    `json:"name"`
	LoadState        string    `json:"load_state"`
	ActiveState      string    `json:"active_state"`
	SubState         string    `json:"sub_state"`
	UnitFileState    string    `json:"unit_file_state"`
	Masked           bool      `json:"masked"`
	NeedDaemonReload bool      `json:"need_daemon_reload"`
	ManagerBootID    string    `json:"manager_boot_id"`
	CapturedAt       time.Time `json:"captured_at"`
}

func (s ServiceSnapshot) Validate() error {
	if strings.TrimSpace(s.Manager) == "" || strings.TrimSpace(s.Name) == "" || s.CapturedAt.IsZero() {
		return fmt.Errorf("service snapshot manager and name are required")
	}
	return nil
}

type ResourceSnapshot struct {
	Reference   CanonicalResource `json:"reference"`
	Fingerprint string            `json:"fingerprint"`
	File        *FileSnapshot     `json:"file,omitempty"`
	Service     *ServiceSnapshot  `json:"service,omitempty"`
}

func (s ResourceSnapshot) IsZero() bool {
	return s.Reference.Key == "" && s.Fingerprint == "" && s.File == nil && s.Service == nil
}

func (s ResourceSnapshot) Validate() error {
	if err := s.Reference.Validate(); err != nil {
		return err
	}
	if !validSHA256(s.Fingerprint) {
		return fmt.Errorf("resource %s has an invalid fingerprint", s.Reference.Key)
	}
	present := 0
	if s.File != nil {
		present++
		if s.Reference.Reference.Kind != ResourceFile {
			return fmt.Errorf("resource %s contains a file snapshot for kind %s", s.Reference.Key, s.Reference.Reference.Kind)
		}
		if err := s.File.Validate(); err != nil {
			return err
		}
		if s.File.Path != s.Reference.Reference.ID {
			return fmt.Errorf("resource %s file snapshot path does not match its resource id", s.Reference.Key)
		}
	}
	if s.Service != nil {
		present++
		if s.Reference.Reference.Kind != ResourceService {
			return fmt.Errorf("resource %s contains a service snapshot for kind %s", s.Reference.Key, s.Reference.Reference.Kind)
		}
		if err := s.Service.Validate(); err != nil {
			return err
		}
	}
	if present != 1 {
		return fmt.Errorf("resource %s must contain exactly one snapshot", s.Reference.Key)
	}
	return nil
}

type Approval struct {
	Source     string    `json:"source"`
	TemplateID string    `json:"template_id,omitempty"`
	PlanDigest string    `json:"plan_digest"`
	ApprovedAt time.Time `json:"approved_at"`
}

func (a Approval) Validate(planDigest string) error {
	if strings.TrimSpace(a.Source) == "" {
		return fmt.Errorf("approval source is required")
	}
	if !validSHA256(a.PlanDigest) || a.PlanDigest != planDigest {
		return fmt.Errorf("approval plan digest does not match the journal")
	}
	if a.ApprovedAt.IsZero() {
		return fmt.Errorf("approval time is required")
	}
	return nil
}

type OperationKind string

const (
	OperationFileCreate     OperationKind = "file_create"
	OperationFileRemove     OperationKind = "file_remove"
	OperationFileMetadata   OperationKind = "file_metadata"
	OperationServiceEnable  OperationKind = "service_enable"
	OperationServiceDisable OperationKind = "service_disable"
	OperationServiceMask    OperationKind = "service_mask"
	OperationServiceUnmask  OperationKind = "service_unmask"
	OperationServiceStart   OperationKind = "service_start"
	OperationServiceStop    OperationKind = "service_stop"
	OperationServiceReload  OperationKind = "service_reload"
	OperationServiceRestart OperationKind = "service_restart"
	OperationDaemonReload   OperationKind = "daemon_reload"
)

func (k OperationKind) Valid() bool {
	switch k {
	case OperationFileCreate,
		OperationFileRemove,
		OperationFileMetadata,
		OperationServiceEnable,
		OperationServiceDisable,
		OperationServiceMask,
		OperationServiceUnmask,
		OperationServiceStart,
		OperationServiceStop,
		OperationServiceReload,
		OperationServiceRestart,
		OperationDaemonReload:
		return true
	default:
		return false
	}
}

type RecoveryMode string

const (
	RecoveryStateInferable     RecoveryMode = "state_inferable"
	RecoveryRollbackReplaySafe RecoveryMode = "rollback_replay_safe"
	RecoveryManual             RecoveryMode = "manual"
)

func (m RecoveryMode) Valid() bool {
	return m == RecoveryStateInferable || m == RecoveryRollbackReplaySafe || m == RecoveryManual
}

type OperationRecord struct {
	ID               string            `json:"id"`
	Sequence         int               `json:"sequence"`
	RollbackSequence int               `json:"rollback_sequence"`
	Kind             OperationKind     `json:"kind"`
	RecoveryMode     RecoveryMode      `json:"recovery_mode"`
	State            OperationState    `json:"state"`
	Resource         CanonicalResource `json:"resource"`
	ExpectedBefore   ResourceSnapshot  `json:"expected_before"`
	Before           ResourceSnapshot  `json:"before"`
	Desired          ResourceSnapshot  `json:"desired"`
	ObservedAfter    *ResourceSnapshot `json:"observed_after,omitempty"`
	ObservedRollback *ResourceSnapshot `json:"observed_rollback,omitempty"`
	Backup           *BackupArtifact   `json:"backup,omitempty"`
	ApplyIntentAt    *time.Time        `json:"apply_intent_at,omitempty"`
	AppliedAt        *time.Time        `json:"applied_at,omitempty"`
	RollbackIntentAt *time.Time        `json:"rollback_intent_at,omitempty"`
	RolledBackAt     *time.Time        `json:"rolled_back_at,omitempty"`
	Error            *JournalError     `json:"error,omitempty"`
}

// ProvesNoEffect reports whether a failed forward operation has durable,
// exact evidence that the target remained in its prepared before state.
func (o OperationRecord) ProvesNoEffect() bool {
	if o.State != OperationFailed || o.ApplyIntentAt == nil || o.ApplyIntentAt.IsZero() ||
		o.AppliedAt != nil || o.RollbackIntentAt != nil ||
		o.ObservedAfter == nil || o.ObservedRollback != nil || o.RolledBackAt != nil ||
		o.Backup == nil || o.Error == nil || o.Before.IsZero() || !snapshotHasCaptureTime(*o.ObservedAfter) {
		return false
	}
	return exactResourceSnapshot(o.Before, *o.ObservedAfter)
}

type RemediationRecipeIdentity struct {
	ID               string           `json:"id"`
	Selector         PlatformSelector `json:"selector"`
	DefinitionSHA256 string           `json:"definition_sha256"`
}

func (i RemediationRecipeIdentity) Validate() error {
	if !recipeIdentifierPattern.MatchString(i.ID) {
		return fmt.Errorf("remediation recipe identity %q is invalid", i.ID)
	}
	if err := validateExactRemediationSelector(i.Selector); err != nil {
		return fmt.Errorf("remediation recipe %s: %w", i.ID, err)
	}
	if !validSHA256(i.DefinitionSHA256) {
		return fmt.Errorf("remediation recipe %s has an invalid definition digest", i.ID)
	}
	return nil
}

type RemediationRuleIdentity struct {
	ID             string       `json:"id"`
	Title          string       `json:"title"`
	Category       Category     `json:"category"`
	Severity       Severity     `json:"severity"`
	Evaluator      string       `json:"evaluator"`
	Verification   Verification `json:"verification"`
	BindingSources []string     `json:"binding_sources"`
	Reference      Reference    `json:"reference"`
}

func (i RemediationRuleIdentity) Validate() error {
	if !bindingRuleIDPatternForRecipe.MatchString(i.ID) || strings.TrimSpace(i.Title) == "" || strings.TrimSpace(i.Evaluator) == "" {
		return fmt.Errorf("remediation rule identity is incomplete")
	}
	if !i.Category.Valid() || !i.Severity.Valid() || i.Verification.State != VerificationVerified {
		return fmt.Errorf("remediation rule %s is not verified or has invalid metadata", i.ID)
	}
	if err := i.Verification.Validate(); err != nil {
		return fmt.Errorf("remediation rule %s has invalid verification provenance: %w", i.ID, err)
	}
	if len(i.BindingSources) == 0 {
		return fmt.Errorf("remediation rule %s has no binding or verification provenance", i.ID)
	}
	seen := make(map[string]struct{}, len(i.BindingSources))
	for _, source := range i.BindingSources {
		if strings.TrimSpace(source) == "" || source != strings.TrimSpace(source) {
			return fmt.Errorf("remediation rule %s has a non-canonical binding source", i.ID)
		}
		if _, duplicate := seen[source]; duplicate {
			return fmt.Errorf("remediation rule %s repeats binding source %s", i.ID, source)
		}
		seen[source] = struct{}{}
	}
	if strings.TrimSpace(i.Reference.Guide) == "" || i.Reference.Item != i.ID {
		return fmt.Errorf("remediation rule %s has an invalid reference identity", i.ID)
	}
	for _, page := range i.Reference.Pages {
		if page < 1 {
			return fmt.Errorf("remediation rule %s has an invalid reference page", i.ID)
		}
	}
	return nil
}

func (o OperationRecord) Validate() error {
	if strings.TrimSpace(o.ID) == "" {
		return fmt.Errorf("operation id is required")
	}
	if o.Sequence < 1 || o.RollbackSequence < 1 {
		return fmt.Errorf("operation %s has an invalid sequence", o.ID)
	}
	if !o.Kind.Valid() || !o.RecoveryMode.Valid() || !o.State.Valid() {
		return fmt.Errorf("operation %s has invalid kind, recovery mode, or state", o.ID)
	}
	if err := o.Resource.Validate(); err != nil {
		return fmt.Errorf("operation %s: %w", o.ID, err)
	}
	if err := o.ExpectedBefore.Validate(); err != nil {
		return fmt.Errorf("operation %s expected before state: %w", o.ID, err)
	}
	if !sameCanonicalResource(o.ExpectedBefore.Reference, o.Resource) {
		return fmt.Errorf("operation %s expected before resource does not match its target", o.ID)
	}
	if err := o.Desired.Validate(); err != nil {
		return fmt.Errorf("operation %s desired state: %w", o.ID, err)
	}
	if !sameCanonicalResource(o.Desired.Reference, o.Resource) {
		return fmt.Errorf("operation %s desired resource does not match its target", o.ID)
	}
	if o.RecoveryMode == RecoveryStateInferable && o.ExpectedBefore.Fingerprint == o.Desired.Fingerprint {
		return fmt.Errorf("operation %s cannot infer recovery because expected and desired states are equivalent", o.ID)
	}
	if o.Kind == OperationFileMetadata {
		if err := validateFileMetadataOperation(o.ExpectedBefore, o.Desired); err != nil {
			return fmt.Errorf("operation %s: %w", o.ID, err)
		}
	}
	if !o.Before.IsZero() {
		if err := o.Before.Validate(); err != nil {
			return fmt.Errorf("operation %s before state: %w", o.ID, err)
		}
		if !sameCanonicalResource(o.Before.Reference, o.Resource) {
			return fmt.Errorf("operation %s before resource does not match its target", o.ID)
		}
		if !exactResourceSnapshot(o.ExpectedBefore, o.Before) {
			return fmt.Errorf("operation %s runtime before state differs from its approved precondition", o.ID)
		}
	}
	if o.State != OperationPlanned && o.Before.IsZero() {
		return fmt.Errorf("operation %s has no durable before state", o.ID)
	}
	if o.State != OperationPlanned && (o.ApplyIntentAt == nil || o.ApplyIntentAt.IsZero() || o.Backup == nil) {
		return fmt.Errorf("operation %s has no durable apply intent or backup", o.ID)
	}
	if o.State == OperationApplyIntentDurable && (o.AppliedAt != nil || o.ObservedAfter != nil || o.RollbackIntentAt != nil || o.ObservedRollback != nil || o.RolledBackAt != nil) {
		return fmt.Errorf("operation %s apply intent contains completion, observation, or rollback artifacts", o.ID)
	}
	if (o.State == OperationApplied || o.State == OperationVerified) && (o.ObservedAfter == nil || o.AppliedAt == nil || o.AppliedAt.IsZero()) {
		return fmt.Errorf("operation %s has no durable observed after state or apply completion time", o.ID)
	}
	if err := validateOperationMarkers(o); err != nil {
		return fmt.Errorf("operation %s: %w", o.ID, err)
	}
	if o.ObservedAfter != nil {
		if err := o.ObservedAfter.Validate(); err != nil {
			return fmt.Errorf("operation %s observed state: %w", o.ID, err)
		}
		if !sameCanonicalResource(o.ObservedAfter.Reference, o.Resource) {
			return fmt.Errorf("operation %s observed resource does not match its target", o.ID)
		}
		if o.State == OperationVerified && !exactResourceSnapshot(o.Desired, *o.ObservedAfter) {
			return fmt.Errorf("operation %s verified state does not exactly match its desired state", o.ID)
		}
		if o.State == OperationApplied {
			before := o.Before
			if before.IsZero() {
				before = o.ExpectedBefore
			}
			if sameResourceSnapshotSemantics(before, *o.ObservedAfter) {
				return fmt.Errorf("operation %s applied state does not exactly match its desired state or preserve an active partial transition", o.ID)
			}
			if o.Kind != OperationFileMetadata && !exactResourceSnapshot(o.Desired, *o.ObservedAfter) {
				return fmt.Errorf("operation %s applied state does not exactly match its desired state", o.ID)
			}
		}
		if o.Kind == OperationFileMetadata {
			before := o.Before
			if before.IsZero() {
				before = o.ExpectedBefore
			}
			if !fileMetadataTransitionCandidate(before, o.Desired, *o.ObservedAfter) {
				return fmt.Errorf("operation %s observed state is not a metadata transition on the original inode", o.ID)
			}
		}
		if o.State == OperationFailed && o.RollbackIntentAt == nil && !o.ProvesNoEffect() {
			return fmt.Errorf("operation %s failed without exact durable no-effect evidence", o.ID)
		}
	}
	if o.State == OperationRolledBack && (o.RollbackIntentAt == nil || o.RollbackIntentAt.IsZero() || o.ObservedRollback == nil || o.RolledBackAt == nil || o.RolledBackAt.IsZero()) {
		return fmt.Errorf("operation %s has no durable rollback intent, observation, or completion time", o.ID)
	}
	if o.ObservedRollback != nil {
		if err := o.ObservedRollback.Validate(); err != nil {
			return fmt.Errorf("operation %s observed rollback state: %w", o.ID, err)
		}
		if !sameCanonicalResource(o.ObservedRollback.Reference, o.Resource) {
			return fmt.Errorf("operation %s observed rollback resource does not match its target", o.ID)
		}
		if !o.Before.IsZero() && !exactResourceSnapshot(o.Before, *o.ObservedRollback) {
			return fmt.Errorf("operation %s observed rollback state differs from its durable before state", o.ID)
		}
	}
	if o.Backup != nil {
		if err := o.Backup.Validate(); err != nil {
			return fmt.Errorf("operation %s: %w", o.ID, err)
		}
	}
	if o.Error != nil {
		if err := o.Error.Validate(); err != nil {
			return fmt.Errorf("operation %s: %w", o.ID, err)
		}
	}
	return nil
}

func validateOperationMarkers(operation OperationRecord) error {
	markers := []struct {
		name  string
		value *time.Time
	}{
		{name: "apply intent", value: operation.ApplyIntentAt},
		{name: "apply completion", value: operation.AppliedAt},
		{name: "rollback intent", value: operation.RollbackIntentAt},
		{name: "rollback completion", value: operation.RolledBackAt},
	}
	for _, marker := range markers {
		if marker.value != nil && marker.value.IsZero() {
			return fmt.Errorf("%s time is zero", marker.name)
		}
	}
	if operation.AppliedAt != nil {
		if operation.ApplyIntentAt == nil || operation.ObservedAfter == nil {
			return fmt.Errorf("apply completion requires its durable intent and observation")
		}
		if operation.AppliedAt.Before(*operation.ApplyIntentAt) {
			return fmt.Errorf("apply completion precedes its durable intent")
		}
	}
	if operation.RollbackIntentAt != nil {
		if operation.ApplyIntentAt == nil {
			return fmt.Errorf("rollback intent requires a durable apply intent")
		}
		if operation.RollbackIntentAt.Before(*operation.ApplyIntentAt) {
			return fmt.Errorf("rollback intent precedes the durable apply intent")
		}
	}
	if operation.ObservedRollback != nil || operation.RolledBackAt != nil {
		if operation.RollbackIntentAt == nil {
			return fmt.Errorf("rollback observation or completion requires a durable rollback intent")
		}
	}
	if operation.RolledBackAt != nil {
		if operation.ObservedRollback == nil {
			return fmt.Errorf("rollback completion requires an observation")
		}
		if operation.RolledBackAt.Before(*operation.RollbackIntentAt) {
			return fmt.Errorf("rollback completion precedes its durable intent")
		}
	}
	return nil
}

func validateFileMetadataOperation(before, desired ResourceSnapshot) error {
	if before.File == nil || desired.File == nil || !before.File.Exists || !desired.File.Exists || before.File.FileType != "regular" || desired.File.FileType != "regular" {
		return fmt.Errorf("file metadata operation must target an existing regular file")
	}
	if before.File.NLink != 1 || desired.File.NLink != 1 {
		return fmt.Errorf("file metadata operation must target a single-link file")
	}
	left, right := before.File, desired.File
	if left.Path != right.Path || left.Exists != right.Exists || left.FileType != right.FileType ||
		left.Size != right.Size || left.SHA256 != right.SHA256 || left.LinkTarget != right.LinkTarget ||
		left.Device != right.Device || left.Inode != right.Inode || left.NLink != right.NLink ||
		left.ParentDevice != right.ParentDevice || left.ParentInode != right.ParentInode ||
		left.XAttrDigest != right.XAttrDigest || left.ACLDigest != right.ACLDigest || left.SELinuxContext != right.SELinuxContext {
		return fmt.Errorf("file metadata operation must preserve inode, parent, content, links, xattrs, ACL, and SELinux context")
	}
	if right.Mode&^left.Mode != 0 {
		return fmt.Errorf("file metadata operation must not add permission or special-mode bits")
	}
	return nil
}

func fileMetadataTransitionCandidate(before, desired, observed ResourceSnapshot) bool {
	if validateFileMetadataOperation(before, desired) != nil || observed.File == nil || observed.Reference.Key != before.Reference.Key {
		return false
	}
	left, current := before.File, observed.File
	if left.Path != current.Path || left.Exists != current.Exists || left.FileType != current.FileType ||
		left.Size != current.Size || left.SHA256 != current.SHA256 || left.LinkTarget != current.LinkTarget ||
		left.Device != current.Device || left.Inode != current.Inode || left.NLink != current.NLink ||
		left.ParentDevice != current.ParentDevice || left.ParentInode != current.ParentInode ||
		left.XAttrDigest != current.XAttrDigest || left.ACLDigest != current.ACLDigest || left.SELinuxContext != current.SELinuxContext {
		return false
	}
	ownershipBefore := current.UID == before.File.UID && current.GID == before.File.GID
	ownershipDesired := current.UID == desired.File.UID && current.GID == desired.File.GID
	return (ownershipBefore || ownershipDesired) &&
		(current.Mode == before.File.Mode || current.Mode == desired.File.Mode)
}

func sameFileIdentity(left, right ResourceSnapshot) bool {
	return left.File != nil && right.File != nil && left.Reference.Key == right.Reference.Key &&
		left.File.Device == right.File.Device && left.File.Inode == right.File.Inode &&
		left.File.ParentDevice == right.File.ParentDevice && left.File.ParentInode == right.File.ParentInode
}

func exactResourceSnapshot(left, right ResourceSnapshot) bool {
	return left.Fingerprint == right.Fingerprint && sameResourceSnapshotSemantics(left, right)
}

func sameResourceSnapshotSemantics(left, right ResourceSnapshot) bool {
	if !sameCanonicalResource(left.Reference, right.Reference) {
		return false
	}
	switch {
	case left.File != nil && right.File != nil:
		leftFile := *left.File
		rightFile := *right.File
		leftFile.CapturedAt = time.Time{}
		rightFile.CapturedAt = time.Time{}
		return leftFile == rightFile
	case left.Service != nil && right.Service != nil:
		leftService := *left.Service
		rightService := *right.Service
		leftService.CapturedAt = time.Time{}
		rightService.CapturedAt = time.Time{}
		return leftService == rightService
	default:
		return false
	}
}

func sameCanonicalResource(left, right CanonicalResource) bool {
	if left.Reference != right.Reference || left.Key != right.Key || len(left.AliasKeys) != len(right.AliasKeys) {
		return false
	}
	for index := range left.AliasKeys {
		if left.AliasKeys[index] != right.AliasKeys[index] {
			return false
		}
	}
	return true
}

func snapshotHasCaptureTime(snapshot ResourceSnapshot) bool {
	switch {
	case snapshot.File != nil:
		return !snapshot.File.CapturedAt.IsZero()
	case snapshot.Service != nil:
		return !snapshot.Service.CapturedAt.IsZero()
	default:
		return false
	}
}

type ChangeSet struct {
	ID             string                    `json:"id"`
	RuleID         string                    `json:"rule_id"`
	RuleIdentity   RemediationRuleIdentity   `json:"rule_identity"`
	RecipeIdentity RemediationRecipeIdentity `json:"recipe_identity"`
	Sequence       int                       `json:"sequence"`
	Risk           RemediationRisk           `json:"risk"`
	State          ChangeSetState            `json:"state"`
	RollbackGroup  string                    `json:"rollback_group,omitempty"`
	DependsOn      []string                  `json:"depends_on,omitempty"`
	Resources      []CanonicalResource       `json:"resources"`
	Before         []ResourceSnapshot        `json:"before,omitempty"`
	After          []ResourceSnapshot        `json:"after,omitempty"`
	Operations     []OperationRecord         `json:"operations"`
	DryRun         string                    `json:"dry_run"`
	ExpectedImpact string                    `json:"expected_impact"`
	Approval       *Approval                 `json:"approval,omitempty"`
	PreparedAt     *time.Time                `json:"prepared_at,omitempty"`
	AppliedAt      *time.Time                `json:"applied_at,omitempty"`
	VerifiedAt     *time.Time                `json:"verified_at,omitempty"`
	RolledBackAt   *time.Time                `json:"rolled_back_at,omitempty"`
	Error          *JournalError             `json:"error,omitempty"`
}

func (c ChangeSet) Validate(planDigest string) error {
	if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.RuleID) == "" {
		return fmt.Errorf("change set id and rule id are required")
	}
	if err := c.RuleIdentity.Validate(); err != nil {
		return fmt.Errorf("change set %s: %w", c.ID, err)
	}
	if c.RuleIdentity.ID != c.RuleID {
		return fmt.Errorf("change set %s rule identity does not match rule id", c.ID)
	}
	if err := c.RecipeIdentity.Validate(); err != nil {
		return fmt.Errorf("change set %s: %w", c.ID, err)
	}
	if c.Sequence < 1 || !c.Risk.Valid() || !c.State.Valid() {
		return fmt.Errorf("change set %s has invalid sequence, risk, or state", c.ID)
	}
	if c.Risk == RiskUnsupported {
		return fmt.Errorf("change set %s cannot include unsupported remediation", c.ID)
	}
	if len(c.Resources) == 0 || len(c.Operations) == 0 {
		return fmt.Errorf("change set %s has no resources or operations", c.ID)
	}
	if strings.TrimSpace(c.DryRun) == "" || strings.TrimSpace(c.ExpectedImpact) == "" {
		return fmt.Errorf("change set %s is missing dry-run or impact information", c.ID)
	}
	resourcesByKey := make(map[string]CanonicalResource, len(c.Resources))
	for _, resource := range c.Resources {
		if err := resource.Validate(); err != nil {
			return fmt.Errorf("change set %s: %w", c.ID, err)
		}
		if _, exists := resourcesByKey[resource.Key]; exists {
			return fmt.Errorf("change set %s repeats resource %s", c.ID, resource.Key)
		}
		resourcesByKey[resource.Key] = resource
	}
	beforeKeys := make(map[string]struct{}, len(c.Before))
	for _, snapshot := range c.Before {
		if err := snapshot.Validate(); err != nil {
			return fmt.Errorf("change set %s before state: %w", c.ID, err)
		}
		resource, exists := resourcesByKey[snapshot.Reference.Key]
		if !exists {
			return fmt.Errorf("change set %s has before state for unknown resource %s", c.ID, snapshot.Reference.Key)
		}
		if !sameCanonicalResource(snapshot.Reference, resource) {
			return fmt.Errorf("change set %s before state resource differs from its canonical resource", c.ID)
		}
		if _, exists := beforeKeys[snapshot.Reference.Key]; exists {
			return fmt.Errorf("change set %s repeats before state for %s", c.ID, snapshot.Reference.Key)
		}
		beforeKeys[snapshot.Reference.Key] = struct{}{}
	}
	if c.State != ChangePlanned && c.State != ChangeApplyFailed && len(beforeKeys) != len(resourcesByKey) {
		return fmt.Errorf("change set %s does not have a complete before state", c.ID)
	}
	afterKeys := make(map[string]struct{}, len(c.After))
	afterByResource := make(map[string]ResourceSnapshot, len(c.After))
	for _, snapshot := range c.After {
		if err := snapshot.Validate(); err != nil {
			return fmt.Errorf("change set %s after state: %w", c.ID, err)
		}
		resource, exists := resourcesByKey[snapshot.Reference.Key]
		if !exists {
			return fmt.Errorf("change set %s has after state for unknown resource %s", c.ID, snapshot.Reference.Key)
		}
		if !sameCanonicalResource(snapshot.Reference, resource) {
			return fmt.Errorf("change set %s after state resource differs from its canonical resource", c.ID)
		}
		if _, exists := afterKeys[snapshot.Reference.Key]; exists {
			return fmt.Errorf("change set %s repeats after state for %s", c.ID, snapshot.Reference.Key)
		}
		afterKeys[snapshot.Reference.Key] = struct{}{}
		afterByResource[snapshot.Reference.Key] = snapshot
	}
	operationIDs := make(map[string]struct{}, len(c.Operations))
	applySequences := make(map[int]struct{}, len(c.Operations))
	rollbackSequences := make(map[int]struct{}, len(c.Operations))
	lastApplySequence := 0
	hasRolledBackOperation := false
	finalDesiredByResource := make(map[string]ResourceSnapshot, len(c.Resources))
	finalObservedByResource := make(map[string]ResourceSnapshot, len(c.Resources))
	for _, operation := range c.Operations {
		if err := operation.Validate(); err != nil {
			return fmt.Errorf("change set %s: %w", c.ID, err)
		}
		if c.State != ChangePlanned && c.State != ChangeApplyFailed && operation.Before.IsZero() {
			return fmt.Errorf("change set %s operation %s has no prepared before state", c.ID, operation.ID)
		}
		resource, exists := resourcesByKey[operation.Resource.Key]
		if !exists {
			return fmt.Errorf("change set %s operation %s uses unknown resource %s", c.ID, operation.ID, operation.Resource.Key)
		}
		if !sameCanonicalResource(operation.Resource, resource) {
			return fmt.Errorf("change set %s operation %s resource differs from its canonical resource", c.ID, operation.ID)
		}
		if _, exists := operationIDs[operation.ID]; exists {
			return fmt.Errorf("change set %s repeats operation %s", c.ID, operation.ID)
		}
		if _, exists := applySequences[operation.Sequence]; exists {
			return fmt.Errorf("change set %s repeats apply sequence %d", c.ID, operation.Sequence)
		}
		if _, exists := rollbackSequences[operation.RollbackSequence]; exists {
			return fmt.Errorf("change set %s repeats rollback sequence %d", c.ID, operation.RollbackSequence)
		}
		if operation.Sequence <= lastApplySequence {
			return fmt.Errorf("change set %s operations are not in apply sequence order", c.ID)
		}
		lastApplySequence = operation.Sequence
		finalDesiredByResource[operation.Resource.Key] = operation.Desired
		if operation.ObservedAfter != nil {
			finalObservedByResource[operation.Resource.Key] = *operation.ObservedAfter
		}
		switch c.State {
		case ChangeApplied, ChangeVerifying:
			if operation.State != OperationApplied {
				return fmt.Errorf("change set %s in state %s contains operation %s in state %s", c.ID, c.State, operation.ID, operation.State)
			}
		case ChangeVerified:
			if operation.State != OperationVerified {
				return fmt.Errorf("verified change set %s contains non-verified operation %s in state %s", c.ID, operation.ID, operation.State)
			}
		}
		if c.State == ChangeRolledBack {
			switch {
			case operation.State == OperationRolledBack:
				hasRolledBackOperation = true
			case operation.State == OperationPlanned, operation.ProvesNoEffect():
			default:
				return fmt.Errorf("rolled-back change set %s contains operation %s in state %s without no-effect evidence", c.ID, operation.ID, operation.State)
			}
		}
		if c.State == ChangeApplyFailed && operation.State != OperationPlanned && !operation.ProvesNoEffect() {
			return fmt.Errorf("apply-failed change set %s contains operation %s without exact no-effect evidence", c.ID, operation.ID)
		}
		operationIDs[operation.ID] = struct{}{}
		applySequences[operation.Sequence] = struct{}{}
		rollbackSequences[operation.RollbackSequence] = struct{}{}
	}
	if c.State == ChangeRolledBack && (!hasRolledBackOperation || c.RolledBackAt == nil || c.RolledBackAt.IsZero()) {
		return fmt.Errorf("rolled-back change set %s has no rolled-back operation or completion time", c.ID)
	}
	if c.Approval != nil {
		if err := c.Approval.Validate(planDigest); err != nil {
			return fmt.Errorf("change set %s: %w", c.ID, err)
		}
	}
	if c.State == ChangeApplied || c.State == ChangeVerifying || c.State == ChangeVerified {
		if c.PreparedAt == nil || c.PreparedAt.IsZero() || c.AppliedAt == nil || c.AppliedAt.IsZero() {
			return fmt.Errorf("change set %s in state %s has no preparation or apply completion time", c.ID, c.State)
		}
		if len(afterKeys) != len(resourcesByKey) || len(finalDesiredByResource) != len(resourcesByKey) {
			return fmt.Errorf("change set %s in state %s does not have a complete after state", c.ID, c.State)
		}
		for resourceKey, desired := range finalDesiredByResource {
			after, afterExists := afterByResource[resourceKey]
			observed, observedExists := finalObservedByResource[resourceKey]
			if !afterExists || !observedExists {
				return fmt.Errorf("change set %s in state %s does not have a complete after state for %s", c.ID, c.State, resourceKey)
			}
			if c.State == ChangeVerifying || c.State == ChangeVerified {
				if !exactResourceSnapshot(desired, observed) || !exactResourceSnapshot(desired, after) {
					return fmt.Errorf("change set %s in state %s does not match the final desired and observed state for %s", c.ID, c.State, resourceKey)
				}
			} else if !exactResourceSnapshot(observed, after) {
				return fmt.Errorf("change set %s after state for %s does not match the final observed state", c.ID, resourceKey)
			}
		}
	}
	if c.State == ChangeVerified && (c.VerifiedAt == nil || c.VerifiedAt.IsZero()) {
		return fmt.Errorf("verified change set %s has no verification completion time", c.ID)
	}
	if c.Error != nil {
		if err := c.Error.Validate(); err != nil {
			return fmt.Errorf("change set %s: %w", c.ID, err)
		}
	}
	return nil
}

type ConflictReason string

const (
	ConflictSharedResource     ConflictReason = "shared_resource"
	ConflictExplicitDependency ConflictReason = "explicit_dependency"
	ConflictRollbackGroup      ConflictReason = "rollback_group"
)

func (r ConflictReason) Valid() bool {
	return r == ConflictSharedResource || r == ConflictExplicitDependency || r == ConflictRollbackGroup
}

type ConflictEdge struct {
	From      string         `json:"from"`
	To        string         `json:"to"`
	Reason    ConflictReason `json:"reason"`
	Resources []string       `json:"resources,omitempty"`
}

type RollbackGroupEntry struct {
	ID         string   `json:"id"`
	ChangeSets []string `json:"change_sets"`
}

type ConflictGraph struct {
	Nodes  []string             `json:"nodes"`
	Edges  []ConflictEdge       `json:"edges"`
	Groups []RollbackGroupEntry `json:"groups,omitempty"`
}

func (g ConflictGraph) Validate() error {
	nodes := make(map[string]struct{}, len(g.Nodes))
	for _, node := range g.Nodes {
		if strings.TrimSpace(node) == "" {
			return fmt.Errorf("conflict graph has an empty node")
		}
		if _, exists := nodes[node]; exists {
			return fmt.Errorf("conflict graph repeats node %s", node)
		}
		nodes[node] = struct{}{}
	}
	edges := make(map[string]struct{}, len(g.Edges))
	for _, edge := range g.Edges {
		if !edge.Reason.Valid() || edge.From == edge.To {
			return fmt.Errorf("conflict graph has an invalid edge %s -> %s", edge.From, edge.To)
		}
		if _, exists := nodes[edge.From]; !exists {
			return fmt.Errorf("conflict edge source %s is unknown", edge.From)
		}
		if _, exists := nodes[edge.To]; !exists {
			return fmt.Errorf("conflict edge target %s is unknown", edge.To)
		}
		seenResources := make(map[string]struct{}, len(edge.Resources))
		for _, resource := range edge.Resources {
			if strings.TrimSpace(resource) == "" {
				return fmt.Errorf("conflict edge %s -> %s has an empty resource", edge.From, edge.To)
			}
			if _, exists := seenResources[resource]; exists {
				return fmt.Errorf("conflict edge %s -> %s repeats resource %s", edge.From, edge.To, resource)
			}
			seenResources[resource] = struct{}{}
		}
		if edge.Reason == ConflictSharedResource && len(edge.Resources) == 0 {
			return fmt.Errorf("shared-resource edge %s -> %s has no resource", edge.From, edge.To)
		}
		edgeID := edge.From + "\x00" + edge.To + "\x00" + string(edge.Reason)
		if _, exists := edges[edgeID]; exists {
			return fmt.Errorf("conflict graph repeats edge %s -> %s for %s", edge.From, edge.To, edge.Reason)
		}
		edges[edgeID] = struct{}{}
	}
	memberships := make(map[string]string)
	groups := make(map[string]struct{}, len(g.Groups))
	for _, group := range g.Groups {
		if strings.TrimSpace(group.ID) == "" || len(group.ChangeSets) == 0 {
			return fmt.Errorf("conflict graph has an invalid rollback group")
		}
		if _, exists := groups[group.ID]; exists {
			return fmt.Errorf("conflict graph repeats rollback group %s", group.ID)
		}
		groups[group.ID] = struct{}{}
		for _, node := range group.ChangeSets {
			if _, exists := nodes[node]; !exists {
				return fmt.Errorf("rollback group %s contains unknown node %s", group.ID, node)
			}
			if previous, exists := memberships[node]; exists {
				return fmt.Errorf("node %s belongs to rollback groups %s and %s", node, previous, group.ID)
			}
			memberships[node] = group.ID
		}
	}
	return nil
}

type RollbackTrigger string

const (
	RollbackUserRequest   RollbackTrigger = "user_request"
	RollbackApplyFailure  RollbackTrigger = "apply_failure"
	RollbackVerifyFailure RollbackTrigger = "verification_failure"
	RollbackCrashRecovery RollbackTrigger = "crash_recovery"
)

func (t RollbackTrigger) Valid() bool {
	return t == RollbackUserRequest || t == RollbackApplyFailure || t == RollbackVerifyFailure || t == RollbackCrashRecovery
}

type RollbackOutcome string

const (
	RollbackSucceeded RollbackOutcome = "succeeded"
	RollbackPartial   RollbackOutcome = "partially_succeeded"
	RollbackFailed    RollbackOutcome = "failed"
	RollbackBlocked   RollbackOutcome = "blocked"
)

func (o RollbackOutcome) Valid() bool {
	return o == "" || o == RollbackSucceeded || o == RollbackPartial || o == RollbackFailed || o == RollbackBlocked
}

type RollbackAttempt struct {
	ID                  string          `json:"id"`
	Scope               RollbackScope   `json:"scope"`
	Trigger             RollbackTrigger `json:"trigger"`
	RequestedChangeSets []string        `json:"requested_change_sets,omitempty"`
	ExpandedChangeSets  []string        `json:"expanded_change_sets"`
	CascadeApproved     bool            `json:"cascade_approved"`
	Outcome             RollbackOutcome `json:"outcome,omitempty"`
	StartedAt           time.Time       `json:"started_at"`
	CompletedAt         *time.Time      `json:"completed_at,omitempty"`
	Errors              []JournalError  `json:"errors,omitempty"`
}

func (a RollbackAttempt) Validate() error {
	if strings.TrimSpace(a.ID) == "" || !a.Scope.Valid() || !a.Trigger.Valid() || !a.Outcome.Valid() || a.StartedAt.IsZero() {
		return fmt.Errorf("rollback attempt %s has invalid metadata", a.ID)
	}
	if a.CompletedAt != nil && a.Outcome == "" {
		return fmt.Errorf("rollback attempt %s completed without an outcome", a.ID)
	}
	if len(a.ExpandedChangeSets) == 0 {
		return fmt.Errorf("rollback attempt %s has no expanded change set", a.ID)
	}
	for label, ids := range map[string][]string{
		"requested": a.RequestedChangeSets,
		"expanded":  a.ExpandedChangeSets,
	} {
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("rollback attempt %s has an empty %s change set", a.ID, label)
			}
			if _, exists := seen[id]; exists {
				return fmt.Errorf("rollback attempt %s repeats %s change set %s", a.ID, label, id)
			}
			seen[id] = struct{}{}
		}
	}
	for _, journalError := range a.Errors {
		if err := journalError.Validate(); err != nil {
			return fmt.Errorf("rollback attempt %s: %w", a.ID, err)
		}
	}
	return nil
}

type JournalErrorCode string

const (
	JournalErrorCorruptJournal      JournalErrorCode = "journal_corrupt"
	JournalErrorRevisionConflict    JournalErrorCode = "journal_revision_conflict"
	JournalErrorUnsupportedSchema   JournalErrorCode = "unsupported_schema"
	JournalErrorHostMismatch        JournalErrorCode = "host_mismatch"
	JournalErrorBootChanged         JournalErrorCode = "boot_changed"
	JournalErrorLockUnavailable     JournalErrorCode = "lock_unavailable"
	JournalErrorBackupMissing       JournalErrorCode = "backup_missing"
	JournalErrorBackupHashMismatch  JournalErrorCode = "backup_hash_mismatch"
	JournalErrorPreconditionFailed  JournalErrorCode = "precondition_failed"
	JournalErrorExternalChange      JournalErrorCode = "external_change_detected"
	JournalErrorUnsupportedResource JournalErrorCode = "unsupported_resource"
	JournalErrorApplyFailed         JournalErrorCode = "apply_failed"
	JournalErrorVerificationFailed  JournalErrorCode = "verification_failed"
	JournalErrorRollbackDependency  JournalErrorCode = "rollback_dependency_conflict"
	JournalErrorRollbackFailed      JournalErrorCode = "rollback_failed"
	JournalErrorServiceUnavailable  JournalErrorCode = "service_state_unavailable"
	JournalErrorPersistFailed       JournalErrorCode = "persist_failed"
	JournalErrorCancelFailed        JournalErrorCode = "cancel_failed"
	JournalErrorRecoveryAmbiguous   JournalErrorCode = "recovery_ambiguous"
)

func (c JournalErrorCode) Valid() bool {
	switch c {
	case JournalErrorCorruptJournal,
		JournalErrorRevisionConflict,
		JournalErrorUnsupportedSchema,
		JournalErrorHostMismatch,
		JournalErrorBootChanged,
		JournalErrorLockUnavailable,
		JournalErrorBackupMissing,
		JournalErrorBackupHashMismatch,
		JournalErrorPreconditionFailed,
		JournalErrorExternalChange,
		JournalErrorUnsupportedResource,
		JournalErrorApplyFailed,
		JournalErrorVerificationFailed,
		JournalErrorRollbackDependency,
		JournalErrorRollbackFailed,
		JournalErrorServiceUnavailable,
		JournalErrorPersistFailed,
		JournalErrorCancelFailed,
		JournalErrorRecoveryAmbiguous:
		return true
	default:
		return false
	}
}

type JournalError struct {
	Code        JournalErrorCode `json:"code"`
	Phase       string           `json:"phase"`
	ChangeSetID string           `json:"change_set_id,omitempty"`
	OperationID string           `json:"operation_id,omitempty"`
	Resource    *ResourceRef     `json:"resource,omitempty"`
	Message     string           `json:"message"`
	Retryable   bool             `json:"retryable"`
	OccurredAt  time.Time        `json:"occurred_at"`
}

func (e JournalError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

func (e JournalError) Validate() error {
	if !e.Code.Valid() || strings.TrimSpace(e.Phase) == "" || strings.TrimSpace(e.Message) == "" || e.OccurredAt.IsZero() {
		return fmt.Errorf("journal error metadata is incomplete")
	}
	if e.Resource != nil {
		if err := e.Resource.Validate(); err != nil {
			return fmt.Errorf("journal error resource: %w", err)
		}
	}
	return nil
}

type FailurePolicy string

const (
	FailureRollbackItem FailurePolicy = "rollback_item"
	FailureRollbackRun  FailurePolicy = "rollback_run"
)

func (p FailurePolicy) Valid() bool {
	return p == FailureRollbackItem || p == FailureRollbackRun
}

type RemediationBuildIdentity struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	ExecutableSHA256 string `json:"executable_sha256"`
	Modified         bool   `json:"modified"`
}

func (i RemediationBuildIdentity) Validate() error {
	if strings.TrimSpace(i.Version) == "" || i.Version != strings.TrimSpace(i.Version) || strings.TrimSpace(i.Commit) == "" || i.Commit != strings.TrimSpace(i.Commit) {
		return fmt.Errorf("remediation build version and commit are required")
	}
	if !validSHA256(i.ExecutableSHA256) {
		return fmt.Errorf("remediation executable digest is invalid")
	}
	return nil
}

func validateRemediationPlatform(platform PlatformInfo) error {
	for name, value := range map[string]string{
		"os":           platform.OS,
		"family":       platform.Family,
		"id":           platform.ID,
		"version":      platform.VersionID,
		"architecture": platform.Architecture,
	} {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("remediation platform %s is required and must be canonical", name)
		}
	}
	if platform.Support != SupportVerified {
		return fmt.Errorf("remediation platform support is not verified")
	}
	return nil
}

type HostIdentity struct {
	MachineIDHash string `json:"machine_id_hash"`
	SystemRoot    string `json:"system_root"`
	RootDevice    uint64 `json:"root_device"`
	RootInode     uint64 `json:"root_inode"`
	BootID        string `json:"boot_id"`
}

func (h HostIdentity) Validate() error {
	if !validSHA256(h.MachineIDHash) || strings.TrimSpace(h.SystemRoot) == "" ||
		strings.TrimSpace(h.SystemRoot) != h.SystemRoot || strings.ContainsAny(h.SystemRoot, "\x00\r\n") ||
		h.RootDevice == 0 || h.RootInode == 0 || !validCanonicalUUID(h.BootID) {
		return fmt.Errorf("host identity is incomplete")
	}
	return nil
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		switch index {
		case 8, 13, 18, 23:
			if value[index] != '-' {
				return false
			}
		default:
			character := value[index]
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				return false
			}
		}
	}
	return true
}

type RemediationJournal struct {
	SchemaVersion        int                      `json:"schema_version"`
	Revision             uint64                   `json:"revision"`
	RunID                string                   `json:"run_id"`
	ScanRunID            string                   `json:"scan_run_id"`
	ScanToolVersion      string                   `json:"scan_tool_version"`
	ScanToolCommit       string                   `json:"scan_tool_commit"`
	RuleSetVersion       string                   `json:"rule_set_version"`
	Platform             PlatformInfo             `json:"platform"`
	RemediationBuild     RemediationBuildIdentity `json:"remediation_build"`
	State                RunState                 `json:"state"`
	FailurePolicy        FailurePolicy            `json:"failure_policy"`
	PlanDigest           string                   `json:"plan_digest"`
	Host                 HostIdentity             `json:"host"`
	StartedAt            time.Time                `json:"started_at"`
	UpdatedAt            time.Time                `json:"updated_at"`
	ChangeSets           []ChangeSet              `json:"change_sets"`
	ConflictGraph        ConflictGraph            `json:"conflict_graph"`
	RollbackAttempts     []RollbackAttempt        `json:"rollback_attempts,omitempty"`
	UnresolvedChangeSets []string                 `json:"unresolved_change_sets,omitempty"`
	Warnings             []string                 `json:"warnings,omitempty"`
	Error                *JournalError            `json:"error,omitempty"`
}

func (j RemediationJournal) Validate() error {
	if j.SchemaVersion != RemediationSchemaVersion {
		return fmt.Errorf("unsupported remediation schema version %d", j.SchemaVersion)
	}
	if strings.TrimSpace(j.RunID) == "" || strings.TrimSpace(j.ScanRunID) == "" {
		return fmt.Errorf("run id and scan run id are required")
	}
	if j.Revision < 1 {
		return fmt.Errorf("journal revision must be positive")
	}
	if strings.TrimSpace(j.ScanToolVersion) == "" || strings.TrimSpace(j.ScanToolCommit) == "" || strings.TrimSpace(j.RuleSetVersion) == "" {
		return fmt.Errorf("scan tool identity and rule set version are required")
	}
	if err := validateRemediationPlatform(j.Platform); err != nil {
		return err
	}
	if err := j.RemediationBuild.Validate(); err != nil {
		return err
	}
	if !j.State.Valid() || !j.FailurePolicy.Valid() || !validSHA256(j.PlanDigest) {
		return fmt.Errorf("journal state, failure policy, or plan digest is invalid")
	}
	if err := j.Host.Validate(); err != nil {
		return err
	}
	if j.StartedAt.IsZero() || j.UpdatedAt.IsZero() {
		return fmt.Errorf("journal timestamps are required")
	}
	if j.UpdatedAt.Before(j.StartedAt) {
		return fmt.Errorf("journal updated_at precedes started_at")
	}
	if len(j.ChangeSets) == 0 {
		return fmt.Errorf("journal has no change sets")
	}
	changeSetIDs := make(map[string]struct{}, len(j.ChangeSets))
	sequences := make(map[int]struct{}, len(j.ChangeSets))
	lastSequence := 0
	for _, changeSet := range j.ChangeSets {
		if err := changeSet.Validate(j.PlanDigest); err != nil {
			return err
		}
		if _, exists := changeSetIDs[changeSet.ID]; exists {
			return fmt.Errorf("journal repeats change set %s", changeSet.ID)
		}
		if _, exists := sequences[changeSet.Sequence]; exists {
			return fmt.Errorf("journal repeats change set sequence %d", changeSet.Sequence)
		}
		if changeSet.Sequence <= lastSequence {
			return fmt.Errorf("journal change sets are not in apply sequence order")
		}
		lastSequence = changeSet.Sequence
		changeSetIDs[changeSet.ID] = struct{}{}
		sequences[changeSet.Sequence] = struct{}{}
	}
	if err := j.ConflictGraph.Validate(); err != nil {
		return err
	}
	if len(j.ConflictGraph.Nodes) != len(changeSetIDs) {
		return fmt.Errorf("conflict graph does not contain every change set")
	}
	for index, node := range j.ConflictGraph.Nodes {
		if _, exists := changeSetIDs[node]; !exists {
			return fmt.Errorf("conflict graph contains unknown change set %s", node)
		}
		if node != j.ChangeSets[index].ID {
			return fmt.Errorf("conflict graph node order does not match change set order")
		}
	}
	attemptIDs := make(map[string]struct{}, len(j.RollbackAttempts))
	incompleteAttempt := -1
	for index, attempt := range j.RollbackAttempts {
		if err := attempt.Validate(); err != nil {
			return err
		}
		if attempt.CompletedAt == nil {
			if attempt.Outcome != "" {
				return fmt.Errorf("rollback attempt %s has an outcome before completion", attempt.ID)
			}
			if incompleteAttempt >= 0 || index != len(j.RollbackAttempts)-1 {
				return fmt.Errorf("only the final rollback attempt may be incomplete")
			}
			incompleteAttempt = index
		}
		if _, exists := attemptIDs[attempt.ID]; exists {
			return fmt.Errorf("journal repeats rollback attempt %s", attempt.ID)
		}
		attemptIDs[attempt.ID] = struct{}{}
		for _, id := range append(append([]string(nil), attempt.RequestedChangeSets...), attempt.ExpandedChangeSets...) {
			if _, exists := changeSetIDs[id]; !exists {
				return fmt.Errorf("rollback attempt %s contains unknown change set %s", attempt.ID, id)
			}
		}
	}
	seenUnresolved := make(map[string]struct{}, len(j.UnresolvedChangeSets))
	for _, id := range j.UnresolvedChangeSets {
		if _, exists := changeSetIDs[id]; !exists {
			return fmt.Errorf("journal marks unknown change set %s unresolved", id)
		}
		if _, exists := seenUnresolved[id]; exists {
			return fmt.Errorf("journal repeats unresolved change set %s", id)
		}
		seenUnresolved[id] = struct{}{}
	}
	normalTerminal := j.State == RunCompleted || j.State == RunRolledBack || j.State == RunCompletedWithRollbacks || j.State == RunCanceled || j.State == RunFailed
	if normalTerminal && len(j.UnresolvedChangeSets) > 0 {
		return fmt.Errorf("normal terminal journal %s cannot contain unresolved changes", j.State)
	}
	if normalTerminal && incompleteAttempt >= 0 {
		return fmt.Errorf("normal terminal journal %s cannot contain incomplete rollback attempt %s", j.State, j.RollbackAttempts[incompleteAttempt].ID)
	}
	if normalTerminal {
		allowedChangeState := func(state ChangeSetState) bool {
			switch j.State {
			case RunCompleted:
				return state == ChangeVerified
			case RunRolledBack:
				return state == ChangePlanned || state == ChangeRolledBack
			case RunCompletedWithRollbacks:
				return state == ChangePlanned || state == ChangeVerified || state == ChangeRolledBack
			case RunCanceled:
				return state == ChangePlanned
			case RunFailed:
				return state == ChangePlanned || state == ChangeVerified || state == ChangeApplyFailed || state == ChangeRolledBack
			default:
				return false
			}
		}
		hasVerified := false
		hasRolledBack := false
		for _, changeSet := range j.ChangeSets {
			if !allowedChangeState(changeSet.State) {
				return fmt.Errorf("normal terminal journal %s cannot contain change set %s in state %s", j.State, changeSet.ID, changeSet.State)
			}
			hasVerified = hasVerified || changeSet.State == ChangeVerified
			hasRolledBack = hasRolledBack || changeSet.State == ChangeRolledBack
			allowedOperation := func(state OperationState) bool { return false }
			switch changeSet.State {
			case ChangePlanned:
				allowedOperation = func(state OperationState) bool { return state == OperationPlanned }
			case ChangeApplyFailed:
				allowedOperation = func(state OperationState) bool { return state == OperationPlanned || state == OperationFailed }
			case ChangeVerified:
				allowedOperation = func(state OperationState) bool { return state == OperationVerified }
			case ChangeRolledBack:
				allowedOperation = func(state OperationState) bool {
					return state == OperationPlanned || state == OperationRolledBack || state == OperationFailed
				}
			default:
				return fmt.Errorf("normal terminal journal %s contains nonterminal change set %s in state %s", j.State, changeSet.ID, changeSet.State)
			}
			for _, operation := range changeSet.Operations {
				if !allowedOperation(operation.State) {
					return fmt.Errorf("normal terminal journal %s contains nonterminal operation %s/%s in state %s", j.State, changeSet.ID, operation.ID, operation.State)
				}
				if operation.State == OperationFailed && !operation.ProvesNoEffect() {
					return fmt.Errorf("normal terminal journal %s contains failed operation %s/%s without exact no-effect evidence", j.State, changeSet.ID, operation.ID)
				}
			}
		}
		if j.State == RunRolledBack && !hasRolledBack {
			return fmt.Errorf("rolled-back journal has no rolled-back change set")
		}
		if j.State == RunCompletedWithRollbacks && (!hasVerified || !hasRolledBack) {
			return fmt.Errorf("completed-with-rollbacks journal must contain verified and rolled-back change sets")
		}
		if hasRolledBack {
			hasSucceededAttempt := false
			covered := make(map[string]struct{})
			for _, attempt := range j.RollbackAttempts {
				if attempt.CompletedAt == nil {
					continue
				}
				if attempt.Outcome == RollbackSucceeded {
					hasSucceededAttempt = true
				}
				if attempt.Outcome != RollbackSucceeded && attempt.Outcome != RollbackPartial {
					continue
				}
				for _, changeSetID := range attempt.ExpandedChangeSets {
					covered[changeSetID] = struct{}{}
				}
			}
			if !hasSucceededAttempt {
				return fmt.Errorf("normal rollback terminal journal %s has no completed successful rollback attempt", j.State)
			}
			for _, changeSet := range j.ChangeSets {
				if changeSet.State != ChangeRolledBack {
					continue
				}
				if _, exists := covered[changeSet.ID]; !exists {
					return fmt.Errorf("rolled-back change set %s is not covered by a completed rollback attempt", changeSet.ID)
				}
			}
		}
	}
	if j.Error != nil {
		if err := j.Error.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	if value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func containsParentReference(value string) bool {
	for _, component := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '/' || r == '\\'
	}) {
		if component == ".." {
			return true
		}
	}
	return false
}
