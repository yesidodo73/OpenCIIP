package model

import "time"

const RunMetadataSchemaVersion = 3

type EvidenceKind string

const (
	EvidenceCommand EvidenceKind = "command"
	EvidenceFile    EvidenceKind = "file"
	EvidenceFact    EvidenceKind = "fact"
)

type CommandEvidence struct {
	Executable string   `json:"executable"`
	Arguments  []string `json:"arguments,omitempty"`
	ExitCode   int      `json:"exit_code"`
	Stdout     string   `json:"stdout,omitempty"`
	Stderr     string   `json:"stderr,omitempty"`
	DurationMS int64    `json:"duration_ms"`
	TimedOut   bool     `json:"timed_out"`
	Truncated  bool     `json:"truncated"`
}

type FileEvidence struct {
	Path      string `json:"path"`
	LineStart int    `json:"line_start,omitempty"`
	LineEnd   int    `json:"line_end,omitempty"`
	Content   string `json:"content,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Owner     string `json:"owner,omitempty"`
	Group     string `json:"group,omitempty"`
	Truncated bool   `json:"truncated"`
}

type Evidence struct {
	Kind       EvidenceKind     `json:"kind"`
	Source     string           `json:"source"`
	CapturedAt time.Time        `json:"captured_at"`
	Redacted   bool             `json:"redacted"`
	Command    *CommandEvidence `json:"command,omitempty"`
	File       *FileEvidence    `json:"file,omitempty"`
	Fact       map[string]any   `json:"fact,omitempty"`
}

type ResultDetail struct {
	Label    string
	Current  string
	Expected string
	Source   string
}

type CheckResult struct {
	RuleID         string         `json:"rule_id"`
	Title          string         `json:"title"`
	Category       Category       `json:"category"`
	Severity       Severity       `json:"severity"`
	Status         Status         `json:"status"`
	UnknownReason  UnknownReason  `json:"unknown_reason,omitempty"`
	Summary        string         `json:"summary"`
	Expected       string         `json:"expected,omitempty"`
	Solution       string         `json:"solution,omitempty"`
	Observed       string         `json:"observed,omitempty"`
	DisplayDetails []ResultDetail `json:"-"`
	Evaluator      string         `json:"evaluator"`
	Verification   Verification   `json:"verification"`
	BindingSources []string       `json:"binding_sources,omitempty"`
	Reference      Reference      `json:"reference"`
	Evidence       []Evidence     `json:"evidence,omitempty"`
	StartedAt      time.Time      `json:"started_at"`
	CompletedAt    time.Time      `json:"completed_at"`
	DurationMS     int64          `json:"duration_ms"`
	ErrorCode      string         `json:"error_code,omitempty"`
	ErrorMessage   string         `json:"error_message,omitempty"`
}

type Selection struct {
	Profiles   []string   `json:"profiles,omitempty"`
	RuleIDs    []string   `json:"rule_ids,omitempty"`
	Categories []Category `json:"categories,omitempty"`
	Severities []Severity `json:"severities,omitempty"`
}

type RunMetadata struct {
	SchemaVersion        int            `json:"schema_version"`
	RunID                string         `json:"run_id"`
	ToolVersion          string         `json:"tool_version"`
	ToolCommit           string         `json:"tool_commit"`
	ToolExecutableSHA256 string         `json:"tool_executable_sha256"`
	GuideYear            int            `json:"guide_year"`
	RuleSetVersion       string         `json:"rule_set_version"`
	StartedAt            time.Time      `json:"started_at"`
	CompletedAt          time.Time      `json:"completed_at"`
	DurationMS           int64          `json:"duration_ms"`
	Platform             PlatformInfo   `json:"platform"`
	Selection            Selection      `json:"selection"`
	Counts               map[Status]int `json:"counts"`
	EvidenceMode         string         `json:"evidence_mode"`
	Redaction            bool           `json:"redaction"`
	Complete             bool           `json:"complete"`
	ExitCode             int            `json:"exit_code"`
	Warnings             []string       `json:"warnings,omitempty"`
	TargetIdentity       *HostIdentity  `json:"target_identity,omitempty"`
}

type ScanRun struct {
	Metadata RunMetadata   `json:"metadata"`
	Results  []CheckResult `json:"results"`
}
