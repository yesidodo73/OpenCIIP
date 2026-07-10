package model

import (
	"fmt"
	"strings"
)

// Status is the public result state of a check.
type Status string

const (
	StatusPass          Status = "PASS"
	StatusFail          Status = "FAIL"
	StatusUnknown       Status = "UNKNOWN"
	StatusNotApplicable Status = "NOT_APPLICABLE"
	StatusError         Status = "ERROR"
	StatusSkipped       Status = "SKIPPED"
)

var statuses = []Status{
	StatusPass,
	StatusFail,
	StatusUnknown,
	StatusNotApplicable,
	StatusError,
	StatusSkipped,
}

func (s Status) Valid() bool {
	for _, candidate := range statuses {
		if s == candidate {
			return true
		}
	}
	return false
}

func ParseStatus(value string) (Status, error) {
	status := Status(strings.ToUpper(strings.TrimSpace(value)))
	if !status.Valid() {
		return "", fmt.Errorf("invalid check status %q", value)
	}
	return status, nil
}

// Severity is the guide-defined importance of a check.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

func (s Severity) Valid() bool {
	return s == SeverityHigh || s == SeverityMedium || s == SeverityLow
}

// Category is the guide's top-level Unix check classification.
type Category string

const (
	CategoryAccount       Category = "account"
	CategoryFileDirectory Category = "file_directory"
	CategoryService       Category = "service"
	CategoryPatch         Category = "patch"
	CategoryLogging       Category = "logging"
)

func (c Category) Valid() bool {
	switch c {
	case CategoryAccount, CategoryFileDirectory, CategoryService, CategoryPatch, CategoryLogging:
		return true
	default:
		return false
	}
}

// UnknownReason provides a machine-readable explanation for UNKNOWN.
type UnknownReason string

const (
	UnknownInsufficientEvidence     UnknownReason = "insufficient_evidence"
	UnknownManualVerification       UnknownReason = "manual_verification_required"
	UnknownUnsupportedConfiguration UnknownReason = "unsupported_configuration"
	UnknownAmbiguousResult          UnknownReason = "ambiguous_result"
)

func (r UnknownReason) Valid() bool {
	switch r {
	case UnknownInsufficientEvidence, UnknownManualVerification, UnknownUnsupportedConfiguration, UnknownAmbiguousResult:
		return true
	default:
		return false
	}
}
