package logging

import (
	"os"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestAssessLogFileTreatsNonRootOwnerAsClearViolation(t *testing.T) {
	clear, ambiguous := assessLogFile(system.FileMetadata{Path: "/var/log/test.log", UID: 1234, Mode: 0o644}, aclAssessment{})
	if len(clear) != 1 || len(ambiguous) != 0 {
		t.Fatalf("assessLogFile() = %#v, %#v, want one clear owner violation", clear, ambiguous)
	}
}

func TestAssessLogFileTreatsGroupWriteAsClearViolation(t *testing.T) {
	clear, ambiguous := assessLogFile(system.FileMetadata{Path: "/var/log/test.log", UID: 0, Mode: os.FileMode(0o660)}, aclAssessment{})
	if len(clear) != 1 || len(ambiguous) != 0 {
		t.Fatalf("assessLogFile() = %#v, %#v, want one clear mode violation", clear, ambiguous)
	}
}

func TestAssessACLDocumentTreatsNamedWriteAsClearViolation(t *testing.T) {
	assessment, err := assessACLDocument([]string{"user::rw-", "user:1000:rw-", "group::r--", "mask::rw-", "other::r--"})
	if err != nil {
		t.Fatalf("assessACLDocument() error = %v", err)
	}
	if len(assessment.clearReasons) != 1 || len(assessment.ambiguousReasons) != 0 {
		t.Fatalf("assessACLDocument() = %#v, want one clear named-user violation", assessment)
	}
}
