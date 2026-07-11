package logging

import (
	"os"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestAssessLogFileTreatsNonRootOwnerAsAmbiguousWithoutServicePolicy(t *testing.T) {
	clear, ambiguous := assessLogFile(system.FileMetadata{Path: "/var/log/test.log", UID: 1234, Mode: 0o644}, aclAssessment{})
	if len(clear) != 0 || len(ambiguous) != 1 {
		t.Fatalf("assessLogFile() = %#v, %#v, want one ambiguous owner finding", clear, ambiguous)
	}
}

func TestAssessLogFileTreatsGroupWriteAsAmbiguousWithoutPackagePolicy(t *testing.T) {
	clear, ambiguous := assessLogFile(system.FileMetadata{Path: "/var/log/test.log", UID: 0, Mode: os.FileMode(0o660)}, aclAssessment{})
	if len(clear) != 0 || len(ambiguous) != 1 {
		t.Fatalf("assessLogFile() = %#v, %#v, want one ambiguous mode finding", clear, ambiguous)
	}
}

func TestAssessACLDocumentTreatsNamedWriteAsAmbiguousWithoutServicePolicy(t *testing.T) {
	assessment, err := assessACLDocument([]string{"user::rw-", "user:1000:rw-", "group::r--", "mask::rw-", "other::r--"})
	if err != nil {
		t.Fatalf("assessACLDocument() error = %v", err)
	}
	if len(assessment.clearReasons) != 0 || len(assessment.ambiguousReasons) != 1 {
		t.Fatalf("assessACLDocument() = %#v, want one ambiguous named-user finding", assessment)
	}
}

func TestAssessACLDocumentTreatsOtherWriteAsClearViolation(t *testing.T) {
	assessment, err := assessACLDocument([]string{"user::rw-", "group::r--", "other::rw-"})
	if err != nil {
		t.Fatalf("assessACLDocument() error = %v", err)
	}
	if len(assessment.clearReasons) != 1 || len(assessment.ambiguousReasons) != 0 {
		t.Fatalf("assessACLDocument() = %#v, want one clear other-write violation", assessment)
	}
}
