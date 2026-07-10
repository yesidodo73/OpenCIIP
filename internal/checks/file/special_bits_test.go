package filecheck

import "testing"

func TestUnapprovedSpecialBitCandidateNeverPassesOnPackageIntegrityAlone(t *testing.T) {
	state, reason := classifyUnapprovedSpecialBitCandidate(false, true)
	if state != "unknown" || reason != "package_integrity_verified_manual_approval_required" {
		t.Fatalf("classifyUnapprovedSpecialBitCandidate() = %q, %q", state, reason)
	}
}

func TestUnapprovedSpecialBitCandidateFailsCompleteInstitutionBaseline(t *testing.T) {
	state, reason := classifyUnapprovedSpecialBitCandidate(true, true)
	if state != "fail" || reason != "file_outside_complete_institution_baseline" {
		t.Fatalf("classifyUnapprovedSpecialBitCandidate() = %q, %q", state, reason)
	}
}
