package service

import (
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestNFSSquashPolicyRequiresExplicitUnmodifiedRootSquash(t *testing.T) {
	if !nfsSquashPolicyExplicitlyKnown(map[string]string{"root_squash": ""}) {
		t.Fatal("explicit root_squash was not recognized")
	}
	for name, options := range map[string]map[string]string{
		"implicit default": {},
		"no root squash":   {"no_root_squash": ""},
		"all squash":       {"root_squash": "", "all_squash": ""},
		"custom anon uid":  {"root_squash": "", "anonuid": "65534"},
		"custom anon gid":  {"root_squash": "", "anongid": "65534"},
	} {
		if nfsSquashPolicyExplicitlyKnown(options) {
			t.Errorf("%s policy was treated as fully verified", name)
		}
	}
}

func TestAnonymousNFSWithoutExportfsUsesIndependentAbsenceEvidence(t *testing.T) {
	evidence := []model.Evidence{{Kind: model.EvidenceFact, Source: "nfs-presence"}}
	for _, status := range []model.Status{model.StatusNotApplicable, model.StatusPass} {
		finding := anonymousNFSWithoutExportfs(evaluator.Outcome{
			Status:   status,
			Observed: "NFS server unit, process, thread, export 없음",
			Evidence: evidence,
		})
		if finding.State != "not_applicable" {
			t.Errorf("status %s mapped to %q, want not_applicable", status, finding.State)
		}
		if len(finding.Evidence) != 1 || finding.Evidence[0].Source != "nfs-presence" {
			t.Errorf("status %s lost independent NFS evidence: %#v", status, finding.Evidence)
		}
	}
}

func TestAnonymousNFSWithoutExportfsDoesNotTreatActiveServerAsAnonymous(t *testing.T) {
	for _, status := range []model.Status{model.StatusFail, model.StatusUnknown} {
		finding := anonymousNFSWithoutExportfs(evaluator.Outcome{
			Status:   status,
			Observed: "NFS server active",
		})
		if finding.State != "unknown" {
			t.Errorf("status %s mapped to %q, want unknown", status, finding.State)
		}
	}
}

func TestAnonymousNFSWithoutExportfsPreservesInspectionError(t *testing.T) {
	finding := anonymousNFSWithoutExportfs(evaluator.Outcome{
		Status:  model.StatusError,
		Summary: "NFS 상태를 확인하지 못했습니다.",
	})
	if finding.State != "error" || finding.Reason != "NFS 상태를 확인하지 못했습니다." {
		t.Fatalf("finding = %#v, want preserved error", finding)
	}
}
