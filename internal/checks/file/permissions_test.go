package filecheck

import (
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestHostsLPDMissingConclusionDoesNotPassActiveOrUnknownInitPath(t *testing.T) {
	if outcome := hostsLPDMissingConclusion("systemd", []string{"port 515 listening"}, nil); outcome.Status != model.StatusUnknown {
		t.Fatalf("active LPD conclusion = %s, want UNKNOWN", outcome.Status)
	}
	if outcome := hostsLPDMissingConclusion("openrc", nil, nil); outcome.Status != model.StatusUnknown {
		t.Fatalf("unknown init conclusion = %s, want UNKNOWN", outcome.Status)
	}
	if outcome := hostsLPDMissingConclusion("systemd", nil, nil); outcome.Status != model.StatusPass {
		t.Fatalf("inactive systemd conclusion = %s, want PASS", outcome.Status)
	}
}
