package filecheck

import (
	"context"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
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

func TestStaticPermissionEvaluatorTreatsMissingACLCollectorAsUnsupportedUnknown(t *testing.T) {
	outcome := staticPermissionEvaluator(permissionPolicy{path: "/etc/passwd", allowedMode: 0o644})(
		context.Background(),
		model.ResolvedRule{},
		evaluator.Environment{
			Files:    newStartupTestReader(t, map[string]string{"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"}),
			Commands: nonOwnerACLFixtureRunner{},
		},
	)
	if outcome.Status != model.StatusUnknown || outcome.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("outcome = %#v, want UNKNOWN unsupported_configuration", outcome)
	}
	if len(outcome.Evidence) < 2 || outcome.Evidence[len(outcome.Evidence)-1].Source != "posix_acl" {
		t.Fatalf("evidence = %#v, want file metadata and ACL collector availability", outcome.Evidence)
	}
}
