package service

import "testing"

func TestAssessPostfixRelayRestrictionsAcceptsGuardedStandardPolicy(t *testing.T) {
	assessment := assessPostfixRelayRestrictions(
		[]string{"permit_mynetworks", "permit_sasl_authenticated", "defer_unauth_destination", "check_recipient_access", "hash:/etc/postfix/after_guard"},
		nil,
	)
	if len(assessment.unsafe) != 0 || len(assessment.indeterminate) != 0 {
		t.Fatalf("assessment = %#v, want deterministic safe guard", assessment)
	}
}

func TestAssessPostfixRelayRestrictionsRejectsUnconditionalPermit(t *testing.T) {
	assessment := assessPostfixRelayRestrictions([]string{"permit", "reject_unauth_destination"}, nil)
	if len(assessment.unsafe) != 1 {
		t.Fatalf("assessment = %#v, want one unsafe finding", assessment)
	}
}

func TestAssessPostfixRelayRestrictionsDoesNotPassLookupBeforeGuard(t *testing.T) {
	assessment := assessPostfixRelayRestrictions(
		[]string{"check_client_access", "hash:/etc/postfix/access", "reject_unauth_destination"},
		nil,
	)
	if len(assessment.unsafe) != 0 || len(assessment.indeterminate) != 1 {
		t.Fatalf("assessment = %#v, want indeterminate lookup before guard", assessment)
	}
}

func TestAssessPostfixRelayRestrictionsDoesNotTreatWarnedGuardAsDeterministic(t *testing.T) {
	assessment := assessPostfixRelayRestrictions([]string{"warn_if_reject", "reject_unauth_destination"}, nil)
	if len(assessment.indeterminate) != 1 {
		t.Fatalf("assessment = %#v, want indeterminate warn_if_reject behavior", assessment)
	}
}

func TestAssessPostfixRelayRestrictionsUsesRecipientFallbackConservatively(t *testing.T) {
	standard := assessPostfixRelayRestrictions(nil, []string{"permit_mynetworks", "reject_unauth_destination"})
	if len(standard.unsafe) != 0 || len(standard.indeterminate) != 0 {
		t.Fatalf("standard recipient fallback = %#v, want deterministic", standard)
	}
	lookup := assessPostfixRelayRestrictions(
		[]string{"check_client_access", "hash:/etc/postfix/access"},
		[]string{"reject_unauth_destination"},
	)
	if len(lookup.indeterminate) != 1 {
		t.Fatalf("lookup recipient fallback = %#v, want indeterminate relay restriction", lookup)
	}
}

func TestAssessPostfixRelayRestrictionsRequiresUnauthDestinationGuard(t *testing.T) {
	assessment := assessPostfixRelayRestrictions([]string{"permit_mynetworks"}, nil)
	if len(assessment.unsafe) != 1 {
		t.Fatalf("assessment = %#v, want missing guard failure", assessment)
	}
}
