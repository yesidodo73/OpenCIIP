package evaluator

import (
	"context"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func testResolvedRule(verification model.VerificationState) model.ResolvedRule {
	return model.ResolvedRule{
		RuleDefinition: model.RuleDefinition{
			ID:        "U-01",
			Title:     "테스트 점검",
			Category:  model.CategoryAccount,
			Severity:  model.SeverityHigh,
			Evaluator: "test.evaluator",
			Criteria:  model.Criteria{Pass: "테스트 기준을 충족해야 합니다."},
			Reference: model.Reference{Guide: "test", Item: "U-01", Pages: []int{1}},
		},
		Applicable:     true,
		Verification:   model.Verification{State: verification},
		BindingSources: []string{"test-layer"},
	}
}

func TestRegistryEvaluateVerificationBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		verification model.VerificationState
		outcome      Outcome
		wantStatus   model.Status
		wantReason   model.UnknownReason
		wantObserved string
		wantCode     string
	}{
		{
			name:         "pending pass becomes unknown",
			verification: model.VerificationPending,
			outcome:      Outcome{Status: model.StatusPass, Summary: "예비 양호", Observed: "value=1"},
			wantStatus:   model.StatusUnknown,
			wantReason:   model.UnknownUnsupportedConfiguration,
			wantObserved: "예비 상태=PASS",
		},
		{
			name:         "pending fail becomes unknown",
			verification: model.VerificationPending,
			outcome:      Outcome{Status: model.StatusFail, Summary: "예비 취약"},
			wantStatus:   model.StatusUnknown,
			wantReason:   model.UnknownUnsupportedConfiguration,
			wantObserved: "예비 상태=FAIL",
		},
		{
			name:         "pending collection error remains error",
			verification: model.VerificationPending,
			outcome:      Outcome{Status: model.StatusError, Summary: "수집 실패", ErrorCode: "read_failed", ErrorMessage: "denied"},
			wantStatus:   model.StatusError,
			wantCode:     "read_failed",
		},
		{
			name:         "pending unknown keeps explicit reason",
			verification: model.VerificationPending,
			outcome:      Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "수동 확인"},
			wantStatus:   model.StatusUnknown,
			wantReason:   model.UnknownManualVerification,
		},
		{
			name:         "verified pass remains pass",
			verification: model.VerificationVerified,
			outcome:      Outcome{Status: model.StatusPass, Summary: "양호"},
			wantStatus:   model.StatusPass,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			registry := NewRegistry()
			if err := registry.Register("test.evaluator", func(context.Context, model.ResolvedRule, Environment) Outcome {
				return test.outcome
			}); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			result := registry.Evaluate(context.Background(), testResolvedRule(test.verification), Environment{})
			if result.Status != test.wantStatus {
				t.Fatalf("status = %s, want %s", result.Status, test.wantStatus)
			}
			if result.UnknownReason != test.wantReason {
				t.Fatalf("unknown reason = %s, want %s", result.UnknownReason, test.wantReason)
			}
			if test.wantObserved != "" && !strings.Contains(result.Observed, test.wantObserved) {
				t.Fatalf("observed = %q, want substring %q", result.Observed, test.wantObserved)
			}
			if result.ErrorCode != test.wantCode {
				t.Fatalf("error code = %q, want %q", result.ErrorCode, test.wantCode)
			}
		})
	}
}

func TestRegistryEvaluateRejectedDoesNotInvokeEvaluator(t *testing.T) {
	t.Parallel()
	called := false
	registry := NewRegistry()
	if err := registry.Register("test.evaluator", func(context.Context, model.ResolvedRule, Environment) Outcome {
		called = true
		return Outcome{Status: model.StatusPass}
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	rule := testResolvedRule(model.VerificationRejected)
	result := registry.Evaluate(context.Background(), rule, Environment{})
	if called {
		t.Fatal("rejected evaluator was invoked")
	}
	if result.Status != model.StatusUnknown || result.UnknownReason != model.UnknownUnsupportedConfiguration {
		t.Fatalf("result = %s/%s, want UNKNOWN/unsupported_configuration", result.Status, result.UnknownReason)
	}
}

func TestRegistryEvaluateMasksPanic(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	if err := registry.Register("test.evaluator", func(context.Context, model.ResolvedRule, Environment) Outcome {
		panic("password=do-not-leak")
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	result := registry.Evaluate(context.Background(), testResolvedRule(model.VerificationVerified), Environment{})
	if result.Status != model.StatusError || result.ErrorCode != "evaluator_panic" {
		t.Fatalf("result = %s/%s, want ERROR/evaluator_panic", result.Status, result.ErrorCode)
	}
	if strings.Contains(result.ErrorMessage, "do-not-leak") {
		t.Fatalf("panic detail leaked: %q", result.ErrorMessage)
	}
}

func TestRegistryEvaluateNormalizesInvalidStatus(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	if err := registry.Register("test.evaluator", func(context.Context, model.ResolvedRule, Environment) Outcome {
		return Outcome{Status: model.Status("INVALID")}
	}); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	result := registry.Evaluate(context.Background(), testResolvedRule(model.VerificationVerified), Environment{})
	if result.Status != model.StatusError || result.ErrorCode != "invalid_evaluator_status" {
		t.Fatalf("result = %s/%s, want ERROR/invalid_evaluator_status", result.Status, result.ErrorCode)
	}
}
