package exitcode

import (
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestForResultsPrecedence(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		results []model.CheckResult
		want    int
	}{
		{name: "empty", want: OK},
		{name: "pass and not applicable", results: []model.CheckResult{{Status: model.StatusPass}, {Status: model.StatusNotApplicable}}, want: OK},
		{name: "unknown", results: []model.CheckResult{{Status: model.StatusUnknown}}, want: Unknown},
		{name: "fail beats unknown", results: []model.CheckResult{{Status: model.StatusUnknown}, {Status: model.StatusFail}}, want: Failed},
		{name: "error beats fail", results: []model.CheckResult{{Status: model.StatusFail}, {Status: model.StatusError}}, want: Error},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := ForResults(test.results); got != test.want {
				t.Fatalf("ForResults() = %d, want %d", got, test.want)
			}
		})
	}
}
