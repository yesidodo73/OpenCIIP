package stateroot

import (
	"strings"
	"testing"
)

func TestPrepareAndValidateRejectMalformedPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "whitespace", value: " \t\r\n "},
		{name: "nul", value: "state\x00root"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			for _, operation := range []struct {
				name string
				run  func(string) (string, error)
			}{
				{name: "prepare", run: Prepare},
				{name: "validate", run: Validate},
			} {
				operation := operation
				t.Run(operation.name, func(t *testing.T) {
					t.Parallel()

					resolved, err := operation.run(test.value)
					if err == nil {
						t.Fatalf("%s(%q) resolved %q without an error", operation.name, test.value, resolved)
					}
					if !strings.Contains(err.Error(), "unsafe remediation state root") {
						t.Fatalf("%s(%q) error = %v, want a structured unsafe-root error", operation.name, test.value, err)
					}
				})
			}
		})
	}
}
