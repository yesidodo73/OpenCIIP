package support

import (
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
)

func TestDNFCacheUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		result executor.Result
		want   bool
	}{
		{
			name: "missing repository cache",
			result: executor.Result{
				ExitCode: 1,
				Stderr:   []byte("Error: Cache-only enabled but no cache for 'baseos'\n"),
			},
			want: true,
		},
		{
			name: "ordinary dnf error",
			result: executor.Result{
				ExitCode: 1,
				Stderr:   []byte("Error: Failed to download metadata for repo 'baseos'\n"),
			},
		},
		{
			name: "successful command with matching diagnostic",
			result: executor.Result{
				ExitCode: 0,
				Stderr:   []byte("Cache-only enabled but no cache for 'baseos'\n"),
			},
		},
		{
			name: "truncated diagnostic",
			result: executor.Result{
				ExitCode:  1,
				Stderr:    []byte("Cache-only enabled but no cache for 'baseos'\n"),
				Truncated: true,
			},
		},
		{
			name: "timed out command",
			result: executor.Result{
				ExitCode: 1,
				Stderr:   []byte("Cache-only enabled but no cache for 'baseos'\n"),
				TimedOut: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := DNFCacheUnavailable(test.result); got != test.want {
				t.Fatalf("DNFCacheUnavailable() = %t, want %t", got, test.want)
			}
		})
	}
}
