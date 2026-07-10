//go:build linux

package workflow

import (
	"context"
	"os"
	"runtime/debug"
	"testing"
)

func TestOpenExecutionWorkflowClosesSystemRootOnConstructorFailure(t *testing.T) {
	previousGCPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGCPercent)

	before := countOpenDescriptors(t)
	systemRoot := t.TempDir()
	for range 32 {
		workflow, err := openExecutionWorkflow(context.Background(), "/unused", systemRoot, false)
		if err == nil {
			_ = workflow.Close()
			t.Fatal("openExecutionWorkflow() succeeded without /etc/os-release")
		}
	}
	after := countOpenDescriptors(t)
	if after != before {
		t.Fatalf("open descriptors changed from %d to %d after constructor failures", before, after)
	}
}

func countOpenDescriptors(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd) error = %v", err)
	}
	return len(entries)
}
