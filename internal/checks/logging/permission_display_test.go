package logging

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func TestLogPermissionDetailsIncludeAllFindings(t *testing.T) {
	entries := make(map[string]system.FileMetadata)
	for index := 0; index < 16; index++ {
		entries[fmt.Sprintf("/var/log/example-%02d", index)] = system.FileMetadata{UID: 0, Mode: 0o666}
	}
	outcome := evaluateLogFilePermissions(context.Background(), guideLogRule(), evaluator.Environment{Files: newGuideLogReader(entries)})
	if outcome.Status != model.StatusFail || len(outcome.Details) != 1 || outcome.Details[0].Current != outcome.Observed {
		t.Fatalf("log permission findings were omitted: %#v", outcome.Details)
	}
	if !strings.Contains(outcome.Details[0].Current, "/var/log/example-15") {
		t.Fatalf("last log finding is missing: %q", outcome.Details[0].Current)
	}
}
