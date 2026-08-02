package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/orchestrator"
)

func TestWriteRollbackFailureStatusShowsRecoveryCommandForAmbiguousEffect(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	rollbackErr := &orchestrator.Error{
		Code:      orchestrator.CodeRecoveryRequired,
		Operation: "persist rolled back operation",
		RunID:     "run-a",
		Committed: true,
		Err:       errors.New("durable result was not confirmed"),
	}
	current := &model.RemediationJournal{
		RunID:    "run-a",
		Revision: 7,
		State:    model.RunRollingBack,
	}
	if err := writeRollbackFailureStatus(&output, "run-a", rollbackErr, current, nil); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	for _, expected := range []string{
		"현재 저널 상태: rolling_back",
		"현재 revision: 7",
		"openciip remediate recover run-a --yes",
		"recover는 새 롤백을 실행하지 않습니다",
	} {
		if !strings.Contains(value, expected) {
			t.Fatalf("output = %q, want %q", value, expected)
		}
	}
}

func TestWriteRollbackFailureStatusRecognizesDurableTerminalState(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	rollbackErr := &orchestrator.Error{
		Code:      orchestrator.CodeRecoveryRequired,
		Operation: "complete rollback attempt",
		RunID:     "run-a",
		Committed: true,
		Err:       errors.New("terminal snapshot sync failed after WAL commit"),
	}
	current := &model.RemediationJournal{
		RunID:    "run-a",
		Revision: 9,
		State:    model.RunRolledBack,
	}
	if err := writeRollbackFailureStatus(&output, "run-a", rollbackErr, current, nil); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	for _, expected := range []string{
		"현재 저널 상태: rolled_back",
		"현재 revision: 9",
		"최종 저널 상태가 이미 영속화되었습니다",
		"동일한 롤백 명령을 다시 실행하지 마세요",
	} {
		if !strings.Contains(value, expected) {
			t.Fatalf("output = %q, want %q", value, expected)
		}
	}
	if strings.Contains(value, "remediate recover") {
		t.Fatalf("output = %q, durable terminal rollback must not recommend recover", value)
	}
}

func TestWriteRollbackFailureStatusDoesNotTrustTerminalStateWithIncompleteWAL(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	current := &model.RemediationJournal{
		RunID:    "run-a",
		Revision: 9,
		State:    model.RunRolledBack,
	}
	if err := writeRollbackFailureStatus(
		&output,
		"run-a",
		errors.New("rollback result unavailable"),
		current,
		errors.New("incomplete WAL tail"),
	); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	if !strings.Contains(value, "현재 저널 상태: rolled_back") ||
		!strings.Contains(value, "openciip remediate recover run-a --yes") {
		t.Fatalf("output = %q, incomplete WAL must require recovery", value)
	}
	if strings.Contains(value, "최종 저널 상태가 이미 영속화되었습니다") {
		t.Fatalf("output = %q, incomplete WAL was treated as a fresh terminal journal", value)
	}
}

func TestWriteRollbackFailureStatusRequestsFreshPreviewForStaleCompletedRun(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	rollbackErr := &orchestrator.Error{
		Code:        orchestrator.CodeRollbackPreviewStale,
		Operation:   "rollback item",
		RunID:       "run-a",
		ChangeSetID: "change-a",
		Err:         errors.New("preview is stale"),
	}
	current := &model.RemediationJournal{
		RunID:    "run-a",
		Revision: 4,
		State:    model.RunCompleted,
	}
	if err := writeRollbackFailureStatus(&output, "run-a", rollbackErr, current, nil); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	if !strings.Contains(value, "현재 저널 상태: completed") {
		t.Fatalf("output = %q, want current journal state", value)
	}
	for _, expected := range []string{
		"새 미리보기에서 preview digest를 다시 생성하세요",
		"openciip remediate rollback preview item run-a change-a",
	} {
		if !strings.Contains(value, expected) {
			t.Fatalf("output = %q, want %q", value, expected)
		}
	}
	for _, unexpected := range []string{
		"최종 저널 상태가 이미 영속화되었습니다",
		"동일한 롤백 명령을 다시 실행하지 마세요",
		"remediate recover",
	} {
		if strings.Contains(value, unexpected) {
			t.Fatalf("output = %q, stale preview contained %q", value, unexpected)
		}
	}
}

func TestWriteRollbackFailureStatusRequestsFreshRunPreview(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	rollbackErr := &orchestrator.Error{
		Code:      orchestrator.CodeRollbackPreviewStale,
		Operation: "rollback run",
		RunID:     "run-a",
		Err:       errors.New("preview is stale"),
	}
	current := &model.RemediationJournal{
		RunID:    "run-a",
		Revision: 5,
		State:    model.RunCompleted,
	}
	if err := writeRollbackFailureStatus(&output, "run-a", rollbackErr, current, nil); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	if !strings.Contains(value, "openciip remediate rollback preview run run-a") {
		t.Fatalf("output = %q, want fresh run preview command", value)
	}
	if strings.Contains(value, "최종 저널 상태가 이미 영속화되었습니다") ||
		strings.Contains(value, "remediate recover") {
		t.Fatalf("output = %q, stale run preview was mistaken for a finalized rollback", value)
	}
}

func TestWriteRollbackFailureStatusDoesNotRefreshStalePreviewWithIncompleteWAL(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	rollbackErr := &orchestrator.Error{
		Code:        orchestrator.CodeRollbackPreviewStale,
		Operation:   "rollback item",
		RunID:       "run-a",
		ChangeSetID: "change-a",
		Err:         errors.New("preview is stale"),
	}
	current := &model.RemediationJournal{
		RunID:    "run-a",
		Revision: 4,
		State:    model.RunCompleted,
	}
	if err := writeRollbackFailureStatus(&output, "run-a", rollbackErr, current, errors.New("incomplete WAL tail")); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	if !strings.Contains(value, "openciip remediate recover run-a --yes") {
		t.Fatalf("output = %q, incomplete WAL did not require recovery", value)
	}
	if strings.Contains(value, "rollback preview item") {
		t.Fatalf("output = %q, stale preview was refreshed from an incomplete WAL", value)
	}
}

func TestWriteRollbackFailureStatusDistinguishesKnownFailedRollback(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	rollbackErr := &orchestrator.Error{
		Code:  orchestrator.CodeRollbackFailed,
		RunID: "run-a",
		Err:   errors.New("restore left the exact after state"),
	}
	current := &model.RemediationJournal{
		RunID:    "run-a",
		Revision: 8,
		State:    model.RunRollbackFailed,
	}
	if err := writeRollbackFailureStatus(&output, "run-a", rollbackErr, current, nil); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	if !strings.Contains(value, "롤백 실행이 복구 또는 재시도가 필요한 상태입니다.") ||
		!strings.Contains(value, "openciip remediate recover run-a --yes") {
		t.Fatalf("output = %q, want failed-rollback recovery guidance", value)
	}
	if strings.Contains(value, "실제 변경 여부") {
		t.Fatalf("output = %q, known failed rollback was described as an ambiguous effect", value)
	}
}

func TestWriteRollbackFailureStatusFailsClosedWhenJournalCannotBeRead(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer
	if err := writeRollbackFailureStatus(
		&output,
		"run-a",
		errors.New("rollback failed"),
		nil,
		errors.New("journal unavailable"),
	); err != nil {
		t.Fatalf("writeRollbackFailureStatus() error = %v", err)
	}
	value := output.String()
	if !strings.Contains(value, "현재 저널 상태: 확인 실패") ||
		!strings.Contains(value, "openciip remediate recover run-a --yes") {
		t.Fatalf("output = %q, want fail-closed recovery guidance", value)
	}
	if strings.Contains(value, "journal unavailable") {
		t.Fatalf("output exposed an internal load error: %q", value)
	}
}
