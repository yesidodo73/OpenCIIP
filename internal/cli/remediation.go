package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/orchestrator"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/workflow"
)

const defaultRemediationStateDirectory = "/var/lib/openciip/remediation"

type remediationCommandOptions struct {
	stateDirectory string
}

func newRemediateCommand(stdout io.Writer, resultCode *int) *cobra.Command {
	options := remediationCommandOptions{stateDirectory: defaultRemediationStateDirectory}
	command := &cobra.Command{
		Use:           "remediate",
		Short:         "검증 완료 항목의 승인 기반 조치와 롤백을 관리합니다",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	command.AddCommand(newRemediationPlanCommand(stdout, resultCode, &options))
	command.AddCommand(newRemediationApproveCommand(stdout, resultCode, &options))
	command.AddCommand(newRemediationCancelCommand(stdout, resultCode, &options))
	command.AddCommand(newRemediationApplyCommand(stdout, resultCode, &options))
	command.AddCommand(newRemediationStatusCommand(stdout, resultCode, &options))
	command.AddCommand(newRemediationRollbackCommand(stdout, resultCode, &options))
	command.AddCommand(newRemediationRecoverCommand(stdout, resultCode, &options))
	return command
}

func newRemediationPlanCommand(stdout io.Writer, resultCode *int, parent *remediationCommandOptions) *cobra.Command {
	var reportDirectory string
	var checks []string
	var failurePolicy string
	command := &cobra.Command{
		Use:   "plan",
		Short: "완료된 점검 보고서로 변경 없는 dry-run 계획을 생성합니다",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if strings.TrimSpace(reportDirectory) == "" {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("--report에 완료된 점검 보고서 디렉터리를 지정해야 합니다")}
			}
			policy := model.FailurePolicy(strings.TrimSpace(failurePolicy))
			if !policy.Valid() {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("--failure-policy는 rollback_item 또는 rollback_run이어야 합니다")}
			}
			service, err := workflow.New(command.Context(), parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("조치 계획을 준비하지 못했습니다", err)
			}
			defer service.Close()
			planned, err := service.PlanFromReport(command.Context(), reportDirectory, workflow.PlanOptions{RuleIDs: checks, FailurePolicy: policy})
			if err != nil {
				return remediationFailure("조치 계획을 생성하지 못했습니다", err)
			}
			if err := writeRemediationPlan(stdout, planned); err != nil {
				return remediationFailure("조치 계획을 출력하지 못했습니다", err)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	command.Flags().StringVar(&reportDirectory, "report", "", "입력할 완료·마스킹 점검 보고서 디렉터리")
	command.Flags().StringSliceVar(&checks, "check", nil, "계획에 포함할 FAIL 항목 코드")
	command.Flags().StringVar(&failurePolicy, "failure-policy", string(model.FailureRollbackItem), "적용 실패 시 rollback_item 또는 rollback_run")
	return command
}

func newRemediationApproveCommand(stdout io.Writer, resultCode *int, parent *remediationCommandOptions) *cobra.Command {
	var digest string
	var confirmed bool
	command := &cobra.Command{
		Use:   "approve RUN_ID",
		Short: "표시된 plan digest를 확인하고 조치 실행을 승인합니다",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			if !confirmed {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("실제 승인은 --yes를 명시해야 합니다")}
			}
			if !isSHA256Digest(digest) {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("--plan-digest에 계획 화면의 64자리 SHA-256 값을 지정해야 합니다")}
			}
			service, err := workflow.OpenExecution(command.Context(), parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("승인을 준비하지 못했습니다", err)
			}
			defer service.Close()
			if err := service.Approve(command.Context(), arguments[0], digest, "cli-explicit", ""); err != nil {
				return remediationFailure("조치 계획을 승인하지 못했습니다", err)
			}
			if _, err := fmt.Fprintf(stdout, "조치 계획을 승인했습니다.\n실행 ID: %s\nplan digest: %s\n실제 적용은 remediate apply 명령으로 별도 실행해야 합니다.\n", arguments[0], digest); err != nil {
				return remediationFailure("승인 결과를 출력하지 못했습니다", err)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	command.Flags().StringVar(&digest, "plan-digest", "", "계획 화면에 표시된 SHA-256 plan digest")
	command.Flags().BoolVar(&confirmed, "yes", false, "표시된 변경 계획과 영향을 검토했음을 확인합니다")
	return command
}

func newRemediationCancelCommand(stdout io.Writer, resultCode *int, parent *remediationCommandOptions) *cobra.Command {
	var confirmed bool
	command := &cobra.Command{
		Use:   "cancel RUN_ID",
		Short: "아직 적용하지 않은 계획을 폐기하고 desired payload를 삭제합니다",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			if !confirmed {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("계획 취소는 --yes를 명시해야 합니다")}
			}
			service, err := workflow.OpenCancellation(parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("계획 취소를 준비하지 못했습니다", err)
			}
			if err := service.Cancel(command.Context(), arguments[0]); err != nil {
				return remediationFailure("조치 계획을 취소하지 못했습니다", err)
			}
			current, err := service.Load(command.Context(), arguments[0])
			if err != nil {
				return remediationFailure("취소 후 저널을 확인하지 못했습니다", err)
			}
			if _, err := fmt.Fprintf(stdout, "조치 계획을 취소했습니다.\n실행 ID: %s\n상태: %s\n", current.RunID, current.State); err != nil {
				return remediationFailure("취소 결과를 출력하지 못했습니다", err)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	command.Flags().BoolVar(&confirmed, "yes", false, "적용 전 계획과 미사용 desired payload를 폐기하는 것을 확인합니다")
	return command
}

func newRemediationApplyCommand(stdout io.Writer, resultCode *int, parent *remediationCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "apply RUN_ID",
		Short: "별도로 승인된 계획을 적용하고 즉시 검증합니다",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			service, err := workflow.OpenExecution(command.Context(), parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("조치 적용을 준비하지 못했습니다", err)
			}
			defer service.Close()
			if err := service.Apply(command.Context(), arguments[0]); err != nil {
				if current, loadErr := service.Load(context.WithoutCancel(command.Context()), arguments[0]); loadErr == nil {
					if _, outputErr := fmt.Fprintf(stdout, "적용 후 저널 상태: %s\n", current.State); outputErr != nil {
						return remediationFailure("조치 적용에 실패했고 현재 저널 상태도 출력하지 못했습니다", fmt.Errorf("%v; 출력 오류: %w", err, outputErr))
					}
				}
				return remediationFailure("조치 적용 또는 검증에 실패했습니다", err)
			}
			current, err := service.Load(command.Context(), arguments[0])
			if err != nil {
				return remediationFailure("적용 후 저널을 확인하지 못했습니다", err)
			}
			if _, err := fmt.Fprintf(stdout, "조치 적용과 검증을 완료했습니다.\n실행 ID: %s\n상태: %s\n", current.RunID, current.State); err != nil {
				return remediationFailure("적용 결과를 출력하지 못했습니다", err)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
}

func newRemediationStatusCommand(stdout io.Writer, resultCode *int, parent *remediationCommandOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "status RUN_ID",
		Short: "조치 실행 저널의 현재 상태를 읽기 전용으로 표시합니다",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			service, err := workflow.OpenStatus(parent.stateDirectory)
			if err != nil {
				return remediationFailure("조치 상태 조회를 준비하지 못했습니다", err)
			}
			inspection, err := service.Inspect(command.Context(), arguments[0])
			if err != nil {
				return remediationFailure("조치 저널을 읽지 못했습니다", err)
			}
			if err := writeRemediationStatus(stdout, inspection.Journal); err != nil {
				return remediationFailure("조치 상태를 출력하지 못했습니다", err)
			}
			if inspection.IncompleteWALTail {
				if _, err := fmt.Fprintln(stdout, "주의: 완결되지 않은 WAL tail이 있습니다. status는 이를 수정하지 않았으며 recover --yes로 정합화해야 합니다."); err != nil {
					return remediationFailure("WAL 복구 안내를 출력하지 못했습니다", err)
				}
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
}

func newRemediationRollbackCommand(stdout io.Writer, resultCode *int, parent *remediationCommandOptions) *cobra.Command {
	command := &cobra.Command{Use: "rollback", Short: "미리 확인한 항목별 또는 실행 전체 범위를 롤백합니다", Args: cobra.NoArgs}
	preview := &cobra.Command{Use: "preview", Short: "현재 revision의 롤백 범위와 역순 실행 순서를 읽기 전용으로 계산합니다", Args: cobra.NoArgs}
	previewItem := &cobra.Command{
		Use:   "item RUN_ID CHANGE_SET_ID",
		Short: "선택 항목의 단독 또는 cascade 롤백 범위를 미리 확인합니다",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, arguments []string) error {
			service, err := workflow.OpenRecovery(parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("항목 롤백 미리보기를 준비하지 못했습니다", err)
			}
			value, err := service.PreviewRollbackItem(command.Context(), arguments[0], arguments[1])
			if err != nil {
				return remediationFailure("항목 롤백 범위를 계산하지 못했습니다", err)
			}
			if err := writeRollbackPreview(stdout, value); err != nil {
				return remediationFailure("항목 롤백 미리보기를 출력하지 못했습니다", err)
			}
			cascade := ""
			if value.CascadeRequired {
				cascade = " --cascade"
			}
			if _, err := fmt.Fprintf(stdout, "\n표시된 범위 전체를 승인하려면 다음 형식을 사용하세요.\nopenciip remediate rollback item %s %s --preview-digest %s%s --yes\n", arguments[0], arguments[1], value.PreviewDigest, cascade); err != nil {
				return remediationFailure("항목 롤백 승인 안내를 출력하지 못했습니다", err)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	previewRun := &cobra.Command{
		Use:   "run RUN_ID",
		Short: "실행 전체의 현재 롤백 범위와 역순 실행 순서를 미리 확인합니다",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			service, err := workflow.OpenRecovery(parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("실행 전체 롤백 미리보기를 준비하지 못했습니다", err)
			}
			value, err := service.PreviewRollbackRun(command.Context(), arguments[0])
			if err != nil {
				return remediationFailure("실행 전체 롤백 범위를 계산하지 못했습니다", err)
			}
			if err := writeRollbackPreview(stdout, value); err != nil {
				return remediationFailure("실행 전체 롤백 미리보기를 출력하지 못했습니다", err)
			}
			if _, err := fmt.Fprintf(stdout, "\n표시된 전체 범위를 승인하려면 다음 형식을 사용하세요.\nopenciip remediate rollback run %s --preview-digest %s --yes\n", arguments[0], value.PreviewDigest); err != nil {
				return remediationFailure("실행 전체 롤백 승인 안내를 출력하지 못했습니다", err)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	preview.AddCommand(previewItem, previewRun)

	var itemCascade, itemConfirmed bool
	var itemPreviewDigest string
	item := &cobra.Command{
		Use:   "item RUN_ID CHANGE_SET_ID",
		Short: "digest로 승인한 항목 롤백 범위를 실행합니다",
		Args:  cobra.ExactArgs(2),
		RunE: func(command *cobra.Command, arguments []string) error {
			if !itemConfirmed || !isSHA256Digest(itemPreviewDigest) {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("항목 롤백은 미리보기의 --preview-digest와 --yes를 모두 지정해야 합니다")}
			}
			service, err := workflow.OpenRecovery(parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("항목 롤백을 준비하지 못했습니다", err)
			}
			attempt, rollbackErr := service.RollbackItem(command.Context(), arguments[0], arguments[1], itemCascade, itemPreviewDigest)
			outputErr := writeRollbackAttempt(stdout, attempt)
			if rollbackErr != nil {
				if outputErr != nil {
					return remediationFailure("항목 롤백과 결과 출력에 실패했습니다", fmt.Errorf("%v; 출력 오류: %w", rollbackErr, outputErr))
				}
				return remediationFailure("항목 롤백을 완료하지 못했습니다", rollbackErr)
			}
			if outputErr != nil {
				return remediationFailure("항목 롤백 결과를 출력하지 못했습니다", outputErr)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	item.Flags().StringVar(&itemPreviewDigest, "preview-digest", "", "직전 롤백 미리보기의 SHA-256 digest")
	item.Flags().BoolVar(&itemCascade, "cascade", false, "미리보기에 표시된 공유 자원·의존 항목 확장 범위를 승인합니다")
	item.Flags().BoolVar(&itemConfirmed, "yes", false, "미리보기에 표시된 롤백 범위와 순서를 확인합니다")

	var runConfirmed bool
	var runPreviewDigest string
	run := &cobra.Command{
		Use:   "run RUN_ID",
		Short: "digest로 승인한 실행 전체 역순 롤백을 수행합니다",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			if !runConfirmed || !isSHA256Digest(runPreviewDigest) {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("실행 전체 롤백은 미리보기의 --preview-digest와 --yes를 모두 지정해야 합니다")}
			}
			service, err := workflow.OpenRecovery(parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("실행 전체 롤백을 준비하지 못했습니다", err)
			}
			attempt, rollbackErr := service.RollbackRun(command.Context(), arguments[0], runPreviewDigest)
			outputErr := writeRollbackAttempt(stdout, attempt)
			if rollbackErr != nil {
				if outputErr != nil {
					return remediationFailure("실행 전체 롤백과 결과 출력에 실패했습니다", fmt.Errorf("%v; 출력 오류: %w", rollbackErr, outputErr))
				}
				return remediationFailure("실행 전체 롤백을 완료하지 못했습니다", rollbackErr)
			}
			if outputErr != nil {
				return remediationFailure("실행 전체 롤백 결과를 출력하지 못했습니다", outputErr)
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	run.Flags().StringVar(&runPreviewDigest, "preview-digest", "", "직전 실행 전체 롤백 미리보기의 SHA-256 digest")
	run.Flags().BoolVar(&runConfirmed, "yes", false, "미리보기에 표시된 실행 전체 롤백 범위와 순서를 확인합니다")
	command.AddCommand(preview, item, run)
	return command
}

func newRemediationRecoverCommand(stdout io.Writer, resultCode *int, parent *remediationCommandOptions) *cobra.Command {
	var confirmed bool
	command := &cobra.Command{
		Use:   "recover RUN_ID",
		Short: "중단된 실행을 실제 파일 상태와 대조해 저널을 정합화합니다",
		Args:  cobra.ExactArgs(1),
		RunE: func(command *cobra.Command, arguments []string) error {
			if !confirmed {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("복구 정합화는 저널 상태를 갱신할 수 있으므로 --yes를 명시해야 합니다")}
			}
			service, err := workflow.OpenRecovery(parent.stateDirectory, "/")
			if err != nil {
				return remediationFailure("복구 판정을 준비하지 못했습니다", err)
			}
			assessment, err := service.Recover(command.Context(), arguments[0])
			if err != nil {
				return remediationFailure("복구 상태를 판정하지 못했습니다", err)
			}
			if _, err := fmt.Fprintf(stdout, "실행 ID: %s\n마지막 유효 revision: %d\n자동 롤백 가능: %t\n", assessment.RunID, assessment.LastValidRevision, assessment.AutomaticRollbackPossible); err != nil {
				return remediationFailure("복구 판정 결과를 출력하지 못했습니다", err)
			}
			for _, values := range []struct {
				title string
				items []string
			}{
				{title: "적용 확인", items: assessment.ConfirmedApplied},
				{title: "롤백 확인", items: assessment.ConfirmedRolledBack},
				{title: "미적용", items: assessment.NotApplied},
				{title: "모호", items: assessment.Ambiguous},
				{title: "판정 근거", items: assessment.Reasons},
			} {
				if err := writeStringList(stdout, values.title, values.items); err != nil {
					return remediationFailure("복구 판정 결과를 출력하지 못했습니다", err)
				}
			}
			*resultCode = exitcode.OK
			return nil
		},
	}
	command.Flags().BoolVar(&confirmed, "yes", false, "현재 파일 상태를 기준으로 복구 저널을 정합화하는 것을 확인합니다")
	return command
}

func writeRemediationPlan(output io.Writer, planned workflow.PlanResult) error {
	if planned.Journal == nil {
		return fmt.Errorf("생성된 조치 저널이 없습니다")
	}
	value := planned.Journal
	if _, err := fmt.Fprintf(output, "조치 dry-run 계획\n실행 ID: %s\n점검 실행 ID: %s\n상태: %s\n실패 정책: %s\nplan digest: %s\n\n", value.RunID, value.ScanRunID, value.State, value.FailurePolicy, value.PlanDigest); err != nil {
		return err
	}
	for _, changeSet := range value.ChangeSets {
		if _, err := fmt.Fprintf(output, "[%s] %s (%s)\n예상 영향: %s\ndry-run:\n%s\n롤백 그룹: %s\n\n", changeSet.RuleID, changeSet.ID, changeSet.Risk, changeSet.ExpectedImpact, changeSet.DryRun, emptyAsNone(changeSet.RollbackGroup)); err != nil {
			return err
		}
	}
	if err := writeStringList(output, "포함 항목", planned.Included); err != nil {
		return err
	}
	if err := writeStringList(output, "제외 항목", planned.Skipped); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "\n이 계획은 아직 승인되지 않았으며 시스템을 변경하지 않았습니다.\n승인하려면 plan digest를 다시 확인한 뒤 다음 형식을 사용하세요.\nopenciip remediate approve %s --plan-digest %s --yes\n", value.RunID, value.PlanDigest)
	return err
}

func writeRemediationStatus(output io.Writer, value *model.RemediationJournal) error {
	if value == nil {
		return fmt.Errorf("조치 저널이 없습니다")
	}
	if _, err := fmt.Fprintf(output, "실행 ID: %s\n점검 실행 ID: %s\nrevision: %d\n상태: %s\n실패 정책: %s\nplan digest: %s\n", value.RunID, value.ScanRunID, value.Revision, value.State, value.FailurePolicy, value.PlanDigest); err != nil {
		return err
	}
	for _, changeSet := range value.ChangeSets {
		if _, err := fmt.Fprintf(output, "- %s %s: %s\n", changeSet.RuleID, changeSet.ID, changeSet.State); err != nil {
			return err
		}
	}
	return writeStringList(output, "미해결 변경 세트", value.UnresolvedChangeSets)
}

func writeRollbackPreview(output io.Writer, value orchestrator.RollbackPreview) error {
	if value.RunID == "" || !isSHA256Digest(value.PreviewDigest) {
		return fmt.Errorf("유효한 롤백 미리보기가 없습니다")
	}
	if _, err := fmt.Fprintf(output, "롤백 미리보기\n실행 ID: %s\nrevision: %d\ncascade 필요: %t\npreview digest: %s\n", value.RunID, value.Revision, value.CascadeRequired, value.PreviewDigest); err != nil {
		return err
	}
	for _, values := range []struct {
		title string
		items []string
	}{
		{title: "요청 변경 세트", items: value.RequestedChangeSets},
		{title: "실제 롤백 범위", items: value.ExpandedChangeSets},
	} {
		if err := writeStringList(output, values.title, values.items); err != nil {
			return err
		}
	}
	return writeOrderedStringList(output, "롤백 실행 순서", value.ExecutionOrder)
}

func writeRollbackAttempt(output io.Writer, attempt model.RollbackAttempt) error {
	if attempt.ID == "" {
		return nil
	}
	if _, err := fmt.Fprintf(output, "롤백 시도: %s\n범위: %s\n결과: %s\n", attempt.ID, attempt.Scope, emptyAsNone(string(attempt.Outcome))); err != nil {
		return err
	}
	if err := writeStringList(output, "요청 변경 세트", attempt.RequestedChangeSets); err != nil {
		return err
	}
	if err := writeStringList(output, "확장 변경 세트", attempt.ExpandedChangeSets); err != nil {
		return err
	}
	if len(attempt.Errors) > 0 {
		errors := make([]string, 0, len(attempt.Errors))
		for _, item := range attempt.Errors {
			errors = append(errors, fmt.Sprintf("%s: %s", item.Code, item.Message))
		}
		if err := writeStringList(output, "롤백 오류", errors); err != nil {
			return err
		}
	}
	return nil
}

func writeStringList(output io.Writer, title string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	values = append([]string(nil), values...)
	sort.Strings(values)
	if _, err := fmt.Fprintf(output, "%s:\n", title); err != nil {
		return err
	}
	for _, value := range values {
		if _, err := fmt.Fprintf(output, "- %s\n", value); err != nil {
			return err
		}
	}
	return nil
}

func writeOrderedStringList(output io.Writer, title string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(output, "%s:\n", title); err != nil {
		return err
	}
	for index, value := range values {
		if _, err := fmt.Fprintf(output, "%d. %s\n", index+1, value); err != nil {
			return err
		}
	}
	return nil
}

func remediationFailure(message string, err error) error {
	return &commandError{code: exitcode.Error, err: fmt.Errorf("%s: %w", message, err)}
}

func isSHA256Digest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func emptyAsNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "없음"
	}
	return value
}
