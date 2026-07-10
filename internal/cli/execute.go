package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yesidodo73/OpenCIIP/internal/app"
	"github.com/yesidodo73/OpenCIIP/internal/buildinfo"
	"github.com/yesidodo73/OpenCIIP/internal/engine"
	"github.com/yesidodo73/OpenCIIP/internal/exitcode"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	remediationworkflow "github.com/yesidodo73/OpenCIIP/internal/remediation/workflow"
	"github.com/yesidodo73/OpenCIIP/internal/report"
	"github.com/yesidodo73/OpenCIIP/internal/tui"
)

func Execute(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	resultCode := exitcode.OK
	command := newRootCommand(stdin, stdout, stderr, &resultCode)
	command.SetArgs(args)
	command.SetContext(ctx)

	if err := command.Execute(); err != nil {
		var failure *commandError
		if errors.As(err, &failure) {
			_, _ = fmt.Fprintln(stderr, failure.err)
			return failure.code
		}
		_, _ = fmt.Fprintln(stderr, err)
		return exitcode.Usage
	}
	return resultCode
}

func newRootCommand(stdin io.Reader, stdout, stderr io.Writer, resultCode *int) *cobra.Command {
	command := &cobra.Command{
		Use:           "openciip",
		Short:         "주요정보통신기반시설 기술적 취약점 점검 도구",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(command *cobra.Command, _ []string) error {
			if !isInteractive(stdin, stdout) {
				return &commandError{code: exitcode.Usage, err: fmt.Errorf("대화형 터미널이 아닙니다. 자동화 환경에서는 openciip scan을 사용하십시오")}
			}
			application, err := app.NewDefault(command.Context())
			if err != nil {
				return &commandError{code: exitcode.Error, err: fmt.Errorf("점검을 준비하지 못했습니다: %w", err)}
			}
			defer application.Close()
			writer, err := report.NewWriter("reports")
			if err != nil {
				return &commandError{code: exitcode.Error, err: fmt.Errorf("보고서 저장 경로를 준비하지 못했습니다: %w", err)}
			}
			factory := func(ctx context.Context) (tui.Remediator, error) {
				return remediationworkflow.New(ctx, defaultRemediationStateDirectory, "/")
			}
			code, err := tui.RunWithRemediation(command.Context(), stdin, stdout, application, writer, factory)
			if err != nil {
				return &commandError{code: exitcode.Error, err: fmt.Errorf("TUI를 실행하지 못했습니다: %w", err)}
			}
			*resultCode = code
			return nil
		},
	}
	command.SetIn(stdin)
	command.SetOut(stdout)
	command.SetErr(stderr)
	command.AddCommand(newScanCommand(stdout, resultCode))
	command.AddCommand(newRemediateCommand(stdout, resultCode))
	command.AddCommand(newVersionCommand(stdout))
	return command
}

func newVersionCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "버전 정보를 표시합니다",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			info := buildinfo.Current()
			_, _ = fmt.Fprintf(stdout, "OpenCIIP %s\ncommit: %s\nbuild date: %s\n", info.Version, info.Commit, info.BuildDate)
		},
	}
}

type scanOptions struct {
	profiles   []string
	checks     []string
	categories []string
	severities []string
	evidence   string
	reportDir  string
	all        bool
	quiet      bool
	noColor    bool
	noRedact   bool
}

func newScanCommand(stdout io.Writer, resultCode *int) *cobra.Command {
	options := scanOptions{}
	command := &cobra.Command{
		Use:   "scan",
		Short: "시스템의 기술적 취약점을 읽기 전용으로 점검합니다",
		Args:  cobra.NoArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			selection, err := parseSelection(options)
			if err != nil {
				return &commandError{code: exitcode.Usage, err: err}
			}
			application, err := app.NewDefault(command.Context())
			if err != nil {
				return &commandError{code: exitcode.Error, err: fmt.Errorf("점검을 준비하지 못했습니다: %w", err)}
			}
			defer application.Close()
			run, err := application.Scan(command.Context(), engine.Options{
				Selection:    selection,
				EvidenceMode: options.evidence,
				NoRedact:     options.noRedact,
			})
			if err != nil {
				if errors.Is(err, engine.ErrInvalidSelection) || errors.Is(err, engine.ErrInvalidOption) {
					return &commandError{code: exitcode.Usage, err: fmt.Errorf("점검 실행 옵션이 올바르지 않습니다: %w", err)}
				}
				return &commandError{code: exitcode.Error, err: fmt.Errorf("점검을 완료하지 못했습니다: %w", err)}
			}
			writer, err := report.NewWriter(options.reportDir)
			if err != nil {
				return &commandError{code: exitcode.Error, err: fmt.Errorf("보고서 저장 경로를 준비하지 못했습니다: %w", err)}
			}
			reportPath, err := writer.WriteScan(command.Context(), run)
			if err != nil {
				return &commandError{code: exitcode.Error, err: fmt.Errorf("보고서를 저장하지 못했습니다: %w", err)}
			}
			if err := report.WriteTerminal(stdout, run, report.TerminalOptions{
				All:   options.all,
				Quiet: options.quiet,
				Color: supportsColor(stdout) && !options.noColor,
			}); err != nil {
				return &commandError{code: exitcode.Error, err: fmt.Errorf("점검 결과를 출력하지 못했습니다: %w", err)}
			}
			if options.quiet {
				_, _ = fmt.Fprintf(stdout, "REPORT %s\n", reportPath)
			} else {
				_, _ = fmt.Fprintf(stdout, "\n보고서: %s\n", reportPath)
			}
			*resultCode = run.Metadata.ExitCode
			return nil
		},
	}
	flags := command.Flags()
	flags.StringSliceVar(&options.profiles, "profile", nil, "실행할 점검 프로필")
	flags.StringSliceVar(&options.checks, "check", nil, "실행할 점검 항목 코드")
	flags.StringSliceVar(&options.categories, "category", nil, "점검 분류")
	flags.StringSliceVar(&options.severities, "severity", nil, "중요도")
	flags.StringVar(&options.evidence, "evidence", "problems", "증적 저장 범위: problems, all, none")
	flags.StringVar(&options.reportDir, "report-dir", "reports", "보고서 저장 디렉터리")
	flags.BoolVar(&options.all, "all", false, "정상 항목을 포함한 모든 결과를 표시합니다")
	flags.BoolVar(&options.quiet, "quiet", false, "최소 결과만 표시합니다")
	flags.BoolVar(&options.noColor, "no-color", false, "색상 출력을 사용하지 않습니다")
	flags.BoolVar(&options.noRedact, "no-redact", false, "보고서 민감정보 마스킹을 해제합니다")
	return command
}

func parseSelection(options scanOptions) (model.Selection, error) {
	selection := model.Selection{
		Profiles: append([]string(nil), options.profiles...),
		RuleIDs:  append([]string(nil), options.checks...),
	}
	for _, value := range options.categories {
		normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), "-", "_")
		category := model.Category(normalized)
		if !category.Valid() {
			return model.Selection{}, fmt.Errorf("지원하지 않는 점검 분류입니다: %s", value)
		}
		selection.Categories = append(selection.Categories, category)
	}
	for _, value := range options.severities {
		severity := model.Severity(strings.ToLower(strings.TrimSpace(value)))
		if !severity.Valid() {
			return model.Selection{}, fmt.Errorf("지원하지 않는 중요도입니다: %s", value)
		}
		selection.Severities = append(selection.Severities, severity)
	}
	return selection, nil
}

func supportsColor(output io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func isInteractive(input io.Reader, output io.Writer) bool {
	inputFile, inputOK := input.(*os.File)
	outputFile, outputOK := output.(*os.File)
	if !inputOK || !outputOK {
		return false
	}
	inputInfo, inputErr := inputFile.Stat()
	outputInfo, outputErr := outputFile.Stat()
	return inputErr == nil && outputErr == nil && inputInfo.Mode()&os.ModeCharDevice != 0 && outputInfo.Mode()&os.ModeCharDevice != 0
}

type commandError struct {
	code int
	err  error
}

func (e *commandError) Error() string { return e.err.Error() }
func (e *commandError) Unwrap() error { return e.err }
