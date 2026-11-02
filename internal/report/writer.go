package report

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/charmbracelet/x/ansi"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
	"github.com/yesidodo73/OpenCIIP/internal/redact"
)

type Writer struct {
	basePath string
	baseInfo os.FileInfo
}

func NewWriter(basePath string) (*Writer, error) {
	if strings.TrimSpace(basePath) == "" {
		basePath = DefaultDirectory()
	}
	absolute, err := filepath.Abs(basePath)
	if err != nil {
		return nil, fmt.Errorf("resolve report directory: %w", err)
	}
	info, err := ensureBaseDirectory(absolute)
	if err != nil {
		return nil, err
	}
	return &Writer{basePath: absolute, baseInfo: info}, nil
}

func DefaultDirectory() string {
	absolute, err := filepath.Abs("reports")
	if err == nil {
		return absolute
	}
	return filepath.Join(string(os.PathSeparator), "reports")
}

func (w *Writer) WriteScan(ctx context.Context, run model.ScanRun) (string, error) {
	if run.Metadata.Redaction {
		run = redact.ScanRun(run)
	}
	run.Results = model.SortedResultsByStatus(run.Results)
	base, err := os.OpenRoot(w.basePath)
	if err != nil {
		return "", fmt.Errorf("open report root: %w", err)
	}
	defer base.Close()
	openedBase, err := base.Stat(".")
	if err != nil || w.baseInfo == nil || !openedBase.IsDir() || !os.SameFile(w.baseInfo, openedBase) {
		if err == nil {
			err = fmt.Errorf("report root changed after initialization")
		}
		return "", fmt.Errorf("verify report root: %w", err)
	}
	if err := validateReportDirectory(w.basePath, openedBase); err != nil {
		return "", fmt.Errorf("verify report root: %w", err)
	}

	name := reportDirectoryName(run.Metadata)
	partial := "." + name + ".partial"
	if err := base.Mkdir(partial, 0o700); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	partialInfo, err := base.Lstat(partial)
	if err != nil {
		return "", fmt.Errorf("inspect partial report directory: %w", err)
	}
	if err := validatePrivateReportDirectory(filepath.Join(w.basePath, partial), partialInfo); err != nil {
		return "", err
	}
	runRoot, err := base.OpenRoot(partial)
	if err != nil {
		return "", fmt.Errorf("open partial report directory: %w", err)
	}
	openedPartial, err := runRoot.Stat(".")
	if err != nil || !os.SameFile(partialInfo, openedPartial) {
		_ = runRoot.Close()
		if err == nil {
			err = fmt.Errorf("partial report directory changed while opening")
		}
		return "", fmt.Errorf("verify partial report directory: %w", err)
	}
	writeErr := w.writeScanFiles(ctx, runRoot, run)
	closeErr := runRoot.Close()
	if writeErr != nil {
		return filepath.Join(w.basePath, partial), writeErr
	}
	if closeErr != nil {
		return filepath.Join(w.basePath, partial), fmt.Errorf("close partial report directory: %w", closeErr)
	}
	if err := base.Rename(partial, name); err != nil {
		return filepath.Join(w.basePath, partial), fmt.Errorf("finalize report directory: %w", err)
	}
	finalInfo, err := base.Lstat(name)
	if err != nil || !os.SameFile(partialInfo, finalInfo) {
		if err == nil {
			err = fmt.Errorf("final report directory changed while renaming")
		}
		return filepath.Join(w.basePath, name), fmt.Errorf("verify final report directory: %w", err)
	}
	if err := validatePrivateReportDirectory(filepath.Join(w.basePath, name), finalInfo); err != nil {
		return filepath.Join(w.basePath, name), err
	}
	if directory, err := base.Open("."); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	currentBase, err := os.Lstat(w.basePath)
	if err != nil || !os.SameFile(w.baseInfo, currentBase) {
		if err == nil {
			err = fmt.Errorf("report root changed while writing")
		}
		return filepath.Join(w.basePath, name), fmt.Errorf("verify report root after writing: %w", err)
	}
	if err := validateReportDirectory(w.basePath, currentBase); err != nil {
		return filepath.Join(w.basePath, name), fmt.Errorf("verify report root after writing: %w", err)
	}
	return filepath.Join(w.basePath, name), nil
}

func (w *Writer) writeScanFiles(ctx context.Context, root *os.Root, run model.ScanRun) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	metadata, err := marshalJSON(run.Metadata)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}
	results, err := marshalJSON(run.Results)
	if err != nil {
		return fmt.Errorf("encode results: %w", err)
	}
	files := []struct {
		name string
		data []byte
	}{
		{name: "summary.txt", data: []byte(renderSummary(run))},
		{name: "failures.txt", data: []byte(renderProblems(run))},
		{name: "metadata.json", data: metadata},
		{name: "results.json", data: results},
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := atomicWrite(root, file.name, file.data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", file.name, err)
		}
	}
	for _, result := range run.Results {
		if len(result.Evidence) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		directory := "evidence/" + string(result.Category)
		if err := root.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create evidence directory %s: %w", directory, err)
		}
		path := directory + "/" + result.RuleID + ".txt"
		if err := atomicWrite(root, path, []byte(renderEvidence(result)), 0o600); err != nil {
			return fmt.Errorf("write evidence %s: %w", result.RuleID, err)
		}
	}
	return nil
}

func ensureBaseDirectory(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if err := validateReportDirectory(path, info); err != nil {
			return nil, err
		}
		return info, nil
	case errors.Is(err, os.ErrNotExist):
		parentPath := filepath.Dir(path)
		name := filepath.Base(path)
		parentInfo, inspectErr := os.Lstat(parentPath)
		if inspectErr != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("parent is not a real directory")
			}
			return nil, fmt.Errorf("inspect report root parent: %w", inspectErr)
		}
		resolvedParent, resolveErr := filepath.EvalSymlinks(parentPath)
		if resolveErr != nil || filepath.Clean(resolvedParent) != filepath.Clean(parentPath) {
			if resolveErr == nil {
				resolveErr = fmt.Errorf("parent path contains a symbolic link")
			}
			return nil, fmt.Errorf("resolve report root parent: %w", resolveErr)
		}
		parent, openErr := os.OpenRoot(parentPath)
		if openErr != nil {
			return nil, fmt.Errorf("open report root parent: %w", openErr)
		}
		defer parent.Close()
		openedParent, statErr := parent.Stat(".")
		if statErr != nil || !os.SameFile(parentInfo, openedParent) {
			if statErr == nil {
				statErr = fmt.Errorf("parent directory changed while opening")
			}
			return nil, fmt.Errorf("verify report root parent: %w", statErr)
		}
		if err := parent.Mkdir(name, 0o700); err != nil {
			return nil, fmt.Errorf("create report root: %w", err)
		}
		created, inspectErr := parent.Lstat(name)
		if inspectErr != nil {
			return nil, fmt.Errorf("inspect created report root: %w", inspectErr)
		}
		if err := validateReportDirectory(path, created); err != nil {
			return nil, err
		}
		opened, openErr := parent.OpenRoot(name)
		if openErr != nil {
			return nil, fmt.Errorf("open created report root: %w", openErr)
		}
		openedInfo, statErr := opened.Stat(".")
		closeErr := opened.Close()
		if statErr != nil || !os.SameFile(created, openedInfo) {
			if statErr == nil {
				statErr = fmt.Errorf("created report root changed while opening")
			}
			return nil, fmt.Errorf("verify created report root: %w", statErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close created report root: %w", closeErr)
		}
		directory, syncErr := parent.Open(".")
		if syncErr != nil {
			return nil, fmt.Errorf("open report root parent for sync: %w", syncErr)
		}
		syncErr = directory.Sync()
		closeDirectoryErr := directory.Close()
		if syncErr != nil {
			return nil, fmt.Errorf("sync report root parent: %w", syncErr)
		}
		if closeDirectoryErr != nil {
			return nil, fmt.Errorf("close report root parent: %w", closeDirectoryErr)
		}
		return created, nil
	default:
		return nil, fmt.Errorf("inspect report root: %w", err)
	}
}

func validateReportDirectory(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("report root must be a real directory: %s", path)
	}
	if err := validateReportDirectoryAccess(path, info); err != nil {
		return err
	}
	if err := validateReportAncestorChain(filepath.Dir(path)); err != nil {
		return err
	}
	if err := validateReportDirectoryPath(path); err != nil {
		return err
	}
	return nil
}

func validateReportAncestorChain(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve report root ancestor: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	current := volume + string(filepath.Separator)
	relative := strings.TrimPrefix(filepath.Clean(absolute), current)
	if relative == filepath.Clean(absolute) {
		current = string(filepath.Separator)
		relative = strings.TrimPrefix(filepath.Clean(absolute), current)
	}
	components := strings.Split(relative, string(filepath.Separator))
	paths := []string{current}
	for _, component := range components {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		paths = append(paths, current)
	}
	for _, candidate := range paths {
		info, inspectErr := os.Lstat(candidate)
		if inspectErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("ancestor is not a real directory")
			}
			return fmt.Errorf("unsafe report root ancestor %s: %w", candidate, inspectErr)
		}
	}
	return nil
}

func atomicWrite(root *os.Root, name string, data []byte, mode os.FileMode) error {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generate temporary file name: %w", err)
	}
	temporary := "." + filepath.Base(name) + ".tmp-" + hex.EncodeToString(suffix)
	directory := filepath.Dir(name)
	if directory != "." {
		temporary = filepath.ToSlash(filepath.Join(directory, temporary))
	}
	file, err := root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = root.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := root.Rename(temporary, filepath.ToSlash(name)); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func marshalJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func reportDirectoryName(metadata model.RunMetadata) string {
	hostname := sanitizeComponent(metadata.Platform.Hostname)
	if hostname == "" {
		hostname = "unknown-host"
	}
	runID := metadata.RunID
	if len(runID) > 12 {
		runID = runID[len(runID)-12:]
	}
	return fmt.Sprintf("%s_%s_%s", metadata.StartedAt.Local().Format("2006-01-02_150405"), hostname, sanitizeComponent(runID))
}

func sanitizeComponent(value string) string {
	var builder strings.Builder
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '.' || character == '-' || character == '_' {
			builder.WriteRune(character)
		} else {
			builder.WriteByte('_')
		}
	}
	return strings.Trim(builder.String(), "._-")
}

func renderSummary(run model.ScanRun) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "OpenCIIP 점검 결과\n")
	fmt.Fprintf(&builder, "실행 ID: %s\n", run.Metadata.RunID)
	fmt.Fprintf(&builder, "도구 버전: %s\n", run.Metadata.ToolVersion)
	fmt.Fprintf(&builder, "도구 커밋: %s\n", run.Metadata.ToolCommit)
	fmt.Fprintf(&builder, "실행 바이너리 SHA-256: %s\n", run.Metadata.ToolExecutableSHA256)
	fmt.Fprintf(&builder, "가이드 연도: %d\n", run.Metadata.GuideYear)
	fmt.Fprintf(&builder, "대상: %s (%s, %s)\n", run.Metadata.Platform.Hostname, platformDisplayName(run.Metadata.Platform), run.Metadata.Platform.Architecture)
	fmt.Fprintf(&builder, "시작 시각: %s\n", run.Metadata.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(&builder, "완료 시각: %s\n", run.Metadata.CompletedAt.Format(time.RFC3339))
	fmt.Fprintf(&builder, "완료 여부: %t\n", run.Metadata.Complete)
	fmt.Fprintf(&builder, "종료 코드: %d\n\n", run.Metadata.ExitCode)
	fmt.Fprintf(&builder, "상태별 합계\n")
	for _, status := range orderedStatuses() {
		fmt.Fprintf(&builder, "- %s: %d\n", statusDisplayLabel(status), run.Metadata.Counts[status])
	}
	if len(run.Metadata.Warnings) > 0 {
		fmt.Fprintf(&builder, "\n주의 사항\n")
		for _, warning := range run.Metadata.Warnings {
			fmt.Fprintf(&builder, "- %s\n", warning)
		}
	}
	return presentation.Sanitize(builder.String())
}

func renderProblems(run model.ScanRun) string {
	var builder strings.Builder
	problemCount := 0
	for _, result := range model.SortedResultsByStatus(run.Results) {
		if result.Status != model.StatusFail && result.Status != model.StatusUnknown && result.Status != model.StatusError {
			continue
		}
		problemCount++
		fmt.Fprintf(&builder, "[%s] %s %s\n", statusDisplayLabel(result.Status), result.RuleID, result.Title)
		fmt.Fprintf(&builder, "중요도: %s\n", result.Severity)
		writeHumanField(&builder, "판정 이유", result.Summary, 0)
		writeHumanAssessment(&builder, result)
		if strings.TrimSpace(result.Solution) != "" {
			writeHumanField(&builder, "조치 방법", result.Solution, 0)
		}
		if result.ErrorCode != "" {
			writeHumanField(&builder, "오류 코드", result.ErrorCode, 0)
		}
		fmt.Fprintf(&builder, "가이드 근거: %s, %v쪽\n\n", result.Reference.Section, result.Reference.Pages)
	}
	if problemCount == 0 {
		builder.WriteString("문제가 발견된 항목이 없습니다.\n")
	}
	return presentation.Sanitize(builder.String())
}

func renderEvidence(result model.CheckResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s %s\n", result.RuleID, result.Title)
	fmt.Fprintf(&builder, "상태: %s\n", statusDisplayLabel(result.Status))
	writeHumanField(&builder, "판정 이유", result.Summary, 0)
	writeHumanAssessment(&builder, result)
	if strings.TrimSpace(result.Solution) != "" {
		writeHumanField(&builder, "조치 방법", result.Solution, 0)
	}
	fmt.Fprintf(&builder, "가이드 근거: %s, %v쪽\n", result.Reference.Section, result.Reference.Pages)
	for index, evidence := range result.Evidence {
		fmt.Fprintf(&builder, "\n[증적 %d]\n", index+1)
		fmt.Fprintf(&builder, "종류: %s\n출처: %s\n수집 시각: %s\n마스킹: %t\n", evidence.Kind, evidence.Source, evidence.CapturedAt.Format(time.RFC3339), evidence.Redacted)
		if evidence.Command != nil {
			fmt.Fprintf(&builder, "실행 파일: %s\n인자: %s\n종료 코드: %d\n실행 시간(ms): %d\n", evidence.Command.Executable, strings.Join(evidence.Command.Arguments, " "), evidence.Command.ExitCode, evidence.Command.DurationMS)
			if evidence.Command.Stdout != "" {
				fmt.Fprintf(&builder, "stdout:\n%s\n", evidence.Command.Stdout)
			}
			if evidence.Command.Stderr != "" {
				fmt.Fprintf(&builder, "stderr:\n%s\n", evidence.Command.Stderr)
			}
		}
		if evidence.File != nil {
			fmt.Fprintf(&builder, "파일: %s\n권한: %s\n소유자: %s\n그룹: %s\n", evidence.File.Path, evidence.File.Mode, evidence.File.Owner, evidence.File.Group)
			if evidence.File.Content != "" {
				fmt.Fprintf(&builder, "내용:\n%s\n", evidence.File.Content)
			}
		}
		if evidence.Fact != nil {
			data, err := json.MarshalIndent(evidence.Fact, "", "  ")
			if err != nil {
				fmt.Fprintf(&builder, "수집 정보: 직렬화할 수 없습니다.\n")
			} else {
				fmt.Fprintf(&builder, "수집 정보:\n%s\n", data)
			}
		}
	}
	return presentation.Sanitize(builder.String())
}

const humanReportWidth = 100

func writeHumanAssessment(builder *strings.Builder, result model.CheckResult) {
	if strings.TrimSpace(result.Expected) != "" {
		writeHumanField(builder, "기준", result.Expected, 0)
	}
	if len(result.DisplayDetails) > 0 {
		builder.WriteString("확인 결과:\n")
		for _, detail := range result.DisplayDetails {
			label := strings.TrimSpace(detail.Label)
			if label == "" {
				label = "판정 결과"
			}
			writeHumanLine(builder, "  - ", label)
			if strings.TrimSpace(detail.Expected) != "" && strings.TrimSpace(detail.Expected) != strings.TrimSpace(result.Expected) {
				writeHumanField(builder, "기준", detail.Expected, 4)
			}
			if strings.TrimSpace(detail.Current) != "" {
				writeHumanField(builder, "현재", detail.Current, 4)
			}
			if strings.TrimSpace(detail.Source) != "" {
				writeHumanField(builder, "위치", detail.Source, 4)
			}
		}
		return
	}
	if strings.TrimSpace(result.Observed) != "" {
		writeHumanField(builder, "확인 결과", result.Observed, 0)
	}
}

func writeHumanField(builder *strings.Builder, label, value string, indent int) {
	items := splitHumanItems(value)
	if len(items) == 0 {
		return
	}
	padding := strings.Repeat(" ", indent)
	if len(items) == 1 {
		writeHumanLine(builder, padding+label+": ", items[0])
		return
	}
	builder.WriteString(padding + label + ":\n")
	for _, item := range items {
		writeHumanLine(builder, padding+"  - ", item)
	}
}

func splitHumanItems(value string) []string {
	value = presentation.Sanitize(value)
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	items := make([]string, 0, len(lines))
	for _, line := range lines {
		for _, item := range strings.Split(line, "; ") {
			if item = strings.TrimSpace(item); item != "" {
				items = append(items, item)
			}
		}
	}
	return items
}

func writeHumanLine(builder *strings.Builder, prefix, value string) {
	prefix = presentation.Sanitize(prefix)
	value = strings.TrimSpace(presentation.Sanitize(value))
	if value == "" {
		return
	}
	available := humanReportWidth - ansi.StringWidth(prefix)
	if available < 20 {
		available = 20
	}
	lines := strings.Split(ansi.Wrap(value, available, ""), "\n")
	continuation := strings.Repeat(" ", ansi.StringWidth(prefix))
	for index, line := range lines {
		if index == 0 {
			builder.WriteString(prefix)
		} else {
			builder.WriteString(continuation)
		}
		builder.WriteString(line)
		builder.WriteByte('\n')
	}
}

func orderedStatuses() []model.Status {
	return []model.Status{
		model.StatusFail,
		model.StatusUnknown,
		model.StatusError,
		model.StatusPass,
		model.StatusNotApplicable,
		model.StatusSkipped,
	}
}
