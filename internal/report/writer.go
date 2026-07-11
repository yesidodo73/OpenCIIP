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

	"github.com/yesidodo73/OpenCIIP/internal/model"
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

	name := reportDirectoryName(run.Metadata)
	partial := "." + name + ".partial"
	if err := base.Mkdir(partial, 0o700); err != nil {
		return "", fmt.Errorf("create report directory: %w", err)
	}
	runRoot, err := base.OpenRoot(partial)
	if err != nil {
		return "", fmt.Errorf("open partial report directory: %w", err)
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
	if directory, err := base.Open("."); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
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
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("report root must not be writable by group or other users: %s", path)
	}
	if err := validateReportAncestorChain(filepath.Dir(path)); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != filepath.Clean(path) {
		if err == nil {
			err = fmt.Errorf("path contains a symbolic link")
		}
		return fmt.Errorf("resolve report root: %w", err)
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
		if inspectErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("ancestor is not a real, non-writable directory")
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
	fmt.Fprintf(&builder, "가이드 연도: %d\n", run.Metadata.GuideYear)
	fmt.Fprintf(&builder, "대상: %s (%s %s, %s)\n", run.Metadata.Platform.Hostname, run.Metadata.Platform.Name, run.Metadata.Platform.VersionID, run.Metadata.Platform.Architecture)
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
	return builder.String()
}

func renderProblems(run model.ScanRun) string {
	var builder strings.Builder
	problemCount := 0
	for _, result := range model.SortedResultsByStatus(run.Results) {
		if result.Status != model.StatusFail && result.Status != model.StatusUnknown && result.Status != model.StatusError {
			continue
		}
		problemCount++
		fmt.Fprintf(&builder, "[%s] %s %s\n", result.Status, result.RuleID, result.Title)
		fmt.Fprintf(&builder, "중요도: %s\n", result.Severity)
		fmt.Fprintf(&builder, "플랫폼 검증 상태: %s\n", result.Verification.State)
		fmt.Fprintf(&builder, "결과: %s\n", result.Summary)
		if result.Observed != "" {
			fmt.Fprintf(&builder, "확인값: %s\n", result.Observed)
		}
		if result.UnknownReason != "" {
			fmt.Fprintf(&builder, "확정 불가 사유: %s\n", result.UnknownReason)
		}
		if result.ErrorCode != "" {
			fmt.Fprintf(&builder, "오류 코드: %s\n", result.ErrorCode)
		}
		fmt.Fprintf(&builder, "가이드 근거: %s, %v쪽\n\n", result.Reference.Section, result.Reference.Pages)
	}
	if problemCount == 0 {
		builder.WriteString("문제가 발견된 항목이 없습니다.\n")
	}
	return builder.String()
}

func renderEvidence(result model.CheckResult) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s %s\n", result.RuleID, result.Title)
	fmt.Fprintf(&builder, "상태: %s\n", statusDisplayLabel(result.Status))
	fmt.Fprintf(&builder, "플랫폼 검증 상태: %s\n", result.Verification.State)
	if len(result.BindingSources) > 0 {
		fmt.Fprintf(&builder, "규칙 계층: %s\n", strings.Join(result.BindingSources, " → "))
	}
	fmt.Fprintf(&builder, "판정 이유: %s\n", result.Summary)
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
	return builder.String()
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
