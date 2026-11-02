package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/presentation"
	"github.com/yesidodo73/OpenCIIP/internal/redact"
)

type TerminalOptions struct {
	All   bool
	Quiet bool
	Color bool
}

func WriteTerminal(output io.Writer, run model.ScanRun, options TerminalOptions) error {
	if run.Metadata.Redaction {
		run = redact.ScanRun(run)
	}
	if !options.Quiet {
		if _, err := fmt.Fprintf(
			output,
			"OpenCIIP 점검 결과 - %s (%s)\n점검 상태: %s\n\n",
			presentation.Sanitize(run.Metadata.Platform.Hostname),
			presentation.Sanitize(platformDisplayName(run.Metadata.Platform)),
			scanSupportLabel(run.Metadata.Platform.ScanSupport),
		); err != nil {
			return err
		}
	}
	visible := 0
	for _, result := range model.SortedResultsByStatus(run.Results) {
		if !options.All && result.Status != model.StatusFail && result.Status != model.StatusUnknown && result.Status != model.StatusError {
			continue
		}
		visible++
		status := colorStatus(result.Status, options.Color)
		ruleID := presentation.Sanitize(result.RuleID)
		title := presentation.Sanitize(result.Title)
		if options.Quiet {
			if _, err := fmt.Fprintf(output, "%s %s %s\n", status, ruleID, title); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(output, "%-20s %-5s %s\n", status, ruleID, title); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "  %s\n", presentation.Sanitize(result.Summary)); err != nil {
			return err
		}
	}
	if visible == 0 {
		if _, err := fmt.Fprintln(output, "문제가 발견된 항목이 없습니다."); err != nil {
			return err
		}
	}
	if options.Quiet {
		return nil
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	statusParts := make([]string, 0, 6)
	for _, status := range orderedStatuses() {
		statusParts = append(statusParts, fmt.Sprintf("%s=%d", statusDisplayLabel(status), run.Metadata.Counts[status]))
	}
	if _, err := fmt.Fprintln(output, strings.Join(statusParts, " ")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	for _, warning := range run.Metadata.Warnings {
		if strings.TrimSpace(warning) == "" {
			continue
		}
		if _, err := fmt.Fprintf(output, "주의: %s\n", presentation.Sanitize(warning)); err != nil {
			return err
		}
	}
	return nil
}

func platformDisplayName(platform model.PlatformInfo) string {
	name := strings.TrimSpace(platform.Name)
	version := strings.TrimSpace(platform.VersionID)
	if name == "" {
		return version
	}
	if version == "" || version == "unknown" || containsVersionToken(name, version, true) {
		return name
	}

	parts := strings.Split(version, ".")
	for count := len(parts) - 1; count >= 1; count-- {
		prefix := strings.Join(parts[:count], ".")
		if start := versionTokenIndex(name, prefix, false); start >= 0 {
			return name[:start] + version + name[start+len(prefix):]
		}
	}
	return name + " " + version
}

func containsVersionToken(value, version string, allowMoreSpecificSuffix bool) bool {
	return versionTokenIndex(value, version, allowMoreSpecificSuffix) >= 0
}

func versionTokenIndex(value, version string, allowMoreSpecificSuffix bool) int {
	for offset := 0; offset <= len(value)-len(version); {
		relative := strings.Index(value[offset:], version)
		if relative < 0 {
			return -1
		}
		start := offset + relative
		end := start + len(version)
		leftBoundary := start == 0 || !isVersionCharacter(value[start-1])
		rightBoundary := end == len(value) || !isVersionCharacter(value[end])
		if allowMoreSpecificSuffix && end < len(value) && value[end] == '.' {
			rightBoundary = true
		}
		if leftBoundary && rightBoundary {
			return start
		}
		offset = start + 1
	}
	return -1
}

func isVersionCharacter(value byte) bool {
	return value >= '0' && value <= '9' || value == '.'
}

func scanSupportLabel(level model.ScanSupportLevel) string {
	switch level {
	case model.ScanSupportTested:
		return "테스트 완료 환경"
	case model.ScanSupportSupported:
		return "Linux 공통 점검"
	default:
		return "지원 대상 아님"
	}
}

func colorStatus(status model.Status, enabled bool) string {
	label := statusDisplayLabel(status)
	if !enabled {
		return label
	}
	color := "\x1b[37m"
	switch status {
	case model.StatusPass:
		color = "\x1b[32m"
	case model.StatusFail, model.StatusError:
		color = "\x1b[31m"
	case model.StatusUnknown:
		color = "\x1b[33m"
	case model.StatusNotApplicable, model.StatusSkipped:
		color = "\x1b[90m"
	}
	return color + label + "\x1b[0m"
}

func statusDisplayLabel(status model.Status) string {
	switch status {
	case model.StatusFail:
		return "취약"
	case model.StatusUnknown:
		return "수동 확인 필요"
	case model.StatusError:
		return "확인 실패"
	case model.StatusPass:
		return "양호"
	case model.StatusNotApplicable:
		return "해당 없음"
	case model.StatusSkipped:
		return "점검하지 않음"
	default:
		return presentation.Sanitize(string(status))
	}
}
