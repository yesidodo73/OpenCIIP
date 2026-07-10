package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type TerminalOptions struct {
	All   bool
	Quiet bool
	Color bool
}

func WriteTerminal(output io.Writer, run model.ScanRun, options TerminalOptions) error {
	if !options.Quiet {
		if _, err := fmt.Fprintf(output, "OpenCIIP 점검 결과 - %s (%s %s)\n\n", run.Metadata.Platform.Hostname, run.Metadata.Platform.Name, run.Metadata.Platform.VersionID); err != nil {
			return err
		}
	}
	visible := 0
	for _, result := range run.Results {
		if !options.All && result.Status != model.StatusFail && result.Status != model.StatusUnknown && result.Status != model.StatusError {
			continue
		}
		visible++
		status := colorStatus(result.Status, options.Color)
		if options.Quiet {
			if _, err := fmt.Fprintf(output, "%s %s %s\n", status, result.RuleID, result.Title); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(output, "%-20s %-5s %s\n", status, result.RuleID, result.Title); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(output, "  %s\n", result.Summary); err != nil {
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
	for _, status := range orderedStatuses() {
		if _, err := fmt.Fprintf(output, "%s=%d ", status, run.Metadata.Counts[status]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(output); err != nil {
		return err
	}
	for _, warning := range run.Metadata.Warnings {
		if strings.TrimSpace(warning) == "" {
			continue
		}
		if _, err := fmt.Fprintf(output, "주의: %s\n", warning); err != nil {
			return err
		}
	}
	return nil
}

func colorStatus(status model.Status, enabled bool) string {
	if !enabled {
		return string(status)
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
	return color + string(status) + "\x1b[0m"
}
