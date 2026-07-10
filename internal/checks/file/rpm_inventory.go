package filecheck

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const rpmQueryFormatOwnership = "%{NEVRA}\t%{RSAHEADER:pgpsig}\n"

type rpmOwnership struct {
	Owned            bool
	NEVRA            string
	SignaturePresent bool
	SignatureSHA256  string
	Complete         bool
	Evidence         model.Evidence
}

type rpmPackageInspection struct {
	ExpectedFiles  map[string]rpmFileRecord
	ModifiedPaths  map[string]struct{}
	Complete       bool
	ModeEvidence   model.Evidence
	VerifyEvidence model.Evidence
}

type rpmFileRecord struct {
	Mode        uint64
	VerifyFlags uint64
}

func inspectRPMOwnership(ctx context.Context, environment evaluator.Environment, candidate string) (rpmOwnership, error) {
	if !environment.Commands.Available("rpm") {
		return rpmOwnership{Complete: false}, nil
	}
	spec := executor.Spec{
		Name:      "rpm",
		Arguments: []string{"-qf", "--qf", rpmQueryFormatOwnership, "--", candidate},
		Timeout:   20 * time.Second,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return rpmOwnership{}, fmt.Errorf("query RPM owner: %w", err)
	}
	evidence := privateCommandSummary("rpm-file-ownership-command", spec, result)
	if result.Truncated {
		return rpmOwnership{Complete: false, Evidence: evidence}, nil
	}
	if result.ExitCode == 1 {
		if rpmReportsUnowned(result.Stdout, result.Stderr, candidate) {
			return rpmOwnership{Owned: false, Complete: true, Evidence: evidence}, nil
		}
		return rpmOwnership{}, fmt.Errorf("rpm -qf could not distinguish an unowned file from a query error")
	}
	if result.ExitCode != 0 {
		return rpmOwnership{}, fmt.Errorf("rpm -qf exit=%d", result.ExitCode)
	}
	if len(result.Stderr) > 0 {
		return rpmOwnership{}, fmt.Errorf("rpm -qf emitted diagnostics")
	}
	lines := nonEmptyLines(string(result.Stdout))
	if len(lines) != 1 {
		return rpmOwnership{}, fmt.Errorf("rpm owner query returned %d records", len(lines))
	}
	fields := strings.SplitN(lines[0], "\t", 2)
	if len(fields) != 2 || !safeRPMLabel(fields[0]) {
		return rpmOwnership{}, fmt.Errorf("rpm owner query returned an invalid package identity")
	}
	signature := strings.TrimSpace(fields[1])
	signaturePresent := signature != "" && signature != "(none)" && signature != "none"
	return rpmOwnership{
		Owned:            true,
		NEVRA:            fields[0],
		SignaturePresent: signaturePresent,
		SignatureSHA256:  pathDigest(signature),
		Complete:         true,
		Evidence:         evidence,
	}, nil
}

func inspectRPMPackage(ctx context.Context, environment evaluator.Environment, nevra string) (rpmPackageInspection, error) {
	if !safeRPMLabel(nevra) {
		return rpmPackageInspection{}, fmt.Errorf("unsafe RPM package identity")
	}
	modeSpec := executor.Spec{
		Name:      "rpm",
		Arguments: []string{"-q", "--qf", "[%{FILEMODES:octal}\t%{FILEVERIFYFLAGS}\t%{FILENAMES}\n]", "--", nevra},
		Timeout:   30 * time.Second,
		MaxOutput: 8 << 20,
	}
	modeResult, err := environment.Commands.Run(ctx, modeSpec)
	if err != nil {
		return rpmPackageInspection{}, fmt.Errorf("query RPM file modes: %w", err)
	}
	modeEvidence := privateCommandSummary("rpm-package-file-mode-command", modeSpec, modeResult)
	if modeResult.ExitCode != 0 {
		return rpmPackageInspection{}, fmt.Errorf("rpm file mode query exit=%d", modeResult.ExitCode)
	}
	if modeResult.Truncated {
		return rpmPackageInspection{Complete: false, ModeEvidence: modeEvidence}, nil
	}
	if len(modeResult.Stderr) > 0 {
		return rpmPackageInspection{}, fmt.Errorf("rpm file mode query emitted diagnostics")
	}
	files, err := parseRPMFileRecords(string(modeResult.Stdout))
	if err != nil {
		return rpmPackageInspection{}, err
	}

	verifySpec := executor.Spec{
		Name:      "rpm",
		Arguments: []string{"-V", "--nodeps", "--noscripts", "--", nevra},
		Timeout:   2 * time.Minute,
		MaxOutput: 8 << 20,
	}
	verifyResult, err := environment.Commands.Run(ctx, verifySpec)
	if err != nil {
		return rpmPackageInspection{}, fmt.Errorf("verify RPM package: %w", err)
	}
	verifyEvidence := privateCommandSummary("rpm-package-verification-command", verifySpec, verifyResult)
	if verifyResult.ExitCode != 0 && verifyResult.ExitCode != 1 {
		return rpmPackageInspection{}, fmt.Errorf("rpm verification exit=%d", verifyResult.ExitCode)
	}
	if verifyResult.Truncated {
		return rpmPackageInspection{
			ExpectedFiles:  files,
			Complete:       false,
			ModeEvidence:   modeEvidence,
			VerifyEvidence: verifyEvidence,
		}, nil
	}
	verification := nonEmptyLines(string(verifyResult.Stdout))
	if len(verifyResult.Stderr) > 0 {
		return rpmPackageInspection{}, fmt.Errorf("rpm verification emitted diagnostics")
	}
	if (verifyResult.ExitCode == 0 && len(verification) > 0) || (verifyResult.ExitCode == 1 && len(verification) == 0) {
		return rpmPackageInspection{}, fmt.Errorf("rpm verification exit status and output disagree")
	}
	modifiedPaths, parsed, unreadable := parseRPMVerificationPaths(verification, files)
	if unreadable {
		return rpmPackageInspection{}, fmt.Errorf("rpm verification could not read package file metadata")
	}
	if !parsed {
		return rpmPackageInspection{}, fmt.Errorf("rpm verification output could not be mapped to package files")
	}
	return rpmPackageInspection{
		ExpectedFiles:  files,
		ModifiedPaths:  modifiedPaths,
		Complete:       true,
		ModeEvidence:   modeEvidence,
		VerifyEvidence: verifyEvidence,
	}, nil
}

func parseRPMFileRecords(content string) (map[string]rpmFileRecord, error) {
	result := make(map[string]rpmFileRecord)
	for lineNumber, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 || fields[2] == "" || fields[2] != strings.TrimSpace(fields[2]) || strings.ContainsAny(fields[2], "\r\n\t\x00") {
			return nil, fmt.Errorf("RPM file mode line %d is invalid", lineNumber+1)
		}
		mode, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 8, 32)
		if err != nil {
			return nil, fmt.Errorf("RPM file mode line %d: %w", lineNumber+1, err)
		}
		verifyFlags, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("RPM file verify flags line %d: %w", lineNumber+1, err)
		}
		filePath := fields[2]
		if _, duplicate := result[filePath]; duplicate {
			return nil, fmt.Errorf("RPM file mode output contains a duplicate path")
		}
		result[filePath] = rpmFileRecord{Mode: mode, VerifyFlags: verifyFlags}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("RPM file mode output is empty")
	}
	return result, nil
}

func parseRPMVerificationPaths(lines []string, expected map[string]rpmFileRecord) (map[string]struct{}, bool, bool) {
	modified := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		matched := ""
		for filePath := range expected {
			if strings.TrimSpace(line) != filePath && !strings.HasSuffix(line, " "+filePath) {
				continue
			}
			if len(filePath) > len(matched) {
				matched = filePath
			}
		}
		if matched == "" {
			return nil, false, false
		}
		prefix := strings.TrimSuffix(line, matched)
		if strings.Contains(prefix, "?") {
			return nil, false, true
		}
		modified[matched] = struct{}{}
	}
	return modified, true, false
}

func rpmReportsUnowned(stdout, stderr []byte, candidate string) bool {
	expected := "file " + candidate + " is not owned by any package"
	standardOutput := strings.TrimSpace(strings.ReplaceAll(string(stdout), "\r\n", "\n"))
	standardError := strings.TrimSpace(strings.ReplaceAll(string(stderr), "\r\n", "\n"))
	return (standardOutput == expected && standardError == "") || (standardError == expected && standardOutput == "")
}

func safeRPMLabel(value string) bool {
	trimmed := strings.TrimSpace(value)
	return value == trimmed && value != "" && !strings.HasPrefix(value, "-") && !strings.ContainsAny(value, "\x00\r\n\t /\\")
}

func nonEmptyLines(value string) []string {
	lines := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) != "" {
			lines = append(lines, raw)
		}
	}
	return lines
}
