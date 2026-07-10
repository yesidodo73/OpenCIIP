package support

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const maxPAMIncludeDepth = 16

type PAMRule struct {
	Service string
	Path    string
	Line    int
	Type    string
	Control string
	Module  string
	Args    []string
}

func ReadPAMService(ctx context.Context, files system.Reader, service string) ([]PAMRule, []model.Evidence, error) {
	visited := make(map[string]bool)
	return readPAMService(ctx, files, service, visited, 0)
}

func readPAMService(ctx context.Context, files system.Reader, service string, stack map[string]bool, depth int) ([]PAMRule, []model.Evidence, error) {
	if depth > maxPAMIncludeDepth {
		return nil, nil, fmt.Errorf("PAM include depth exceeds %d", maxPAMIncludeDepth)
	}
	if !validPAMServiceName(service) {
		return nil, nil, fmt.Errorf("invalid PAM service name %q", service)
	}
	if stack[service] {
		return nil, nil, fmt.Errorf("PAM include cycle at %s", service)
	}
	stack[service] = true
	defer delete(stack, service)

	path := "/etc/pam.d/" + service
	data, _, err := files.ReadFile(ctx, path, 2<<20)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	logicalLines, err := pamLogicalLines(string(data))
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	rules := make([]PAMRule, 0, len(logicalLines))
	evidenceLines := make([]map[string]any, 0, len(logicalLines))
	allEvidence := []model.Evidence{}
	for _, logical := range logicalLines {
		parsed, err := parsePAMLine(service, path, logical.line, logical.text)
		if err != nil {
			return nil, nil, err
		}
		if parsed == nil {
			continue
		}
		evidenceLines = append(evidenceLines, map[string]any{
			"line":    parsed.Line,
			"type":    parsed.Type,
			"control": parsed.Control,
			"module":  filepath.Base(parsed.Module),
			"args":    append([]string(nil), parsed.Args...),
		})
		if parsed.Control == "include" || parsed.Control == "substack" {
			included, includedEvidence, includeErr := readPAMService(ctx, files, parsed.Module, stack, depth+1)
			if includeErr != nil {
				return nil, nil, includeErr
			}
			rules = append(rules, included...)
			allEvidence = append(allEvidence, includedEvidence...)
			continue
		}
		rules = append(rules, *parsed)
	}
	fileEvidence := FactEvidence(path, map[string]any{"rules": evidenceLines})
	allEvidence = append([]model.Evidence{fileEvidence}, allEvidence...)
	return rules, allEvidence, nil
}

type logicalLine struct {
	line int
	text string
}

func pamLogicalLines(content string) ([]logicalLine, error) {
	physical := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	result := make([]logicalLine, 0, len(physical))
	var builder strings.Builder
	startLine := 0
	for index, raw := range physical {
		trimmed := strings.TrimSpace(raw)
		if builder.Len() == 0 {
			startLine = index + 1
		}
		continuation := strings.HasSuffix(trimmed, "\\")
		if continuation {
			trimmed = strings.TrimSpace(strings.TrimSuffix(trimmed, "\\"))
		}
		if builder.Len() > 0 && trimmed != "" {
			builder.WriteByte(' ')
		}
		builder.WriteString(trimmed)
		if continuation {
			continue
		}
		text := strings.TrimSpace(builder.String())
		builder.Reset()
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if comment := strings.IndexByte(text, '#'); comment >= 0 {
			text = strings.TrimSpace(text[:comment])
		}
		if text != "" {
			result = append(result, logicalLine{line: startLine, text: text})
		}
	}
	if builder.Len() > 0 {
		return nil, fmt.Errorf("unterminated continuation at line %d", startLine)
	}
	return result, nil
}

func parsePAMLine(service, path string, line int, content string) (*PAMRule, error) {
	fields := strings.Fields(content)
	if len(fields) < 3 {
		return nil, fmt.Errorf("parse %s line %d: expected at least 3 fields", path, line)
	}
	rule := &PAMRule{Service: service, Path: path, Line: line, Type: strings.TrimPrefix(fields[0], "-")}
	index := 1
	if strings.HasPrefix(fields[index], "[") {
		control := make([]string, 0)
		for ; index < len(fields); index++ {
			control = append(control, fields[index])
			if strings.HasSuffix(fields[index], "]") {
				break
			}
		}
		if index >= len(fields) || !strings.HasSuffix(fields[index], "]") {
			return nil, fmt.Errorf("parse %s line %d: unterminated bracketed control", path, line)
		}
		rule.Control = strings.Join(control, " ")
		index++
	} else {
		rule.Control = fields[index]
		index++
	}
	if index >= len(fields) {
		return nil, fmt.Errorf("parse %s line %d: module is missing", path, line)
	}
	rule.Module = fields[index]
	index++
	rule.Args = append([]string(nil), fields[index:]...)
	return rule, nil
}

func validPAMServiceName(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
