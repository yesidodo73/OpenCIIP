package redact

import (
	"regexp"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const marker = "[REDACTED]"

var (
	assignmentPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|community|private[_-]?key|authorization|cookie)(\s*[:=]\s*)([^\s,;]+)`)
	shadowLinePattern = regexp.MustCompile(`(?m)^([^:\r\n]+):([^:\r\n]*):`)
	communityPattern  = regexp.MustCompile(`(?im)^(\s*(?:rocommunity|rwcommunity|com2sec)\s+)(\S+)`)
	pemPattern        = regexp.MustCompile(`(?s)-----BEGIN [^-]*(?:PRIVATE KEY|SECRET)[^-]*-----.*?-----END [^-]*(?:PRIVATE KEY|SECRET)[^-]*-----`)
)

func Text(value string) string {
	value = pemPattern.ReplaceAllString(value, marker)
	value = shadowLinePattern.ReplaceAllString(value, `${1}:`+marker+`:`)
	value = communityPattern.ReplaceAllString(value, `${1}`+marker)
	return assignmentPattern.ReplaceAllString(value, `${1}${2}`+marker)
}

func ScanRun(run model.ScanRun) model.ScanRun {
	clone := run
	clone.Metadata.Counts = cloneCounts(run.Metadata.Counts)
	clone.Metadata.Warnings = append([]string(nil), run.Metadata.Warnings...)
	if run.Metadata.TargetIdentity != nil {
		identity := *run.Metadata.TargetIdentity
		clone.Metadata.TargetIdentity = &identity
	}
	clone.Results = make([]model.CheckResult, len(run.Results))
	for index, result := range run.Results {
		clone.Results[index] = result
		clone.Results[index].BindingSources = append([]string(nil), result.BindingSources...)
		clone.Results[index].Verification.Environments = append([]string(nil), result.Verification.Environments...)
		clone.Results[index].Observed = Text(result.Observed)
		clone.Results[index].ErrorMessage = Text(result.ErrorMessage)
		clone.Results[index].Evidence = make([]model.Evidence, len(result.Evidence))
		for evidenceIndex, evidence := range result.Evidence {
			clone.Results[index].Evidence[evidenceIndex] = cloneEvidence(evidence)
		}
	}
	return clone
}

func cloneEvidence(evidence model.Evidence) model.Evidence {
	clone := evidence
	clone.Redacted = true
	if evidence.Command != nil {
		command := *evidence.Command
		command.Arguments = append([]string(nil), evidence.Command.Arguments...)
		command.Stdout = Text(command.Stdout)
		command.Stderr = Text(command.Stderr)
		clone.Command = &command
	}
	if evidence.File != nil {
		file := *evidence.File
		file.Content = Text(file.Content)
		clone.File = &file
	}
	if evidence.Fact != nil {
		clone.Fact = cloneMap(evidence.Fact)
	}
	return clone
}

func cloneMap(values map[string]any) map[string]any {
	clone := make(map[string]any, len(values))
	for key, value := range values {
		if sensitiveKey(key) {
			clone[key] = marker
			continue
		}
		clone[key] = cloneValue(value)
	}
	return clone
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case string:
		return Text(typed)
	case map[string]any:
		return cloneMap(typed)
	case map[string]string:
		clone := make(map[string]string, len(typed))
		for key, child := range typed {
			if sensitiveKey(key) {
				clone[key] = marker
			} else {
				clone[key] = Text(child)
			}
		}
		return clone
	case []map[string]any:
		clone := make([]map[string]any, len(typed))
		for index, child := range typed {
			clone[index] = cloneMap(child)
		}
		return clone
	case []any:
		clone := make([]any, len(typed))
		for index, child := range typed {
			clone[index] = cloneValue(child)
		}
		return clone
	case []string:
		clone := make([]string, len(typed))
		for index, child := range typed {
			clone[index] = Text(child)
		}
		return clone
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", "_"), " ", "_"))
	for _, fragment := range []string{"password_value", "password_hash", "passwd_value", "secret", "token", "api_key", "community", "private_key", "authorization", "cookie", "credential_value"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func cloneCounts(counts map[model.Status]int) map[model.Status]int {
	clone := make(map[model.Status]int, len(counts))
	for status, count := range counts {
		clone[status] = count
	}
	return clone
}
