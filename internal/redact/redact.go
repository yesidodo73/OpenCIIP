package redact

import (
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const marker = "[REDACTED]"

var (
	assignmentPattern     = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|community|private[_-]?key|authorization|cookie|credential|credentials|passphrase)([ \t]*[:=][ \t]*)("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;]+)`)
	shadowLikeLinePattern = regexp.MustCompile(`(?m)^[^:\r\n]+:[^\r\n]*\r?$`)
	legacyCryptPattern    = regexp.MustCompile(`^[./0-9A-Za-z]{13}$`)
	communityPattern      = regexp.MustCompile(`(?im)^(\s*(?:rocommunity|rwcommunity|com2sec)\s+)(\S+)`)
	pemPattern            = regexp.MustCompile(`(?s)-----BEGIN [^-]*(?:PRIVATE KEY|SECRET)[^-]*-----.*?-----END [^-]*(?:PRIVATE KEY|SECRET)[^-]*-----`)
	httpHeaderPattern     = regexp.MustCompile(`(?im)^([^\r\n]*?\b(?:authorization|proxy-authorization|cookie|set-cookie)[ \t]*:[ \t]*)[^\r\n]*`)
)

func Text(value string) string {
	value = pemPattern.ReplaceAllString(value, marker)
	value = shadowLikeLinePattern.ReplaceAllStringFunc(value, redactShadowLikeLine)
	value = communityPattern.ReplaceAllString(value, `${1}`+marker)
	value = httpHeaderPattern.ReplaceAllString(value, `${1}`+marker)
	return redactAssignments(value)
}

func redactAssignments(value string) string {
	matches := assignmentPattern.FindAllStringSubmatchIndex(value, -1)
	if len(matches) == 0 {
		return value
	}

	var builder strings.Builder
	builder.Grow(len(value))
	last := 0
	changed := false
	for _, match := range matches {
		keyStart, keyEnd := match[2], match[3]
		if preserveAssignmentToken(
			value,
			keyStart,
			keyEnd,
			match[4],
			match[5],
			match[6],
			match[7],
		) {
			continue
		}
		builder.WriteString(value[last:match[0]])
		builder.WriteString(value[keyStart:keyEnd])
		builder.WriteString(value[match[4]:match[5]])
		builder.WriteString(marker)
		last = match[1]
		changed = true
	}
	if !changed {
		return value
	}
	builder.WriteString(value[last:])
	return builder.String()
}

func preserveAssignmentToken(
	value string,
	keyStart, keyEnd int,
	delimiterStart, delimiterEnd int,
	assignmentStart, assignmentEnd int,
) bool {
	if strings.TrimSpace(value[delimiterStart:delimiterEnd]) != ":" {
		return false
	}

	tokenStart := keyStart
	for tokenStart > 0 && assignmentTokenByte(value[tokenStart-1]) {
		tokenStart--
	}
	assignment := value[assignmentStart:assignmentEnd]
	if strings.EqualFold(value[tokenStart:keyEnd], "common-password") &&
		decimalDigits(assignment) {
		return true
	}
	if tokenStart == 0 || (value[tokenStart-1] != '/' && value[tokenStart-1] != '\\') {
		return false
	}

	pathStart := tokenStart - 1
	for pathStart > 0 && !assignmentPathBoundary(value[pathStart-1]) {
		pathStart--
	}
	diagnosticPath := strings.ToLower(strings.ReplaceAll(value[pathStart:keyEnd], "\\", "/"))
	switch diagnosticPath {
	case "/etc/pam.d/common-password", "c:/etc/pam.d/common-password",
		"/etc/pam.d/password-auth", "c:/etc/pam.d/password-auth":
		return decimalDigits(assignment)
	case "/etc/cron.daily/passwd", "c:/etc/cron.daily/passwd":
		return assignment == "허용되지"
	default:
		return false
	}
}

func assignmentTokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' ||
		value == '_' || value == '-' || value == '.'
}

func assignmentPathBoundary(value byte) bool {
	switch value {
	case ' ', '\t', '\r', '\n', ',', ';', '=', '"', '\'':
		return true
	default:
		return false
	}
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func redactShadowLikeLine(line string) string {
	lineEnding := ""
	if strings.HasSuffix(line, "\r") {
		line = strings.TrimSuffix(line, "\r")
		lineEnding = "\r"
	}
	if net.ParseIP(strings.TrimSpace(line)) != nil {
		return line + lineEnding
	}
	fields := strings.Split(line, ":")
	if len(fields) < 2 {
		return line + lineEnding
	}

	password := fields[1]
	agingFields := fields[2:]
	completeShadow := len(fields) == 9 && areAgingFields(agingFields)
	if !completeShadow && !looksLikeShadowPassword(password, agingFields) {
		return line + lineEnding
	}
	fields[1] = marker
	return strings.Join(fields, ":") + lineEnding
}

func looksLikeShadowPassword(password string, agingFields []string) bool {
	if password == "" {
		return len(agingFields) > 0 && areAgingFields(agingFields)
	}
	unlocked := strings.TrimLeft(password, "!")
	if unlocked != password && (unlocked == "" || unlocked == "*" || strings.HasPrefix(unlocked, "$")) {
		return true
	}
	if password == "*" || password == "*LK*" || password == "LK" || password == "NP" || strings.HasPrefix(password, "$") {
		return true
	}
	return legacyCryptPattern.MatchString(unlocked) && (len(agingFields) == 0 || areAgingFields(agingFields))
}

func areAgingFields(fields []string) bool {
	for _, field := range fields {
		if field == "" {
			continue
		}
		if _, err := strconv.ParseInt(field, 10, 64); err != nil {
			return false
		}
	}
	return true
}

func ScanRun(run model.ScanRun) model.ScanRun {
	clone := run
	clone.Metadata.Counts = cloneCounts(run.Metadata.Counts)
	clone.Metadata.ToolVersion = Text(run.Metadata.ToolVersion)
	clone.Metadata.ToolCommit = Text(run.Metadata.ToolCommit)
	clone.Metadata.ToolExecutableSHA256 = Text(run.Metadata.ToolExecutableSHA256)
	clone.Metadata.RuleSetVersion = Text(run.Metadata.RuleSetVersion)
	clone.Metadata.EvidenceMode = Text(run.Metadata.EvidenceMode)
	clone.Metadata.Platform = redactPlatform(run.Metadata.Platform)
	clone.Metadata.Selection.Profiles = redactStrings(run.Metadata.Selection.Profiles)
	clone.Metadata.Selection.RuleIDs = redactStrings(run.Metadata.Selection.RuleIDs)
	clone.Metadata.Selection.Categories = append(
		[]model.Category(nil),
		run.Metadata.Selection.Categories...,
	)
	clone.Metadata.Selection.Severities = append(
		[]model.Severity(nil),
		run.Metadata.Selection.Severities...,
	)
	clone.Metadata.Warnings = redactStrings(run.Metadata.Warnings)
	if run.Metadata.TargetIdentity != nil {
		identity := *run.Metadata.TargetIdentity
		identity.MachineIDHash = Text(identity.MachineIDHash)
		identity.SystemRoot = Text(identity.SystemRoot)
		identity.BootID = Text(identity.BootID)
		clone.Metadata.TargetIdentity = &identity
	}
	clone.Results = make([]model.CheckResult, len(run.Results))
	for index, result := range run.Results {
		clone.Results[index] = result
		clone.Results[index].RuleID = Text(result.RuleID)
		clone.Results[index].Title = Text(result.Title)
		clone.Results[index].Summary = Text(result.Summary)
		clone.Results[index].Expected = Text(result.Expected)
		clone.Results[index].Evaluator = Text(result.Evaluator)
		clone.Results[index].ErrorCode = Text(result.ErrorCode)
		clone.Results[index].BindingSources = redactStrings(result.BindingSources)
		clone.Results[index].Verification.Environments = redactStrings(result.Verification.Environments)
		clone.Results[index].Verification.VerifiedAt = Text(result.Verification.VerifiedAt)
		clone.Results[index].Reference.Guide = Text(result.Reference.Guide)
		clone.Results[index].Reference.Section = Text(result.Reference.Section)
		clone.Results[index].Reference.Item = Text(result.Reference.Item)
		clone.Results[index].Reference.Pages = append([]int(nil), result.Reference.Pages...)
		clone.Results[index].Observed = Text(result.Observed)
		clone.Results[index].DisplayDetails = make([]model.ResultDetail, len(result.DisplayDetails))
		for detailIndex, detail := range result.DisplayDetails {
			clone.Results[index].DisplayDetails[detailIndex] = model.ResultDetail{
				Label:    Text(detail.Label),
				Current:  Text(detail.Current),
				Expected: Text(detail.Expected),
				Source:   Text(detail.Source),
			}
		}
		clone.Results[index].ErrorMessage = Text(result.ErrorMessage)
		clone.Results[index].Evidence = make([]model.Evidence, len(result.Evidence))
		for evidenceIndex, evidence := range result.Evidence {
			clone.Results[index].Evidence[evidenceIndex] = cloneEvidence(evidence)
		}
	}
	return clone
}

func redactPlatform(platform model.PlatformInfo) model.PlatformInfo {
	platform.Hostname = Text(platform.Hostname)
	platform.OS = Text(platform.OS)
	platform.ID = Text(platform.ID)
	platform.Name = Text(platform.Name)
	platform.VersionID = Text(platform.VersionID)
	platform.Family = Text(platform.Family)
	platform.Architecture = Text(platform.Architecture)
	platform.KernelRelease = Text(platform.KernelRelease)
	platform.InitSystem = Text(platform.InitSystem)
	platform.PackageManager = Text(platform.PackageManager)
	platform.Privilege = Text(platform.Privilege)
	return platform
}

func redactStrings(values []string) []string {
	clone := make([]string, len(values))
	for index, value := range values {
		clone[index] = Text(value)
	}
	return clone
}

func cloneEvidence(evidence model.Evidence) model.Evidence {
	clone := evidence
	clone.Redacted = true
	clone.Source = Text(evidence.Source)
	if evidence.Command != nil {
		command := *evidence.Command
		command.Executable = Text(command.Executable)
		command.Arguments = redactCommandArguments(evidence.Command.Arguments)
		command.Stdout = Text(command.Stdout)
		command.Stderr = Text(command.Stderr)
		clone.Command = &command
	}
	if evidence.File != nil {
		file := *evidence.File
		file.Path = Text(file.Path)
		file.Content = Text(file.Content)
		file.Mode = Text(file.Mode)
		file.Owner = Text(file.Owner)
		file.Group = Text(file.Group)
		clone.File = &file
	}
	if evidence.Fact != nil {
		clone.Fact = cloneMap(evidence.Fact)
	}
	return clone
}

func redactCommandArguments(arguments []string) []string {
	clone := make([]string, len(arguments))
	redactNext := false
	for index, argument := range arguments {
		if redactNext {
			clone[index] = marker
			redactNext = false
			continue
		}
		clone[index] = Text(argument)
		if sensitiveCommandOption(argument) {
			redactNext = true
		}
	}
	return clone
}

func sensitiveCommandOption(argument string) bool {
	if !strings.HasPrefix(argument, "-") || strings.ContainsAny(argument, "=\r\n\x00") {
		return false
	}
	option := strings.TrimLeft(argument, "-")
	option = strings.ToLower(strings.ReplaceAll(option, "_", "-"))
	for _, suffix := range []string{
		"password", "passwd", "secret", "token", "api-key", "community",
		"private-key", "authorization", "cookie", "credential", "credentials",
	} {
		if option == suffix || strings.HasSuffix(option, "-"+suffix) {
			return true
		}
	}
	return false
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
	case []map[string]string:
		clone := make([]map[string]string, len(typed))
		for index, child := range typed {
			item := make(map[string]string, len(child))
			for key, value := range child {
				if sensitiveKey(key) {
					item[key] = marker
				} else {
					item[key] = Text(value)
				}
			}
			clone[index] = item
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
	tokens := sensitiveKeyTokens(key)
	for _, token := range tokens {
		switch token {
		case "password", "passwd", "secret", "token", "credential", "credentials",
			"passphrase", "community", "authorization", "cookie":
			return true
		}
	}
	for index := 0; index+1 < len(tokens); index++ {
		pair := tokens[index] + "_" + tokens[index+1]
		if pair == "api_key" || pair == "private_key" {
			return true
		}
	}
	return false
}

func sensitiveKeyTokens(key string) []string {
	runes := []rune(key)
	tokens := make([]string, 0, 4)
	start := -1
	flush := func(end int) {
		if start >= 0 && end > start {
			tokens = append(tokens, strings.ToLower(string(runes[start:end])))
		}
		start = -1
	}
	for index, character := range runes {
		isLetter := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z'
		isDigit := character >= '0' && character <= '9'
		if !isLetter && !isDigit {
			flush(index)
			continue
		}
		if start < 0 {
			start = index
			continue
		}
		isUpper := character >= 'A' && character <= 'Z'
		previous := runes[index-1]
		previousLowerOrDigit := previous >= 'a' && previous <= 'z' ||
			previous >= '0' && previous <= '9'
		nextLower := index+1 < len(runes) &&
			runes[index+1] >= 'a' && runes[index+1] <= 'z'
		previousUpper := previous >= 'A' && previous <= 'Z'
		if isUpper && (previousLowerOrDigit || previousUpper && nextLower) {
			flush(index)
			start = index
		}
	}
	flush(len(runes))
	return tokens
}

func cloneCounts(counts map[model.Status]int) map[model.Status]int {
	clone := make(map[model.Status]int, len(counts))
	for status, count := range counts {
		clone[status] = count
	}
	return clone
}
