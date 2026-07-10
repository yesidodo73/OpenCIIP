package support

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type StaticShellOperationKind string

const (
	StaticShellAssign   StaticShellOperationKind = "assign"
	StaticShellUnset    StaticShellOperationKind = "unset"
	StaticShellUmask    StaticShellOperationKind = "umask"
	StaticShellSource   StaticShellOperationKind = "source"
	StaticShellExport   StaticShellOperationKind = "export"
	StaticShellReadOnly StaticShellOperationKind = "readonly"
)

type StaticShellOperation struct {
	Kind   StaticShellOperationKind
	Name   string
	Value  string
	Source string
	Line   int
}

type StaticShellIssue struct {
	Source string
	Line   int
	Reason string
}

type StaticShellAnalysis struct {
	Operations []StaticShellOperation
	Issues     []StaticShellIssue
}

// AnalyzeStaticShell recognizes only unconditional, side-effect-free shell
// assignments and the export/readonly/umask/source/unset builtins. It never executes input.
// Anything whose effect depends on runtime shell state is reported as an
// issue so callers cannot mistake a partial parse for an effective value.
func AnalyzeStaticShell(source string, data []byte) StaticShellAnalysis {
	analysis := StaticShellAnalysis{}
	if !utf8.Valid(data) {
		analysis.Issues = append(analysis.Issues, StaticShellIssue{
			Source: source,
			Line:   1,
			Reason: "UTF-8로 해석할 수 없는 셸 설정",
		})
		return analysis
	}
	if strings.IndexByte(string(data), 0) >= 0 {
		analysis.Issues = append(analysis.Issues, StaticShellIssue{
			Source: source,
			Line:   1,
			Reason: "NUL 바이트가 포함된 셸 설정",
		})
		return analysis
	}
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		analysis.Issues = append(analysis.Issues, StaticShellIssue{
			Source: source,
			Line:   1,
			Reason: "지원하지 않는 단독 CR 줄바꿈",
		})
		return analysis
	}

	blockDepth := 0
	continued := false
	lines := strings.Split(normalized, "\n")
	for index, raw := range lines {
		lineNumber := index + 1
		if continued {
			analysis.Issues = append(analysis.Issues, StaticShellIssue{
				Source: source,
				Line:   lineNumber,
				Reason: "여러 줄 셸 구문",
			})
			continued = hasTrailingShellContinuation(raw)
			continue
		}
		if hasTrailingShellContinuation(raw) {
			analysis.Issues = append(analysis.Issues, StaticShellIssue{
				Source: source,
				Line:   lineNumber,
				Reason: "여러 줄 셸 구문",
			})
			continued = true
			continue
		}

		commands, err := splitStaticShellCommands(raw)
		if err != nil {
			analysis.Issues = append(analysis.Issues, StaticShellIssue{
				Source: source,
				Line:   lineNumber,
				Reason: "셸 구문을 정적으로 분리할 수 없음",
			})
			continue
		}
		for _, command := range commands {
			fields := strings.Fields(command)
			if len(fields) == 0 {
				continue
			}
			first := fields[0]
			if closesStaticShellBlock(first) {
				if blockDepth == 0 {
					analysis.Issues = append(analysis.Issues, StaticShellIssue{
						Source: source,
						Line:   lineNumber,
						Reason: "대응하는 시작이 없는 셸 블록 종료",
					})
				} else {
					blockDepth--
				}
				continue
			}
			if opensStaticShellBlock(fields, command) {
				analysis.Issues = append(analysis.Issues, StaticShellIssue{
					Source: source,
					Line:   lineNumber,
					Reason: "조건부·반복·함수 셸 블록",
				})
				blockDepth++
				continue
			}
			if first == "then" || first == "else" || first == "elif" || first == "do" {
				analysis.Issues = append(analysis.Issues, StaticShellIssue{
					Source: source,
					Line:   lineNumber,
					Reason: "조건부·반복 셸 분기",
				})
				continue
			}
			if blockDepth > 0 {
				continue
			}
			if hasDynamicStaticShellSyntax(command) {
				analysis.Issues = append(analysis.Issues, StaticShellIssue{
					Source: source,
					Line:   lineNumber,
					Reason: "명령 치환·파이프·논리 연산 등 동적 셸 구문",
				})
				continue
			}
			operations, recognized := parseStaticShellCommand(source, lineNumber, command, fields)
			if !recognized {
				analysis.Issues = append(analysis.Issues, StaticShellIssue{
					Source: source,
					Line:   lineNumber,
					Reason: "효과를 정적으로 증명할 수 없는 셸 명령",
				})
				continue
			}
			analysis.Operations = append(analysis.Operations, operations...)
		}
	}
	if continued {
		analysis.Issues = append(analysis.Issues, StaticShellIssue{
			Source: source,
			Line:   len(lines),
			Reason: "완결되지 않은 여러 줄 셸 구문",
		})
	}
	if blockDepth != 0 {
		analysis.Issues = append(analysis.Issues, StaticShellIssue{
			Source: source,
			Line:   len(lines),
			Reason: "셸 블록 경계를 확정할 수 없음",
		})
	}
	return analysis
}

func parseStaticShellCommand(source string, line int, command string, fields []string) ([]StaticShellOperation, bool) {
	if len(fields) == 0 {
		return nil, true
	}
	first := fields[0]
	switch first {
	case ":", "true", "false":
		if len(fields) == 1 {
			return nil, true
		}
		return nil, false
	case "export":
		if len(fields) == 1 {
			return nil, true
		}
		operations := make([]StaticShellOperation, 0, 2*(len(fields)-1))
		for _, field := range fields[1:] {
			name, value, assigned := splitStaticAssignment(field)
			if assigned {
				if !validShellIdentifier(name) {
					return nil, false
				}
				operations = append(operations, StaticShellOperation{Kind: StaticShellAssign, Name: name, Value: value, Source: source, Line: line})
				field = name
			}
			if !validShellIdentifier(field) {
				return nil, false
			}
			operations = append(operations, StaticShellOperation{Kind: StaticShellExport, Name: field, Source: source, Line: line})
		}
		return operations, true
	case "readonly":
		return parseStaticAttributeCommand(source, line, fields[1:], false, true)
	case "declare", "typeset":
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "-") {
			return nil, false
		}
		flags := strings.TrimPrefix(fields[1], "-")
		if flags == "" || strings.Trim(flags, "xr") != "" {
			return nil, false
		}
		return parseStaticAttributeCommand(source, line, fields[2:], strings.Contains(flags, "x"), strings.Contains(flags, "r"))
	case "unset":
		if len(fields) < 2 {
			return nil, false
		}
		operations := make([]StaticShellOperation, 0, len(fields)-1)
		for _, name := range fields[1:] {
			if !validShellIdentifier(name) {
				return nil, false
			}
			operations = append(operations, StaticShellOperation{Kind: StaticShellUnset, Name: name, Source: source, Line: line})
		}
		return operations, true
	case "umask":
		if len(fields) == 1 {
			return nil, true
		}
		if len(fields) != 2 {
			return nil, false
		}
		return []StaticShellOperation{{Kind: StaticShellUmask, Value: fields[1], Source: source, Line: line}}, true
	case ".", "source":
		if len(fields) != 2 {
			return nil, false
		}
		return []StaticShellOperation{{Kind: StaticShellSource, Value: fields[1], Source: source, Line: line}}, true
	case "local", "eval", "exec", "set", "shopt", "alias", "unalias", "return", "exit", "break", "continue", "trap":
		return nil, false
	}

	name, value, assigned := splitStaticAssignment(command)
	if !assigned || !validShellIdentifier(name) {
		return nil, false
	}
	if strings.TrimSpace(command) != command || hasUnquotedShellWhitespace(value) {
		return nil, false
	}
	return []StaticShellOperation{{Kind: StaticShellAssign, Name: name, Value: value, Source: source, Line: line}}, true
}

func parseStaticAttributeCommand(source string, line int, fields []string, exported, readOnly bool) ([]StaticShellOperation, bool) {
	if len(fields) == 0 || !exported && !readOnly {
		return nil, false
	}
	operations := make([]StaticShellOperation, 0, 3*len(fields))
	for _, field := range fields {
		name, value, assigned := splitStaticAssignment(field)
		if assigned {
			if !validShellIdentifier(name) {
				return nil, false
			}
			operations = append(operations, StaticShellOperation{Kind: StaticShellAssign, Name: name, Value: value, Source: source, Line: line})
			field = name
		}
		if !validShellIdentifier(field) {
			return nil, false
		}
		if exported {
			operations = append(operations, StaticShellOperation{Kind: StaticShellExport, Name: field, Source: source, Line: line})
		}
		if readOnly {
			operations = append(operations, StaticShellOperation{Kind: StaticShellReadOnly, Name: field, Source: source, Line: line})
		}
	}
	return operations, true
}

// ExpandStaticShellWord expands only simple $NAME, ${NAME}, quoting, escaping,
// and a leading ~. Missing variables and every other expansion form are
// rejected instead of being guessed.
func ExpandStaticShellWord(raw string, variables map[string]string) (string, error) {
	word := strings.TrimSpace(raw)
	if word == "" {
		return "", nil
	}
	var result strings.Builder
	quote := byte(0)
	for index := 0; index < len(word); {
		character := word[index]
		if quote == '\'' {
			if character == '\'' {
				quote = 0
			} else {
				result.WriteByte(character)
			}
			index++
			continue
		}
		if character == '\'' && quote == 0 {
			quote = '\''
			index++
			continue
		}
		if character == '"' {
			if quote == '"' {
				quote = 0
			} else if quote == 0 {
				quote = '"'
			} else {
				result.WriteByte(character)
			}
			index++
			continue
		}
		if character == '\\' {
			if index+1 >= len(word) {
				return "", fmt.Errorf("완결되지 않은 이스케이프")
			}
			next := word[index+1]
			if quote == '"' && !strings.ContainsRune("$`\"\\\n", rune(next)) {
				result.WriteByte(character)
				index++
				continue
			}
			if next == '\n' {
				return "", fmt.Errorf("여러 줄 이스케이프는 지원하지 않음")
			}
			result.WriteByte(next)
			index += 2
			continue
		}
		if character == '`' {
			return "", fmt.Errorf("명령 치환은 지원하지 않음")
		}
		if character == '$' {
			name, next, err := staticShellVariable(word, index)
			if err != nil {
				return "", err
			}
			value, exists := variables[name]
			if !exists {
				return "", fmt.Errorf("변수 %s의 값을 확정할 수 없음", name)
			}
			result.WriteString(value)
			index = next
			continue
		}
		if quote == 0 {
			if unicode.IsSpace(rune(character)) {
				return "", fmt.Errorf("인용되지 않은 공백")
			}
			if strings.ContainsRune(";&|<>()[]{}*?!", rune(character)) {
				return "", fmt.Errorf("동적 셸 메타문자 %q", character)
			}
			if character == '~' && index > 0 && word[index-1] == ':' {
				return "", fmt.Errorf("할당문 내부 틸드 확장은 지원하지 않음")
			}
			if character == '~' && index == 0 {
				if len(word) > 1 && word[1] != '/' {
					return "", fmt.Errorf("사용자 이름을 포함한 틸드 확장")
				}
				home, exists := variables["HOME"]
				if !exists {
					return "", fmt.Errorf("HOME 값을 확정할 수 없음")
				}
				result.WriteString(home)
				index++
				continue
			}
		}
		result.WriteByte(character)
		index++
	}
	if quote != 0 {
		return "", fmt.Errorf("닫히지 않은 따옴표")
	}
	return result.String(), nil
}

func staticShellVariable(word string, start int) (string, int, error) {
	if start+1 >= len(word) {
		return "", start, fmt.Errorf("변수 이름이 없는 달러 확장")
	}
	if word[start+1] == '(' {
		return "", start, fmt.Errorf("명령 또는 산술 치환은 지원하지 않음")
	}
	if word[start+1] == '{' {
		end := strings.IndexByte(word[start+2:], '}')
		if end < 0 {
			return "", start, fmt.Errorf("닫히지 않은 변수 확장")
		}
		end += start + 2
		name := word[start+2 : end]
		if !validShellIdentifier(name) {
			return "", start, fmt.Errorf("단순 변수가 아닌 매개변수 확장")
		}
		return name, end + 1, nil
	}
	end := start + 1
	if !isShellIdentifierStart(word[end]) {
		return "", start, fmt.Errorf("지원하지 않는 특수 매개변수 확장")
	}
	end++
	for end < len(word) && isShellIdentifierPart(word[end]) {
		end++
	}
	return word[start+1 : end], end, nil
}

func splitStaticAssignment(command string) (string, string, bool) {
	index := strings.IndexByte(command, '=')
	if index <= 0 {
		return "", "", false
	}
	if command[index-1] == '+' {
		return "", "", false
	}
	return command[:index], command[index+1:], true
}

func validShellIdentifier(value string) bool {
	if value == "" || !isShellIdentifierStart(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		if !isShellIdentifierPart(value[index]) {
			return false
		}
	}
	return true
}

func isShellIdentifierStart(value byte) bool {
	return value == '_' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func isShellIdentifierPart(value byte) bool {
	return isShellIdentifierStart(value) || value >= '0' && value <= '9'
}

func hasUnquotedShellWhitespace(value string) bool {
	quote := byte(0)
	escaped := false
	for index := 0; index < len(value); index++ {
		character := value[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if unicode.IsSpace(rune(character)) {
			return true
		}
	}
	return false
}

func hasDynamicStaticShellSyntax(command string) bool {
	quote := byte(0)
	escaped := false
	for index := 0; index < len(command); index++ {
		character := command[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote == '\'' {
			if character == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' {
			if character == '"' {
				quote = 0
				continue
			}
			if character == '`' || character == '$' && index+1 < len(command) && command[index+1] == '(' {
				return true
			}
			continue
		}
		if character == '\'' {
			quote = '\''
			continue
		}
		if character == '"' {
			quote = '"'
			continue
		}
		if character == '`' || character == '|' || character == '<' || character == '>' {
			return true
		}
		if character == '$' && index+1 < len(command) && command[index+1] == '(' {
			return true
		}
		if character == '&' && index+1 < len(command) && command[index+1] == '&' {
			return true
		}
	}
	return false
}

func splitStaticShellCommands(line string) ([]string, error) {
	commands := make([]string, 0, 2)
	var builder strings.Builder
	quote := byte(0)
	escaped := false
	atWordStart := true
	for index := 0; index < len(line); index++ {
		character := line[index]
		if escaped {
			builder.WriteByte(character)
			escaped = false
			atWordStart = false
			continue
		}
		if character == '\\' && quote != '\'' {
			builder.WriteByte(character)
			escaped = true
			atWordStart = false
			continue
		}
		if quote != 0 {
			builder.WriteByte(character)
			if character == quote {
				quote = 0
			}
			continue
		}
		switch character {
		case '\'', '"':
			quote = character
			builder.WriteByte(character)
			atWordStart = false
		case '#':
			if atWordStart {
				index = len(line)
			} else {
				builder.WriteByte(character)
			}
		case ';':
			if command := strings.TrimSpace(builder.String()); command != "" {
				commands = append(commands, command)
			}
			builder.Reset()
			atWordStart = true
		default:
			builder.WriteByte(character)
			atWordStart = unicode.IsSpace(rune(character))
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("닫히지 않은 따옴표 또는 이스케이프")
	}
	if command := strings.TrimSpace(builder.String()); command != "" {
		commands = append(commands, command)
	}
	return commands, nil
}

func hasTrailingShellContinuation(line string) bool {
	count := 0
	for index := len(line) - 1; index >= 0 && line[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}

func opensStaticShellBlock(fields []string, command string) bool {
	if len(fields) == 0 {
		return false
	}
	switch fields[0] {
	case "if", "for", "while", "until", "case", "select", "function", "{", "(":
		return true
	}
	first := fields[0]
	return strings.HasSuffix(first, "()") || strings.Contains(command, "() {") || strings.Contains(command, "(){")
}

func closesStaticShellBlock(first string) bool {
	switch first {
	case "fi", "done", "esac", "}", ")":
		return true
	default:
		return false
	}
}
