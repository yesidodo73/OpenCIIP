package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type systemdNamespaceProperty struct {
	Name    string
	Boolean bool
}

var sshdNamespaceProperties = [...]systemdNamespaceProperty{
	{Name: "RootDirectory"},
	{Name: "RootImage"},
	{Name: "RootEphemeral", Boolean: true},
	{Name: "RootDirectoryStartOnly", Boolean: true},
	{Name: "BindPaths"},
	{Name: "BindReadOnlyPaths"},
	{Name: "TemporaryFileSystem"},
	{Name: "MountImages"},
	{Name: "ExtensionImages"},
	{Name: "ExtensionDirectories"},
	{Name: "InaccessiblePaths"},
}

var sshdUnprintableArraySignatures = map[string]string{
	"BindPaths":           "a(ssbt)",
	"BindReadOnlyPaths":   "a(ssbt)",
	"TemporaryFileSystem": "a(ss)",
}

var sshdLaunchProperties = func() string {
	names := []string{
		"ExecStart",
		"Environment",
		"EnvironmentFiles",
		"PassEnvironment",
		"UnsetEnvironment",
	}
	for _, property := range sshdNamespaceProperties {
		names = append(names, property.Name)
	}
	return strings.Join(names, ",")
}()

type sshLaunchProfile struct {
	Unit                   string
	Executable             string
	ConfigurationArguments []string
	CustomConfiguration    bool
}

type systemdEnvironmentFile struct {
	Path         string
	IgnoreErrors bool
}

func resolveSSHLaunchUnits(ctx context.Context, environment evaluator.Environment, states []support.UnitState) ([]string, []model.Evidence, []string, error) {
	units := make(map[string]struct{})
	evidence := make([]model.Evidence, 0)
	unknowns := make([]string, 0)
	for _, state := range states {
		if !support.UnitActive(state) {
			continue
		}
		unitName := strings.TrimSpace(state.InspectionName)
		if unitName == "" {
			unitName = strings.TrimSpace(state.Name)
		}
		switch {
		case strings.HasSuffix(unitName, ".service"):
			if !validSystemdServiceName(unitName) {
				unknowns = append(unknowns, "활성 SSH service unit 이름을 해석할 수 없음")
				continue
			}
			units[unitName] = struct{}{}
		case strings.HasSuffix(unitName, ".socket"):
			triggered, triggerEvidence, reason, err := inspectSSHSocketTriggers(ctx, environment, unitName)
			evidence = append(evidence, triggerEvidence)
			if err != nil {
				return nil, evidence, unknowns, err
			}
			if reason != "" {
				unknowns = append(unknowns, unitName+": "+reason)
				continue
			}
			for _, triggeredUnit := range triggered {
				units[triggeredUnit] = struct{}{}
			}
		default:
			unknowns = append(unknowns, unitName+": 지원하지 않는 활성 SSH unit 유형")
		}
	}
	result := make([]string, 0, len(units))
	for unitName := range units {
		result = append(result, unitName)
	}
	sort.Strings(result)
	if len(result) == 0 && len(unknowns) == 0 {
		unknowns = append(unknowns, "활성 SSH 프로세스 또는 리스너의 systemd 기동 unit을 확인할 수 없음")
	}
	return result, evidence, uniqueSorted(unknowns), nil
}

func inspectSSHSocketTriggers(ctx context.Context, environment evaluator.Environment, unitName string) ([]string, model.Evidence, string, error) {
	spec := executor.Spec{
		Name:      "systemctl",
		Arguments: []string{"show", "--no-pager", "--property=Triggers", "--", unitName},
		Timeout:   10 * time.Second,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := support.CommandSummaryEvidence("systemd-ssh-socket-trigger", spec, result, map[string]any{
		"unit": unitName, "exit_code": result.ExitCode, "truncated": result.Truncated,
	})
	if err != nil {
		return nil, evidence, "", err
	}
	if result.ExitCode != 0 || result.Truncated {
		return nil, evidence, "", fmt.Errorf("systemctl show Triggers %s exit=%d truncated=%t", unitName, result.ExitCode, result.Truncated)
	}
	properties, err := support.ParseKeyValueOutput(string(result.Stdout))
	if err != nil {
		return nil, evidence, "Triggers 출력을 해석할 수 없음", nil
	}
	raw, exists := properties["Triggers"]
	if !exists || strings.TrimSpace(raw) == "" {
		return nil, evidence, "연결을 처리할 service unit을 확인할 수 없음", nil
	}
	triggered := make([]string, 0)
	for _, candidate := range strings.Fields(raw) {
		if !validSystemdServiceName(candidate) {
			return nil, evidence, "service가 아닌 trigger를 포함함", nil
		}
		triggered = append(triggered, candidate)
	}
	sort.Strings(triggered)
	evidence.Fact["trigger_count"] = len(triggered)
	return uniqueSorted(triggered), evidence, "", nil
}

func inspectSSHDLaunchProfile(ctx context.Context, environment evaluator.Environment, unitName string) (sshLaunchProfile, []model.Evidence, string, error) {
	profile := sshLaunchProfile{Unit: unitName}
	spec := executor.Spec{
		Name: "systemctl",
		Arguments: []string{
			"show", "--no-pager", "--property=" + sshdLaunchProperties, "--", unitName,
		},
		Timeout: 10 * time.Second, MaxOutput: 2 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := []model.Evidence{support.CommandSummaryEvidence("systemd-sshd-launch", spec, result, map[string]any{
		"unit": unitName, "exit_code": result.ExitCode, "truncated": result.Truncated,
	})}
	if err != nil {
		return profile, evidence, "", err
	}
	if result.ExitCode != 0 || result.Truncated {
		return profile, evidence, "", fmt.Errorf("systemctl show sshd launch %s exit=%d truncated=%t", unitName, result.ExitCode, result.Truncated)
	}
	properties, parseErr := support.ParseKeyValueOutput(string(result.Stdout))
	if parseErr != nil {
		return profile, evidence, "systemd 기동 속성을 해석할 수 없음", nil
	}
	namespaceOverrides, namespaceEvidence, namespaceReason := inspectSystemdNamespaceProperties(
		ctx,
		environment,
		unitName,
		properties,
	)
	evidence = append(evidence, namespaceEvidence...)
	evidence[0].Fact["namespace_property_count"] = len(sshdNamespaceProperties)
	if namespaceReason != "" {
		return profile, evidence, namespaceReason, nil
	}
	if len(namespaceOverrides) > 0 {
		evidence[0].Fact["namespace_override_properties"] = append([]string(nil), namespaceOverrides...)
		return profile, evidence,
			"systemd 파일 시스템 격리 속성이 활성화되었거나 값을 해석할 수 없음: " + strings.Join(namespaceOverrides, ", "),
			nil
	}
	execStart, exists := properties["ExecStart"]
	if !exists || strings.TrimSpace(execStart) == "" {
		return profile, evidence, "ExecStart가 없음", nil
	}
	executable, arguments, reason := parseSystemdExecStart(execStart)
	if reason != "" {
		return profile, evidence, reason, nil
	}
	if !standardSSHDExecutable(executable) {
		return profile, evidence, "ExecStart가 표준 sshd가 아닌 래퍼 또는 사용자 지정 실행 파일을 사용함", nil
	}

	referenced, referenceReason := referencedSystemdVariables(arguments)
	if referenceReason != "" {
		return profile, evidence, referenceReason, nil
	}
	values, environmentEvidence, environmentReason, environmentErr := resolveSystemdEnvironment(ctx, environment, properties, referenced)
	evidence = append(evidence, environmentEvidence...)
	if environmentErr != nil {
		return profile, evidence, "", environmentErr
	}
	if environmentReason != "" {
		return profile, evidence, environmentReason, nil
	}
	expanded, expandReason := expandSystemdArguments(arguments, values)
	if expandReason != "" {
		return profile, evidence, expandReason, nil
	}
	if len(expanded) == 0 || expanded[0] != executable {
		return profile, evidence, "ExecStart path와 argv[0]가 일치하지 않음", nil
	}
	configurationArguments, custom, argumentReason := sshdConfigurationArguments(expanded[1:])
	if argumentReason != "" {
		return profile, evidence, argumentReason, nil
	}
	profile.Executable = executable
	profile.ConfigurationArguments = configurationArguments
	profile.CustomConfiguration = custom
	evidence[0].Fact["executable"] = executable
	evidence[0].Fact["configuration_argument_count"] = len(configurationArguments)
	evidence[0].Fact["custom_configuration"] = custom
	return profile, evidence, "", nil
}

func inspectSystemdNamespaceProperties(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
	properties map[string]string,
) ([]string, []model.Evidence, string) {
	active := make([]string, 0)
	evidence := make([]model.Evidence, 0)
	for _, property := range sshdNamespaceProperties {
		value, exists := properties[property.Name]
		if !exists {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if value == "[unprintable]" {
			signature, supported := sshdUnprintableArraySignatures[property.Name]
			if !supported {
				return nil, evidence,
					"systemd 파일 시스템 격리 속성 값을 해석할 수 없음: " + property.Name
			}
			count, propertyEvidence, reason := inspectSystemdArrayProperty(
				ctx,
				environment,
				unitName,
				property.Name,
				signature,
			)
			evidence = append(evidence, propertyEvidence)
			if reason != "" {
				return nil, evidence, reason
			}
			if count > 0 {
				active = append(active, property.Name)
			}
			continue
		}
		if property.Boolean {
			switch strings.ToLower(value) {
			case "no", "false", "0":
				continue
			}
		}
		active = append(active, property.Name)
	}
	return active, evidence, ""
}

func inspectSystemdArrayProperty(
	ctx context.Context,
	environment evaluator.Environment,
	unitName string,
	propertyName string,
	expectedSignature string,
) (int, model.Evidence, string) {
	objectPath := systemdUnitObjectPath(unitName)
	spec := executor.Spec{
		Name: "busctl",
		Arguments: []string{
			"get-property",
			"org.freedesktop.systemd1",
			objectPath,
			"org.freedesktop.systemd1.Service",
			propertyName,
		},
		Timeout:   10 * time.Second,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	evidence := support.CommandSummaryEvidence("systemd-sshd-namespace-property", spec, result, map[string]any{
		"unit":               unitName,
		"property":           propertyName,
		"expected_signature": expectedSignature,
		"exit_code":          result.ExitCode,
		"truncated":          result.Truncated,
	})
	if err != nil {
		evidence.Fact["run_error"] = true
		return 0, evidence,
			propertyName + "의 systemd typed 속성 조회 명령을 실행할 수 없음"
	}
	if result.ExitCode != 0 || result.Truncated || result.TimedOut {
		return 0, evidence, fmt.Sprintf(
			"%s의 systemd typed 속성을 확인할 수 없음: exit=%d truncated=%t timed_out=%t",
			propertyName,
			result.ExitCode,
			result.Truncated,
			result.TimedOut,
		)
	}
	count, ok := parseBusctlArrayCount(string(result.Stdout), expectedSignature)
	if !ok {
		return 0, evidence,
			propertyName + "의 systemd typed 배열 출력을 해석할 수 없음"
	}
	evidence.Fact["array_count"] = count
	return count, evidence, ""
}

func parseBusctlArrayCount(output string, expectedSignature string) (int, bool) {
	output = strings.TrimSpace(strings.ReplaceAll(output, "\r\n", "\n"))
	if output == "" || strings.ContainsAny(output, "\x00\r\n\t") {
		return 0, false
	}
	signature, remainder, found := strings.Cut(output, " ")
	if !found || signature != expectedSignature {
		return 0, false
	}
	remainder = strings.TrimSpace(remainder)
	countToken, payload, hasPayload := strings.Cut(remainder, " ")
	count, err := strconv.Atoi(countToken)
	if err != nil || count < 0 || strconv.Itoa(count) != countToken {
		return 0, false
	}
	payload = strings.TrimSpace(payload)
	if count == 0 {
		return 0, !hasPayload || payload == ""
	}
	if !hasPayload || payload == "" {
		return 0, false
	}
	return count, true
}

func systemdUnitObjectPath(unitName string) string {
	const prefix = "/org/freedesktop/systemd1/unit/"
	var escaped strings.Builder
	escaped.Grow(len(prefix) + len(unitName))
	escaped.WriteString(prefix)
	for index := 0; index < len(unitName); index++ {
		character := unitName[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') {
			escaped.WriteByte(character)
			continue
		}
		escaped.WriteString(fmt.Sprintf("_%02x", character))
	}
	return escaped.String()
}

func parseSystemdExecStart(value string) (string, []string, string) {
	if strings.Count(value, "path=") != 1 || strings.Count(value, "argv[]=") != 1 {
		return "", nil, "ExecStart 명령 수 또는 구조를 확정할 수 없음"
	}
	pathMarker := strings.Index(value, "path=")
	argvMarker := strings.Index(value, "; argv[]=")
	if pathMarker < 0 || argvMarker < 0 || argvMarker <= pathMarker+len("path=") {
		return "", nil, "ExecStart path/argv 구조를 해석할 수 없음"
	}
	pathWords, ok := splitSystemdWords(strings.TrimSpace(value[pathMarker+len("path=") : argvMarker]))
	if !ok || len(pathWords) != 1 {
		return "", nil, "ExecStart 실행 파일 경로를 해석할 수 없음"
	}
	argumentStart := argvMarker + len("; argv[]=")
	argumentEndRelative := strings.Index(value[argumentStart:], "; ignore_errors=")
	if argumentEndRelative < 0 {
		return "", nil, "ExecStart argv 경계를 해석할 수 없음"
	}
	arguments, ok := splitSystemdWords(strings.TrimSpace(value[argumentStart : argumentStart+argumentEndRelative]))
	if !ok || len(arguments) == 0 {
		return "", nil, "ExecStart argv를 해석할 수 없음"
	}
	return pathWords[0], arguments, ""
}

func splitSystemdWords(value string) ([]string, bool) {
	if strings.ContainsAny(value, "\x00\r\n") {
		return nil, false
	}
	words := make([]string, 0)
	var builder strings.Builder
	quote := rune(0)
	escaped := false
	started := false
	flush := func() {
		if started {
			words = append(words, builder.String())
			builder.Reset()
			started = false
		}
	}
	for _, character := range value {
		if escaped {
			builder.WriteRune(character)
			started = true
			escaped = false
			continue
		}
		if character == '\\' && quote != '\'' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				builder.WriteRune(character)
				started = true
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			started = true
			continue
		}
		if unicode.IsSpace(character) {
			flush()
			continue
		}
		builder.WriteRune(character)
		started = true
	}
	if escaped || quote != 0 {
		return nil, false
	}
	flush()
	return words, true
}

func referencedSystemdVariables(arguments []string) (map[string]struct{}, string) {
	result := make(map[string]struct{})
	for _, argument := range arguments {
		name, form, ok := systemdVariableReference(argument)
		if ok {
			if !validEnvironmentName(name) {
				return nil, "ExecStart 환경 변수 이름을 해석할 수 없음"
			}
			_ = form
			result[name] = struct{}{}
			continue
		}
		if strings.Contains(argument, "$") || strings.Contains(argument, "%") {
			return nil, "ExecStart의 부분 환경 변수 또는 systemd specifier 확장을 확정할 수 없음"
		}
	}
	return result, ""
}

func resolveSystemdEnvironment(
	ctx context.Context,
	environment evaluator.Environment,
	properties map[string]string,
	wanted map[string]struct{},
) (map[string]string, []model.Evidence, string, error) {
	values := make(map[string]string)
	if len(wanted) == 0 {
		return values, nil, "", nil
	}
	inline := properties["Environment"]
	words, ok := splitSystemdWords(inline)
	if !ok {
		return nil, nil, "systemd Environment 값을 해석할 수 없음", nil
	}
	for _, word := range words {
		key, value, found := strings.Cut(word, "=")
		if !found || !validEnvironmentName(key) {
			continue
		}
		if _, needed := wanted[key]; needed {
			values[key] = value
		}
	}

	filesValue := properties["EnvironmentFiles"]
	files, reason := parseSystemdEnvironmentFiles(filesValue)
	if reason != "" {
		return nil, nil, reason, nil
	}
	evidence := make([]model.Evidence, 0, len(files))
	for _, file := range files {
		data, _, err := environment.Files.ReadFile(ctx, file.Path, 2<<20)
		if err != nil {
			if file.IgnoreErrors && errors.Is(err, os.ErrNotExist) {
				evidence = append(evidence, support.FactEvidence(file.Path, map[string]any{
					"exists": false, "ignore_errors": true, "referenced_values_recorded": false,
				}))
				continue
			}
			return nil, evidence, "", err
		}
		found, parseReason := parseSystemdEnvironmentFile(string(data), wanted)
		if parseReason != "" {
			return nil, evidence, file.Path + ": " + parseReason, nil
		}
		foundNames := make([]string, 0, len(found))
		for key, value := range found {
			values[key] = value
			foundNames = append(foundNames, key)
		}
		sort.Strings(foundNames)
		evidence = append(evidence, support.FactEvidence(file.Path, map[string]any{
			"exists": true, "ignore_errors": file.IgnoreErrors, "referenced_variables": foundNames,
			"referenced_values_recorded": false,
		}))
	}

	passValue := properties["PassEnvironment"]
	passNames, ok := splitSystemdWords(passValue)
	if !ok {
		return nil, evidence, "systemd PassEnvironment 값을 해석할 수 없음", nil
	}
	unsetValue := properties["UnsetEnvironment"]
	unsetEntries, ok := splitSystemdWords(unsetValue)
	if !ok {
		return nil, evidence, "systemd UnsetEnvironment 값을 해석할 수 없음", nil
	}
	unconditionallyUnset := make(map[string]bool)
	for _, entry := range unsetEntries {
		key, expected, conditional := strings.Cut(entry, "=")
		if _, needed := wanted[key]; !needed {
			continue
		}
		if !conditional {
			delete(values, key)
			unconditionallyUnset[key] = true
		} else if values[key] == expected {
			delete(values, key)
		}
	}
	for _, name := range passNames {
		if _, needed := wanted[name]; needed && !unconditionallyUnset[name] {
			return nil, evidence, "PassEnvironment로 전달되는 manager 환경 변수 값을 확인할 수 없음", nil
		}
	}
	return values, evidence, "", nil
}

func parseSystemdEnvironmentFiles(value string) ([]systemdEnvironmentFile, string) {
	if strings.TrimSpace(value) == "" {
		return nil, ""
	}
	words, ok := splitSystemdWords(value)
	if !ok {
		return nil, "EnvironmentFiles 값을 해석할 수 없음"
	}
	files := make([]systemdEnvironmentFile, 0)
	for index := 0; index < len(words); index++ {
		filePath := words[index]
		if !path.IsAbs(filePath) || path.Clean(filePath) != filePath || strings.ContainsAny(filePath, "*?[\x00\r\n") {
			return nil, "EnvironmentFiles 경로를 결정적으로 해석할 수 없음"
		}
		file := systemdEnvironmentFile{Path: filePath}
		if index+1 < len(words) && strings.HasPrefix(words[index+1], "(ignore_errors=") {
			marker := words[index+1]
			switch marker {
			case "(ignore_errors=yes)":
				file.IgnoreErrors = true
			case "(ignore_errors=no)":
			default:
				return nil, "EnvironmentFiles ignore_errors 값을 해석할 수 없음"
			}
			index++
		}
		files = append(files, file)
	}
	return files, ""
}

func parseSystemdEnvironmentFile(content string, wanted map[string]struct{}) (map[string]string, string) {
	values := make(map[string]string)
	for index, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		key, rawValue, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !validEnvironmentName(key) {
			continue
		}
		if _, needed := wanted[key]; !needed {
			continue
		}
		value, ok := parseSystemdEnvironmentValue(rawValue)
		if !ok {
			return nil, fmt.Sprintf("line %d의 %s 값을 해석할 수 없음", index+1, key)
		}
		values[key] = value
	}
	return values, ""
}

func parseSystemdEnvironmentValue(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", true
	}
	if value[0] == '\'' || value[0] == '"' {
		words, ok := splitSystemdWords(value)
		if !ok || len(words) != 1 {
			return "", false
		}
		return words[0], true
	}
	if strings.ContainsAny(value, "'\"\\\x00\r\n") {
		return "", false
	}
	return value, true
}

func expandSystemdArguments(arguments []string, values map[string]string) ([]string, string) {
	expanded := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		name, form, reference := systemdVariableReference(argument)
		if !reference {
			expanded = append(expanded, argument)
			continue
		}
		value := values[name]
		if form == "braced" {
			expanded = append(expanded, value)
			continue
		}
		if value == "" {
			continue
		}
		words, ok := splitSystemdWords(value)
		if !ok {
			return nil, "ExecStart 환경 변수의 인수 확장을 해석할 수 없음"
		}
		for _, word := range words {
			if strings.ContainsAny(word, "$%") {
				return nil, "ExecStart 환경 변수의 중첩 확장을 확정할 수 없음"
			}
		}
		expanded = append(expanded, words...)
	}
	return expanded, ""
}

func systemdVariableReference(value string) (name, form string, ok bool) {
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") && strings.Count(value, "$") == 1 {
		return value[2 : len(value)-1], "braced", true
	}
	if strings.HasPrefix(value, "$") && strings.Count(value, "$") == 1 {
		return value[1:], "split", true
	}
	return "", "", false
}

func sshdConfigurationArguments(arguments []string) ([]string, bool, string) {
	configuration := make([]string, 0)
	custom := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch {
		case argument == "-f":
			if index+1 >= len(arguments) {
				return nil, false, "sshd -f 설정 경로가 없음"
			}
			index++
			configPath := arguments[index]
			if !validSSHDConfigPath(configPath) {
				return nil, false, "sshd -f 설정 경로를 안전하게 해석할 수 없음"
			}
			configuration = append(configuration, "-f", configPath)
			custom = custom || configPath != "/etc/ssh/sshd_config"
		case strings.HasPrefix(argument, "-f") && len(argument) > 2:
			configPath := strings.TrimPrefix(argument, "-f")
			if !validSSHDConfigPath(configPath) {
				return nil, false, "sshd -f 설정 경로를 안전하게 해석할 수 없음"
			}
			configuration = append(configuration, "-f", configPath)
			custom = custom || configPath != "/etc/ssh/sshd_config"
		case argument == "-o":
			if index+1 >= len(arguments) || strings.TrimSpace(arguments[index+1]) == "" {
				return nil, false, "sshd -o 설정 값이 없음"
			}
			index++
			option := arguments[index]
			configuration = append(configuration, "-o", option)
			custom = custom || sshdOptionChangesConfigurationSources(option)
		case strings.HasPrefix(argument, "-o") && len(argument) > 2:
			option := strings.TrimPrefix(argument, "-o")
			configuration = append(configuration, "-o", option)
			custom = custom || sshdOptionChangesConfigurationSources(option)
		case argument == "-4", argument == "-6", argument == "-D", argument == "-d", argument == "-e", argument == "-i", argument == "-q", argument == "-t":
		case argument == "-c", argument == "-E", argument == "-g", argument == "-h", argument == "-p":
			if index+1 >= len(arguments) {
				return nil, false, "sshd 실행 옵션의 인수가 없음"
			}
			index++
		default:
			return nil, false, fmt.Sprintf("sshd 실행 인수 %q의 설정 영향도를 확정할 수 없음", argument)
		}
	}
	return configuration, custom, ""
}

func sshdOptionChangesConfigurationSources(option string) bool {
	key := strings.ToLower(strings.TrimSpace(option))
	if before, _, found := strings.Cut(key, "="); found {
		key = strings.TrimSpace(before)
	} else if fields := strings.Fields(key); len(fields) > 0 {
		key = fields[0]
	}
	return key == "include" || key == "match"
}

func standardSSHDExecutable(executable string) bool {
	return executable == "/usr/sbin/sshd"
}

func validSSHDConfigPath(value string) bool {
	return path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validSystemdServiceName(value string) bool {
	if !strings.HasSuffix(value, ".service") || value == ".service" {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("@_.:-", character) {
			return false
		}
	}
	return true
}

func validEnvironmentName(value string) bool {
	if value == "" || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z') || value[0] == '_') {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
