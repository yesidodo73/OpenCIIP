package service

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const EvaluatorFTPRootLogin = "unix.service.ftp_root_login"

var ftpRootLoginProducts = []serviceProduct{
	{
		id:        "vsftpd",
		label:     "vsftpd",
		units:     []string{"vsftpd.service", "vsftpd.socket"},
		processes: []string{"vsftpd"},
	},
	{
		id:        "proftpd",
		label:     "ProFTPD",
		units:     []string{"proftpd.service", "proftpd.socket"},
		processes: []string{"proftpd"},
	},
	{
		id:        "pure-ftpd",
		label:     "Pure-FTPd",
		units:     []string{"pure-ftpd.service", "pure-ftpd.socket"},
		processes: []string{"pure-ftpd"},
	},
}

func evaluateFTPRootLogin(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	target, terminal := inspectServiceTarget(ctx, environment, "FTP 서비스", ftpRootLoginProducts, []int{21, 990}, "tcp")
	if terminal != nil {
		return *terminal
	}

	switch target.product.id {
	case "vsftpd":
		return evaluateVSFTPRootLogin(ctx, environment, target)
	case "proftpd":
		return evaluateProFTPRootLogin(ctx, environment, target)
	default:
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 FTP 제품의 root 로그인 실효 설정을 확인할 수 없습니다.",
			Expected:      "모든 실제 FTP 인증 경로에서 root 로그인이 차단되어야 합니다.",
			Observed:      target.product.label,
			Evidence:      target.evidence,
		}
	}
}

func evaluateVSFTPRootLogin(ctx context.Context, environment evaluator.Environment, target serviceTarget) evaluator.Outcome {
	const configurationPath = "/etc/vsftpd/vsftpd.conf"
	data, _, err := environment.Files.ReadFile(ctx, configurationPath, 2<<20)
	if err != nil {
		return ftpRootLoginError("vsftpd_config_read_failed", err)
	}
	settings, complete, err := parseVSFTPSettings(string(data))
	if err != nil {
		return ftpRootLoginError("vsftpd_config_parse_failed", err)
	}
	evidence := append([]model.Evidence(nil), target.evidence...)
	if !complete {
		evidence = append(evidence, support.FactEvidence(configurationPath, map[string]any{"fully_interpreted": false}))
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "vsftpd 설정의 include 경로를 완전히 해석할 수 없습니다.",
			Expected:      "vsftpd의 전체 실효 설정과 PAM 인증 경로를 확인할 수 있어야 합니다.",
			Observed:      "include 또는 외부 설정 참조가 있습니다.",
			Evidence:      evidence,
		}
	}

	pamService := strings.TrimSpace(settings["pam_service_name"])
	if pamService == "" {
		pamService = "ftp"
	}
	if !validPAMServiceName(pamService) {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "vsftpd가 사용자 지정 PAM 서비스 이름을 사용합니다.",
			Expected:      "지원하는 PAM 서비스의 전체 인증 스택에서 root 차단을 확인할 수 있어야 합니다.",
			Observed:      "지원하지 않는 PAM 서비스 이름",
			Evidence:      evidence,
		}
	}

	blockedByUserList := false
	userListEnabled, err := yesNoSetting(settings, "userlist_enable", false)
	if err != nil {
		return ftpRootLoginError("vsftpd_config_parse_failed", err)
	}
	userListDeny, err := yesNoSetting(settings, "userlist_deny", true)
	if err != nil {
		return ftpRootLoginError("vsftpd_config_parse_failed", err)
	}
	userListPath := strings.TrimSpace(settings["userlist_file"])
	if userListPath == "" {
		userListPath = "/etc/vsftpd/user_list"
	}
	if userListEnabled {
		if !path.IsAbs(userListPath) {
			return unsupportedFTPConfiguration("vsftpd userlist_file이 절대 경로가 아닙니다.", evidence)
		}
		users, readErr := readAccountList(ctx, environment.Files, userListPath)
		if readErr != nil {
			return ftpRootLoginError("vsftpd_userlist_read_failed", readErr)
		}
		_, rootListed := users["root"]
		blockedByUserList = (userListDeny && rootListed) || (!userListDeny && !rootListed)
		evidence = append(evidence, support.FactEvidence(userListPath, map[string]any{
			"root_blocked": blockedByUserList,
			"mode":         map[bool]string{true: "deny_list", false: "allow_list"}[userListDeny],
		}))
	}

	pamResult, err := inspectPAMRootRestriction(ctx, environment.Files, pamService)
	if err != nil {
		return ftpRootLoginError("vsftpd_pam_parse_failed", err)
	}
	pamRootBlocked := pamResult.denied && pamResult.complete
	evidence = append(evidence, support.FactEvidence("/etc/pam.d/"+pamService, map[string]any{
		"files_inspected":    pamResult.files,
		"root_blocked":       pamRootBlocked,
		"root_deny_detected": pamResult.denied,
		"fully_interpreted":  pamResult.complete,
	}))

	expected := "모든 실제 vsftpd 사용자 목록과 PAM 인증 경로에서 root 로그인이 차단되어야 합니다."
	if blockedByUserList || pamRootBlocked {
		methods := make([]string, 0, 2)
		if blockedByUserList {
			methods = append(methods, "vsftpd user list")
		}
		if pamRootBlocked {
			methods = append(methods, "PAM")
		}
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "vsftpd의 root 로그인이 모든 확인된 인증 진입점에서 차단됩니다.",
			Expected: expected,
			Observed: "차단 경로: " + strings.Join(methods, ", "),
			Evidence: evidence,
		}
	}
	if !pamResult.complete {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "vsftpd PAM 스택의 root 접근 조건을 완전히 해석할 수 없습니다.",
			Expected:      expected,
			Observed:      "지원하지 않는 PAM 제어 흐름 또는 접근 모듈이 있습니다.",
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusFail,
		Summary:  "vsftpd의 root 로그인을 차단하는 실효 설정이 없습니다.",
		Expected: expected,
		Observed: "user list와 PAM 스택에서 root 차단 규칙을 찾지 못했습니다.",
		Evidence: evidence,
	}
}

func parseVSFTPSettings(content string) (map[string]string, bool, error) {
	settings := make(map[string]string)
	complete := true
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) == "" {
			return nil, false, fmt.Errorf("line %d is not a key=value setting", lineNumber+1)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "include" || key == "include_file" || key == "config_file" {
			complete = false
			continue
		}
		settings[key] = strings.TrimSpace(value)
	}
	return settings, complete, nil
}

func yesNoSetting(settings map[string]string, key string, defaultValue bool) (bool, error) {
	value, exists := settings[key]
	if !exists || strings.TrimSpace(value) == "" {
		return defaultValue, nil
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	default:
		return false, fmt.Errorf("setting %s is not YES or NO", key)
	}
}

type pamRootRestriction struct {
	denied    bool
	complete  bool
	denyReset bool
	files     []string
}

func inspectPAMRootRestriction(ctx context.Context, files system.Reader, serviceName string) (pamRootRestriction, error) {
	result := pamRootRestriction{complete: true}
	visited := make(map[string]struct{})
	if err := inspectPAMFile(ctx, files, serviceName, visited, false, &result); err != nil {
		return pamRootRestriction{}, err
	}
	if result.denied && !result.denyReset {
		result.complete = true
	}
	sort.Strings(result.files)
	return result, nil
}

func inspectPAMFile(
	ctx context.Context,
	files system.Reader,
	serviceName string,
	visited map[string]struct{},
	controlFlowUnknown bool,
	result *pamRootRestriction,
) error {
	if len(visited) >= 32 {
		return fmt.Errorf("PAM include depth exceeds the supported limit")
	}
	filePath := "/etc/pam.d/" + serviceName
	if _, exists := visited[filePath]; exists {
		return nil
	}
	visited[filePath] = struct{}{}
	result.files = append(result.files, filePath)
	data, _, err := files.ReadFile(ctx, filePath, 1<<20)
	if err != nil {
		return err
	}

	unknownFlow := controlFlowUnknown
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@include") {
			fields := strings.Fields(line)
			if len(fields) != 2 || !validPAMServiceName(fields[1]) {
				result.complete = false
				continue
			}
			if err := inspectPAMFile(ctx, files, fields[1], visited, unknownFlow, result); err != nil {
				return fmt.Errorf("PAM include at line %d: %w", lineNumber+1, err)
			}
			if !result.complete && !result.denied {
				unknownFlow = true
			}
			continue
		}

		facility, control, module, options, parseErr := parsePAMLine(line)
		if parseErr != nil {
			return fmt.Errorf("PAM line %d: %w", lineNumber+1, parseErr)
		}
		if facility != "auth" && facility != "account" {
			continue
		}
		control = strings.ToLower(control)
		if control == "include" || control == "substack" {
			if !validPAMServiceName(module) {
				result.complete = false
				continue
			}
			if err := inspectPAMFile(ctx, files, module, visited, unknownFlow, result); err != nil {
				return fmt.Errorf("PAM include at line %d: %w", lineNumber+1, err)
			}
			if !result.complete && !result.denied {
				unknownFlow = true
			}
			continue
		}
		if strings.HasPrefix(control, "[") || control == "sufficient" {
			if result.denied && strings.Contains(strings.ToLower(control), "=reset") {
				result.denied = false
				result.denyReset = true
			}
			unknownFlow = true
			result.complete = false
		}

		module = path.Base(module)
		switch module {
		case "pam_listfile.so":
			denied, understood, err := evaluatePAMListfile(ctx, files, control, options, unknownFlow)
			if err != nil {
				return fmt.Errorf("PAM listfile at line %d: %w", lineNumber+1, err)
			}
			if !understood {
				result.complete = false
			}
			if denied {
				result.denied = true
			}
		case "pam_access.so", "pam_exec.so", "pam_python.so", "pam_script.so", "pam_succeed_if.so", "pam_wheel.so":
			result.complete = false
		case "pam_deny.so", "pam_env.so", "pam_faillock.so", "pam_keyinit.so", "pam_lastlog.so", "pam_limits.so",
			"pam_localuser.so", "pam_mail.so", "pam_motd.so", "pam_nologin.so", "pam_permit.so", "pam_pwquality.so",
			"pam_pwhistory.so", "pam_rootok.so", "pam_sepermit.so", "pam_systemd.so", "pam_unix.so", "pam_warn.so":
			// These standard modules do not provide a static FTP root allow/deny list.
		case "pam_shells.so", "pam_sss.so":
			result.complete = false
		default:
			result.complete = false
		}
	}
	return nil
}

func parsePAMLine(line string) (string, string, string, []string, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", "", "", nil, fmt.Errorf("expected facility, control and module")
	}
	facility := strings.TrimPrefix(fields[0], "-")
	controlEnd := 1
	control := fields[1]
	if strings.HasPrefix(control, "[") {
		for !strings.HasSuffix(control, "]") {
			controlEnd++
			if controlEnd >= len(fields)-1 {
				return "", "", "", nil, fmt.Errorf("unterminated bracket control")
			}
			control += " " + fields[controlEnd]
		}
	}
	moduleIndex := controlEnd + 1
	if moduleIndex >= len(fields) {
		return "", "", "", nil, fmt.Errorf("module is missing")
	}
	return facility, control, fields[moduleIndex], fields[moduleIndex+1:], nil
}

func evaluatePAMListfile(
	ctx context.Context,
	files system.Reader,
	control string,
	options []string,
	controlFlowUnknown bool,
) (bool, bool, error) {
	values := make(map[string]string)
	for _, option := range options {
		key, value, found := strings.Cut(option, "=")
		if found {
			values[strings.ToLower(key)] = value
		}
	}
	if strings.ToLower(values["item"]) != "user" || (control != "required" && control != "requisite") || controlFlowUnknown {
		return false, false, nil
	}
	sense := strings.ToLower(values["sense"])
	if sense != "deny" && sense != "allow" {
		return false, false, nil
	}
	listPath := values["file"]
	if !path.IsAbs(listPath) {
		return false, false, nil
	}
	accounts, err := readAccountList(ctx, files, listPath)
	if err != nil {
		return false, false, err
	}
	_, listed := accounts["root"]
	return (sense == "deny" && listed) || (sense == "allow" && !listed), true, nil
}

func readAccountList(ctx context.Context, files system.Reader, filePath string) (map[string]struct{}, error) {
	data, _, err := files.ReadFile(ctx, filePath, 1<<20)
	if err != nil {
		return nil, err
	}
	accounts := make(map[string]struct{})
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := strings.Fields(line)[0]
		accounts[name] = struct{}{}
	}
	return accounts, nil
}

func validPAMServiceName(value string) bool {
	if value == "" || strings.HasPrefix(value, ".") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func evaluateProFTPRootLogin(ctx context.Context, environment evaluator.Environment, target serviceTarget) evaluator.Outcome {
	const configurationPath = "/etc/proftpd.conf"
	data, _, err := environment.Files.ReadFile(ctx, configurationPath, 2<<20)
	if err != nil {
		return ftpRootLoginError("proftpd_config_read_failed", err)
	}
	rootLogin, found, complete, err := parseProFTPRootLogin(string(data))
	if err != nil {
		return ftpRootLoginError("proftpd_config_parse_failed", err)
	}
	evidence := append(append([]model.Evidence(nil), target.evidence...), support.FactEvidence(configurationPath, map[string]any{
		"fully_interpreted": complete,
		"root_login_set":    found,
		"root_login":        rootLogin,
	}))
	if !complete || !found {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "ProFTPD의 include, 조건부 범위 또는 RootLogin 실효값을 완전히 해석할 수 없습니다.",
			Expected:      "모든 활성 ProFTPD 서버 범위에서 RootLogin이 비활성화되어야 합니다.",
			Observed:      "단일 전역 RootLogin 값을 확정할 수 없습니다.",
			Evidence:      evidence,
		}
	}
	expected := "전역 ProFTPD RootLogin 설정이 비활성화되어야 합니다."
	if !rootLogin {
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "ProFTPD의 root 로그인이 비활성화되어 있습니다.",
			Expected: expected,
			Observed: "RootLogin=off",
			Evidence: evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusFail,
		Summary:  "ProFTPD가 root 로그인을 허용하고 있습니다.",
		Expected: expected,
		Observed: "RootLogin=on",
		Evidence: evidence,
	}
}

func parseProFTPRootLogin(content string) (bool, bool, bool, error) {
	rootLogin := false
	found := false
	complete := true
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line, _, _ := strings.Cut(raw, "#")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		if directive == "include" || strings.HasPrefix(line, "<") {
			complete = false
			continue
		}
		if directive != "rootlogin" {
			continue
		}
		if len(fields) != 2 {
			return false, false, false, fmt.Errorf("line %d has an invalid RootLogin directive", lineNumber+1)
		}
		switch strings.ToLower(fields[1]) {
		case "off", "no", "false":
			rootLogin = false
		case "on", "yes", "true":
			rootLogin = true
		default:
			return false, false, false, fmt.Errorf("line %d has an invalid RootLogin value", lineNumber+1)
		}
		found = true
	}
	return rootLogin, found, complete, nil
}

func unsupportedFTPConfiguration(observed string, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownUnsupportedConfiguration,
		Summary:       "FTP root 로그인 설정을 결정적으로 해석할 수 없습니다.",
		Expected:      "모든 실제 FTP 인증 경로에서 root 로그인이 차단되어야 합니다.",
		Observed:      observed,
		Evidence:      evidence,
	}
}

func ftpRootLoginError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "FTP root 로그인 설정을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
