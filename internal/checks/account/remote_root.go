package account

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorRemoteRootLogin = "unix.account.remote_root_login"

func evaluateRemoteRootLogin(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "원격 root 로그인 경로를 지원하는 방식으로 확인할 수 없습니다.",
			Expected:      "systemd 기반 SSH 및 Telnet 활성 경로에서 root 직접 로그인이 차단되어야 합니다.",
			Observed:      "init=" + environment.Platform.InitSystem,
		}
	}

	sshActive, sshInstalled, sshUnits, sshEvidence, sshErr := inspectRemoteService(ctx, environment,
		[]string{"sshd.service", "sshd.socket"}, []string{"sshd"}, 22)
	if sshErr != nil {
		return checkError("ssh_target_inspection_failed", sshErr)
	}
	telnetActive, telnetInstalled, _, telnetEvidence, telnetErr := inspectRemoteService(ctx, environment,
		[]string{"telnet.socket", "telnet.service", "telnet@.service", "xinetd.service"},
		[]string{"in.telnetd", "telnetd", "xinetd"}, 23)
	if telnetErr != nil {
		return checkError("telnet_target_inspection_failed", telnetErr)
	}
	evidence := append(sshEvidence, telnetEvidence...)
	if !sshActive && !telnetActive {
		installed := append(sshInstalled, telnetInstalled...)
		sort.Strings(installed)
		observed := "활성 SSH/Telnet unit, 프로세스 또는 리스너가 없습니다."
		if len(installed) > 0 {
			observed += " 설치된 unit: " + strings.Join(installed, ", ")
		}
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "활성 원격 터미널 서비스가 없습니다.",
			Expected: "활성 SSH 또는 Telnet 경로가 있을 때 root 직접 로그인을 차단해야 합니다.",
			Observed: observed,
			Evidence: evidence,
		}
	}

	if sshActive {
		sshOutcome := evaluateSSHRootPolicy(ctx, environment, sshUnits)
		evidence = append(evidence, sshOutcome.Evidence...)
		if sshOutcome.Status == model.StatusFail || sshOutcome.Status == model.StatusError {
			sshOutcome.Evidence = evidence
			return sshOutcome
		}
		if sshOutcome.Status == model.StatusUnknown {
			if telnetActive {
				sshOutcome.Observed += "; 활성 Telnet 경로도 자동 확정할 수 없습니다."
			}
			sshOutcome.Evidence = evidence
			return sshOutcome
		}
	}

	if telnetActive {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 Telnet 인증 경로의 root 차단 실효성을 자동 확정할 수 없습니다.",
			Expected:      "Telnet의 모든 PAM, securetty 및 super-server 경로에서 root 직접 로그인이 차단되어야 합니다.",
			Observed:      "TCP 23 또는 Telnet 관련 unit/프로세스가 활성 상태입니다.",
			Evidence:      evidence,
		}
	}

	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "활성 SSH 경로에서 root 직접 로그인이 차단되어 있습니다.",
		Expected: "모든 원격 터미널 경로에서 root 직접 로그인이 차단되어야 합니다.",
		Observed: "sshd의 모든 확인 가능한 조건에서 PermitRootLogin=no이고 활성 Telnet 경로가 없습니다.",
		Evidence: evidence,
	}
}

func inspectRemoteService(
	ctx context.Context,
	environment evaluator.Environment,
	units []string,
	processNames []string,
	port int,
) (bool, []string, []support.UnitState, []model.Evidence, error) {
	states, unitEvidence, err := support.InspectUnits(ctx, environment, units)
	if err != nil {
		return false, nil, nil, nil, err
	}
	active := false
	installed := make([]string, 0)
	for _, state := range states {
		if support.UnitInstalled(state) {
			installed = append(installed, state.Name)
		}
		active = active || support.UnitActive(state)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, processNames)
	if err != nil {
		return false, nil, nil, nil, err
	}
	listeners, listenerEvidence, err := support.InspectTCPListeningPorts(ctx, environment, []int{port})
	if err != nil {
		return false, nil, nil, nil, err
	}
	active = active || len(processes) > 0 || len(listeners[port]) > 0
	evidence := append(unitEvidence, processEvidence, listenerEvidence)
	return active, installed, states, evidence, nil
}

func evaluateSSHRootPolicy(ctx context.Context, environment evaluator.Environment, unitStates []support.UnitState) evaluator.Outcome {
	launchUnits, launchUnitEvidence, launchUnitUnknowns, err := resolveSSHLaunchUnits(ctx, environment, unitStates)
	if err != nil {
		return checkError("sshd_launch_unit_inspection_failed", err)
	}
	evidence := append([]model.Evidence(nil), launchUnitEvidence...)
	launchProfiles := make([]sshLaunchProfile, 0, len(launchUnits))
	launchUnknowns := append([]string(nil), launchUnitUnknowns...)
	defaultConfigurationUsed := false
	for _, unitName := range launchUnits {
		profile, profileEvidence, unknownReason, profileErr := inspectSSHDLaunchProfile(ctx, environment, unitName)
		evidence = append(evidence, profileEvidence...)
		if profileErr != nil {
			return checkError("sshd_launch_inspection_failed", profileErr)
		}
		if unknownReason != "" {
			launchUnknowns = append(launchUnknowns, unitName+": "+unknownReason)
			continue
		}
		launchProfiles = append(launchProfiles, profile)
		defaultConfigurationUsed = defaultConfigurationUsed || !profile.CustomConfiguration
		if profile.CustomConfiguration {
			launchUnknowns = append(launchUnknowns, unitName+": 사용자 지정 SSH 설정의 모든 Match/Include 경로를 열거할 수 없음")
		}
	}

	ambiguous := false
	unsafeMatch := false
	if defaultConfigurationUsed {
		var configEvidence []model.Evidence
		ambiguous, unsafeMatch, configEvidence, err = inspectSSHDMatchOverrides(ctx, environment)
		if err != nil {
			return checkError("sshd_config_inspection_failed", err)
		}
		evidence = append(evidence, configEvidence...)
	}
	addresses := []string{"127.0.0.1", "192.0.2.1", "::1", "2001:db8::1"}
	host := strings.TrimSpace(environment.Platform.Hostname)
	if host == "" || strings.ContainsAny(host, ",=\x00\r\n") {
		host = "localhost"
	}
	unsafe := make([]string, 0)
	for _, profile := range launchProfiles {
		for _, address := range addresses {
			arguments := append([]string(nil), profile.ConfigurationArguments...)
			arguments = append(arguments, "-T", "-C", "user=root,host="+host+",addr="+address)
			spec := executor.Spec{
				Name:      "sshd",
				Arguments: arguments,
				Timeout:   15 * time.Second,
				MaxOutput: 2 << 20,
			}
			result, runErr := environment.Commands.Run(ctx, spec)
			if runErr != nil {
				return checkError("sshd_effective_config_failed", runErr)
			}
			resultEvidence := support.CommandSummaryEvidence("sshd-effective-root-policy", spec, result, map[string]any{
				"unit": profile.Unit, "address": address,
			})
			evidence = append(evidence, resultEvidence)
			if result.ExitCode != 0 || result.Truncated {
				return checkError("sshd_effective_config_failed", fmt.Errorf("unit %s address %s exit=%d truncated=%t", profile.Unit, address, result.ExitCode, result.Truncated))
			}
			settings, parseErr := parseSSHDTestOutput(string(result.Stdout))
			if parseErr != nil {
				return checkError("sshd_effective_config_parse_failed", parseErr)
			}
			value, exists := settings["permitrootlogin"]
			if !exists {
				return checkError("sshd_permit_root_login_missing", fmt.Errorf("sshd -T omitted permitrootlogin"))
			}
			resultEvidence.Fact["permit_root_login"] = value
			if !strings.EqualFold(value, "no") {
				unsafe = append(unsafe, profile.Unit+" "+address+"="+value)
			}
		}
	}
	if len(unsafe) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "SSH에서 root 직접 로그인이 허용되는 실효 구성이 있습니다.",
			Expected: "모든 SSH 연결 조건에서 PermitRootLogin이 no여야 합니다.",
			Observed: strings.Join(unsafe, ", "),
			Evidence: evidence,
		}
	}
	if unsafeMatch || ambiguous || len(launchUnknowns) > 0 || len(launchProfiles) == 0 {
		observed := "Match 블록 또는 Include 구성을 완전히 열거할 수 없습니다."
		if unsafeMatch {
			observed = "Match 블록에 PermitRootLogin=no가 아닌 재정의가 있습니다."
		} else if len(launchUnknowns) > 0 {
			sort.Strings(launchUnknowns)
			observed = strings.Join(uniqueSorted(launchUnknowns), "; ")
		} else if len(launchProfiles) == 0 {
			observed = "활성 SSH 경로의 실제 sshd 실행 구성을 확인할 수 없습니다."
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "출발지와 사용자 조건별 SSH root 로그인 정책을 모두 확정할 수 없습니다.",
			Expected:      "모든 SSH Match 조건에서 root 직접 로그인이 차단되어야 합니다.",
			Observed:      observed,
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{Status: model.StatusPass, Evidence: evidence}
}

func parseSSHDTestOutput(output string) (map[string]string, error) {
	settings := make(map[string]string)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("sshd -T line %d is invalid", lineNumber+1)
		}
		settings[strings.ToLower(fields[0])] = strings.Join(fields[1:], " ")
	}
	return settings, nil
}

func inspectSSHDMatchOverrides(ctx context.Context, environment evaluator.Environment) (ambiguous, unsafeMatch bool, evidence []model.Evidence, err error) {
	paths := []string{"/etc/ssh/sshd_config"}
	entries, readDirErr := environment.Files.ReadDir("/etc/ssh/sshd_config.d")
	if readDirErr != nil && !errors.Is(readDirErr, os.ErrNotExist) {
		return false, false, nil, readDirErr
	}
	if readDirErr == nil {
		names := make([]string, 0)
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") && filepath.Base(entry.Name()) == entry.Name() {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			paths = append(paths, "/etc/ssh/sshd_config.d/"+name)
		}
	}
	for _, path := range paths {
		data, _, readErr := environment.Files.ReadFile(ctx, path, 2<<20)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) && path != "/etc/ssh/sshd_config" {
				continue
			}
			return false, false, evidence, readErr
		}
		inMatch := false
		facts := make([]map[string]any, 0)
		for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			line := stripSSHDComment(raw)
			if line == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				ambiguous = true
				continue
			}
			keyword := strings.ToLower(fields[0])
			switch keyword {
			case "include":
				if inMatch {
					ambiguous = true
				}
				for _, pattern := range fields[1:] {
					normalized := filepath.ToSlash(pattern)
					if normalized != "/etc/ssh/sshd_config.d/*.conf" {
						ambiguous = true
					}
				}
			case "match":
				inMatch = true
				// Match conditions may span included files and can depend on
				// source addresses that are not enumerable from local state.
				ambiguous = true
				facts = append(facts, map[string]any{"line": index + 1, "keyword": "Match", "condition": strings.Join(fields[1:], " ")})
			case "permitrootlogin":
				value := strings.ToLower(fields[1])
				facts = append(facts, map[string]any{"line": index + 1, "keyword": "PermitRootLogin", "value": value, "in_match": inMatch})
				if inMatch && value != "no" {
					unsafeMatch = true
				}
			}
		}
		evidence = append(evidence, support.FactEvidence(path, map[string]any{"directives": facts}))
	}
	return ambiguous, unsafeMatch, evidence, nil
}

func stripSSHDComment(line string) string {
	quoted := false
	escaped := false
	for index, character := range line {
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			quoted = !quoted
			continue
		}
		if character == '#' && !quoted {
			return strings.TrimSpace(line[:index])
		}
	}
	return strings.TrimSpace(line)
}
