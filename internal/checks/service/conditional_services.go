package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorDoSProneDisabled = "unix.service.dos_prone_disabled"
	EvaluatorNFSDisabled      = "unix.service.nfs_disabled"
	EvaluatorAutofsDisabled   = "unix.service.autofs_disabled"
	EvaluatorRPCDisabled      = "unix.service.rpc_disabled"
)

func evaluateDoSProneDisabled(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	legacy := disabledEvaluator(disabledPolicy{
		label: "Echo, Discard, Daytime 및 Chargen",
		units: []string{
			"echo.service", "echo.socket", "echo-dgram.service", "echo-dgram.socket",
			"discard.service", "discard.socket", "discard-dgram.service", "discard-dgram.socket",
			"daytime.service", "daytime.socket", "daytime-dgram.service", "daytime-dgram.socket",
			"chargen.service", "chargen.socket", "chargen-dgram.service", "chargen-dgram.socket",
		},
		ports:     []int{7, 9, 13, 19},
		processes: []string{"in.echod", "in.discardd", "in.daytimed", "in.chargend"},
		xinetdServices: []string{
			"echo", "echo-stream", "echo-dgram",
			"discard", "discard-stream", "discard-dgram",
			"daytime", "daytime-stream", "daytime-dgram",
			"chargen", "chargen-stream", "chargen-dgram",
		},
	})(ctx, rule, environment)
	if legacy.Status == model.StatusFail || legacy.Status == model.StatusError || legacy.Status == model.StatusUnknown {
		return legacy
	}

	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{
		"chronyd.service", "named.service", "named-chroot.service", "snmpd.service", "postfix.service", "sendmail.service",
	})
	if err != nil {
		return serviceError("additional_service_inspection_failed", "DoS 관련 추가", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"chronyd", "named", "snmpd", "master", "sendmail"})
	if err != nil {
		return serviceError("additional_process_inspection_failed", "DoS 관련 추가", err)
	}
	active := append([]string(nil), processes...)
	for _, unit := range units {
		if support.UnitActive(unit) || support.UnitEnabled(unit) {
			active = append(active, unit.Name)
		}
	}
	if len(active) == 0 {
		legacy.Evidence = append(legacy.Evidence, unitEvidence...)
		legacy.Evidence = append(legacy.Evidence, processEvidence)
		return legacy
	}
	sort.Strings(active)
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "legacy 응답 서비스는 비활성이나 추가 네트워크 서비스의 업무 필요성을 확인해야 합니다.",
		Expected:      "Echo, Discard, Daytime, Chargen은 비활성화하고 NTP·DNS·SNMP·SMTP는 승인된 업무 서비스만 사용해야 합니다.",
		Observed:      "활성 또는 부팅 활성 후보: " + strings.Join(uniqueStrings(active), ", "),
		Evidence:      append(append(legacy.Evidence, unitEvidence...), processEvidence),
	}
}

func evaluateNFSDisabled(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return unsupportedConditionalService("NFS", environment.Platform.InitSystem)
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{
		"nfs-server.service", "nfs-mountd.service", "nfs-idmapd.service", "nfsdcld.service",
		"nfs-ganesha.service",
	})
	if err != nil {
		return serviceError("nfs_unit_inspection_failed", "NFS", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"nfsd", "rpc.nfsd", "rpc.mountd", "ganesha.nfsd"})
	if err != nil {
		return serviceError("nfs_process_inspection_failed", "NFS", err)
	}
	evidence := append(unitEvidence, processEvidence)
	activeSignals := append([]string(nil), processes...)
	installed := false
	for _, unit := range units {
		installed = installed || support.UnitInstalled(unit)
		if support.UnitActive(unit) || support.UnitEnabled(unit) {
			activeSignals = append(activeSignals, unit.Name)
		}
	}
	listeners, listenerEvidence, err := support.InspectListeningPorts(ctx, environment, []int{2049})
	if err != nil {
		return serviceError("nfs_listener_inspection_failed", "NFS", err)
	}
	evidence = append(evidence, listenerEvidence)
	if len(listeners[2049]) > 0 {
		activeSignals = append(activeSignals, "port 2049 listening")
	}
	if threads, threadEvidence, exists, readErr := readNFSDThreads(ctx, environment); readErr != nil {
		return serviceError("nfsd_state_failed", "NFS", readErr)
	} else {
		evidence = append(evidence, threadEvidence)
		if exists && threads > 0 {
			activeSignals = append(activeSignals, fmt.Sprintf("nfsd threads=%d", threads))
		}
	}
	configured, configEvidence, configErr := inspectNFSExports(ctx, environment)
	if configErr != nil {
		return serviceError("nfs_exports_inspection_failed", "NFS", configErr)
	}
	evidence = append(evidence, configEvidence...)
	if environment.Commands.Available("exportfs") {
		spec := executor.Spec{Name: "exportfs", Arguments: []string{"-v"}, Timeout: 20 * time.Second, MaxOutput: 4 << 20}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return serviceError("nfs_exportfs_failed", "NFS", runErr)
		}
		evidence = append(evidence, privateCommandSummary(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return serviceError("nfs_exportfs_failed", "NFS", fmt.Errorf("exit=%d truncated=%t", result.ExitCode, result.Truncated))
		}
		if nonEmptyLines(result.Stdout) > 0 {
			activeSignals = append(activeSignals, "exportfs active exports")
		}
	}
	required, policySet, parameterErr := support.BoolParameter(rule.Parameters, "nfs_required")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "NFS", parameterErr)
	}
	activeSignals = uniqueStrings(activeSignals)
	active := len(activeSignals) > 0
	if !installed && !configured && !active {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "NFS 서버 구성요소와 export가 없습니다.", Expected: "불필요한 NFS 서버는 비활성화되어야 합니다.", Observed: "NFS server unit, process, thread, export 없음", Evidence: evidence}
	}
	if policySet && required {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "기관 정책에서 NFS 서버 사용을 필요한 업무 서비스로 지정했습니다.", Expected: "불필요한 NFS 서버에만 비활성화 기준을 적용합니다.", Observed: fmt.Sprintf("nfs_required=true active=%t configured=%t", active, configured), Evidence: evidence}
	}
	if active {
		if policySet {
			return evaluator.Outcome{Status: model.StatusFail, Summary: "불필요하다고 지정된 NFS 서버의 활성 경로가 있습니다.", Expected: "nfs_required=false이면 unit, 프로세스, nfsd thread와 export가 모두 비활성이어야 합니다.", Observed: strings.Join(activeSignals, "; "), Evidence: evidence}
		}
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "활성 NFS 서버의 업무 필요성을 확인해야 합니다.", Expected: "기관 정책으로 NFS 서버 필요 여부를 확인해야 합니다.", Observed: strings.Join(activeSignals, "; "), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "NFS 서버의 활성 경로가 없습니다.", Expected: "불필요한 NFS 서버의 unit, 프로세스, nfsd thread와 export가 비활성이어야 합니다.", Observed: fmt.Sprintf("active=false configured=%t", configured), Evidence: evidence}
}

func evaluateAutofsDisabled(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return unsupportedConditionalService("autofs", environment.Platform.InitSystem)
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{"autofs.service"})
	if err != nil {
		return serviceError("autofs_unit_inspection_failed", "autofs", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"automount"})
	if err != nil {
		return serviceError("autofs_process_inspection_failed", "autofs", err)
	}
	evidence := append(unitEvidence, processEvidence)
	active := len(processes) > 0
	installed := false
	for _, unit := range units {
		installed = installed || support.UnitInstalled(unit)
		active = active || support.UnitActive(unit) || support.UnitEnabled(unit)
	}
	configured, configEvidence, configErr := staticConfigPresence(ctx, environment, "/etc/auto.master", "/etc/auto.master.d", ".autofs")
	if configErr != nil {
		return serviceError("autofs_config_inspection_failed", "autofs", configErr)
	}
	evidence = append(evidence, configEvidence...)
	required, policySet, parameterErr := support.BoolParameter(rule.Parameters, "autofs_required")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "autofs", parameterErr)
	}
	if !installed && !configured && !active {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "autofs 구성요소가 없습니다.", Expected: "불필요한 autofs는 비활성화되어야 합니다.", Observed: "unit, process, map 없음", Evidence: evidence}
	}
	if policySet && required {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "기관 정책에서 autofs 사용을 필요한 업무 기능으로 지정했습니다.", Expected: "불필요한 autofs에만 비활성화 기준을 적용합니다.", Observed: fmt.Sprintf("autofs_required=true active=%t", active), Evidence: evidence}
	}
	if active {
		if policySet {
			return evaluator.Outcome{Status: model.StatusFail, Summary: "불필요하다고 지정된 autofs가 활성화되어 있습니다.", Expected: "autofs_required=false이면 unit과 automount 프로세스가 비활성이어야 합니다.", Observed: "autofs active or enabled", Evidence: evidence}
		}
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "활성 autofs의 업무 필요성을 확인해야 합니다.", Expected: "기관 정책으로 autofs 필요 여부를 확인해야 합니다.", Observed: "autofs active or enabled", Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "autofs가 비활성화되어 있습니다.", Expected: "불필요한 autofs unit과 프로세스가 비활성이어야 합니다.", Observed: fmt.Sprintf("active=false configured=%t", configured), Evidence: evidence}
}

func evaluateRPCDisabled(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return unsupportedConditionalService("RPC", environment.Platform.InitSystem)
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{
		"rpcbind.service", "rpcbind.socket", "rpc-statd.service", "rstatd.service", "rusersd.service",
		"walld.service", "sprayd.service", "rexd.service", "rquotad.service",
	})
	if err != nil {
		return serviceError("rpc_unit_inspection_failed", "RPC", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{
		"rpcbind", "rpc.statd", "rpc.rstatd", "rpc.rusersd", "rpc.rwalld", "rpc.sprayd", "rpc.rexd", "rpc.rquotad",
	})
	if err != nil {
		return serviceError("rpc_process_inspection_failed", "RPC", err)
	}
	evidence := append(unitEvidence, processEvidence)
	installed := false
	active := make([]string, 0)
	for _, unit := range units {
		installed = installed || support.UnitInstalled(unit)
		if support.UnitActive(unit) || support.UnitEnabled(unit) {
			active = append(active, strings.TrimSuffix(strings.TrimSuffix(unit.Name, ".service"), ".socket"))
		}
	}
	for _, process := range processes {
		active = append(active, strings.TrimPrefix(process, "rpc."))
	}
	if len(active) > 0 && environment.Commands.Available("rpcinfo") {
		spec := executor.Spec{Name: "rpcinfo", Arguments: []string{"-p"}, Timeout: 20 * time.Second, MaxOutput: 2 << 20}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return serviceError("rpcinfo_failed", "RPC", runErr)
		}
		evidence = append(evidence, privateCommandSummary(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return serviceError("rpcinfo_failed", "RPC", fmt.Errorf("exit=%d truncated=%t", result.ExitCode, result.Truncated))
		}
		services, parseErr := parseRPCInfo(result.Stdout)
		if parseErr != nil {
			return serviceError("rpcinfo_parse_failed", "RPC", parseErr)
		}
		active = append(active, services...)
	}
	active = uniqueStrings(active)
	if !installed && len(active) == 0 {
		return evaluator.Outcome{Status: model.StatusNotApplicable, Summary: "RPC framework와 대상 daemon이 없습니다.", Expected: "불필요한 RPC daemon은 비활성화되어야 합니다.", Observed: "RPC unit 및 process 없음", Evidence: evidence}
	}
	if len(active) == 0 {
		return evaluator.Outcome{Status: model.StatusPass, Summary: "RPC daemon의 활성 경로가 없습니다.", Expected: "불필요한 RPC daemon은 비활성화되어야 합니다.", Observed: "설치된 RPC unit이 inactive이고 disabled 상태입니다.", Evidence: evidence}
	}
	approved, policySet, parameterErr := support.StringSliceParameter(rule.Parameters, "approved_rpc_services")
	if parameterErr != nil {
		return serviceError("invalid_rule_parameter", "RPC", parameterErr)
	}
	if !policySet {
		return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownManualVerification, Summary: "활성 RPC 프로그램의 업무 필요성과 NFS 의존성을 확인해야 합니다.", Expected: "approved_rpc_services 정책과 활성 RPC 프로그램을 대조해야 합니다.", Observed: strings.Join(active, ", "), Evidence: evidence}
	}
	approvedSet := make(map[string]bool, len(approved))
	for _, item := range approved {
		item = strings.TrimSpace(item)
		if item == "" || strings.ContainsAny(item, " \t/\\:") {
			return serviceError("invalid_rule_parameter", "RPC", fmt.Errorf("invalid approved RPC service %q", item))
		}
		approvedSet[item] = true
	}
	unapproved := make([]string, 0)
	for _, item := range active {
		if !approvedSet[item] {
			unapproved = append(unapproved, item)
		}
	}
	if len(unapproved) > 0 {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "승인되지 않은 RPC daemon이 활성화되어 있습니다.", Expected: "활성 RPC 프로그램이 approved_rpc_services 정책에 포함되어야 합니다.", Observed: strings.Join(unapproved, ", "), Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "활성 RPC 프로그램이 모두 승인 목록에 포함되어 있습니다.", Expected: "활성 RPC 프로그램이 approved_rpc_services 정책에 포함되어야 합니다.", Observed: strings.Join(active, ", "), Evidence: evidence}
}

func readNFSDThreads(ctx context.Context, environment evaluator.Environment) (int, model.Evidence, bool, error) {
	data, _, err := environment.Files.ReadFile(ctx, "/proc/fs/nfsd/threads", 4<<10)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, support.FactEvidence("/proc/fs/nfsd/threads", map[string]any{"exists": false}), false, nil
		}
		return 0, model.Evidence{}, false, err
	}
	threads, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || threads < 0 {
		return 0, model.Evidence{}, true, fmt.Errorf("invalid nfsd thread count")
	}
	return threads, support.FactEvidence("/proc/fs/nfsd/threads", map[string]any{"exists": true, "threads": threads}), true, nil
}

func inspectNFSExports(ctx context.Context, environment evaluator.Environment) (bool, []model.Evidence, error) {
	configured, evidence, err := staticConfigPresence(ctx, environment, "/etc/exports", "/etc/exports.d", ".exports")
	return configured, evidence, err
}

func staticConfigPresence(ctx context.Context, environment evaluator.Environment, mainFile, directory, suffix string) (bool, []model.Evidence, error) {
	paths := []string{mainFile}
	entries, err := environment.Files.ReadDir(directory)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, nil, err
	}
	if err == nil {
		names := make([]string, 0)
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), suffix) && path.Base(entry.Name()) == entry.Name() {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			paths = append(paths, path.Join(directory, name))
		}
	}
	configured := false
	evidence := make([]model.Evidence, 0, len(paths))
	for _, filePath := range paths {
		data, _, readErr := environment.Files.ReadFile(ctx, filePath, 2<<20)
		if readErr != nil {
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			return false, evidence, readErr
		}
		count := 0
		for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
			line, _, _ := strings.Cut(raw, "#")
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		configured = configured || count > 0
		digest := sha256.Sum256(data)
		evidence = append(evidence, support.FactEvidence(filePath, map[string]any{"directive_count": count, "sha256": fmt.Sprintf("%x", digest), "content_redacted": true}))
	}
	return configured, evidence, nil
}

func privateCommandSummary(spec executor.Spec, result executor.Result) model.Evidence {
	stdoutDigest := sha256.Sum256(result.Stdout)
	stderrDigest := sha256.Sum256(result.Stderr)
	return support.FactEvidence(spec.Name, map[string]any{
		"executable": result.Executable, "arguments": spec.EvidenceArguments(), "exit_code": result.ExitCode,
		"duration_ms": result.Duration.Milliseconds(), "stdout_sha256": fmt.Sprintf("%x", stdoutDigest),
		"stderr_sha256": fmt.Sprintf("%x", stderrDigest), "stdout_line_count": nonEmptyLines(result.Stdout), "content_redacted": true,
	})
}

func nonEmptyLines(data []byte) int {
	count := 0
	for _, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(raw) != "" {
			count++
		}
	}
	return count
}

func parseRPCInfo(data []byte) ([]string, error) {
	services := make([]string, 0)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 0 || strings.EqualFold(fields[0], "program") {
			continue
		}
		if len(fields) < 4 {
			return nil, fmt.Errorf("rpcinfo line %d has fewer than 4 fields", lineNumber+1)
		}
		if _, err := strconv.ParseUint(fields[0], 10, 32); err != nil {
			return nil, fmt.Errorf("rpcinfo line %d has invalid program", lineNumber+1)
		}
		name := "program-" + fields[0]
		if len(fields) >= 5 && fields[4] != "" {
			name = fields[4]
		}
		services = append(services, name)
	}
	return uniqueStrings(services), nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func unsupportedConditionalService(label, initSystem string) evaluator.Outcome {
	return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: label + " 서비스 상태를 지원하는 방식으로 확인할 수 없습니다.", Expected: "systemd 기반 Rocky Linux 9.8 환경이 필요합니다.", Observed: "init=" + initSystem}
}
