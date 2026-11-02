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
	return disabledEvaluator(disabledPolicy{
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
		return evaluator.Outcome{Status: model.StatusPass, Summary: "NFS 서버 구성요소와 export가 없어 비활성 상태입니다.", Expected: rule.Criteria.Pass, Observed: "NFS server unit, process, thread, export 없음", Evidence: evidence}
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
	if !installed && !configured && !active {
		return evaluator.Outcome{Status: model.StatusPass, Summary: "automountd 구성요소가 없어 비활성 상태입니다.", Expected: rule.Criteria.Pass, Observed: "unit, process, map 없음", Evidence: evidence}
	}
	if active {
		return evaluator.Outcome{Status: model.StatusFail, Summary: "automountd 서비스가 활성화되어 있습니다.", Expected: rule.Criteria.Pass, Observed: "autofs active or enabled", Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusPass, Summary: "automountd 서비스가 비활성화되어 있습니다.", Expected: rule.Criteria.Pass, Observed: fmt.Sprintf("active=false configured=%t", configured), Evidence: evidence}
}

func evaluateRPCDisabled(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	if environment.Platform.InitSystem != "systemd" {
		return unsupportedConditionalService("RPC", environment.Platform.InitSystem)
	}
	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{
		"rpc-statd.service", "rstatd.service", "rusersd.service",
		"walld.service", "sprayd.service", "rexd.service", "rquotad.service",
		"ypupdated.service",
	})
	if err != nil {
		return serviceError("rpc_unit_inspection_failed", "RPC", err)
	}
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{
		"rpc.statd", "rpc.rstatd", "rpc.rusersd", "rpc.rwalld", "rpc.sprayd", "rpc.rexd", "rpc.rquotad", "rpc.ypupdated",
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
	active = uniqueStrings(active)
	if !installed && len(active) == 0 {
		return evaluator.Outcome{Status: model.StatusPass, Summary: "점검 대상 RPC 서비스가 없어 비활성 상태입니다.", Expected: rule.Criteria.Pass, Observed: "대상 RPC unit 및 process 없음", Evidence: evidence}
	}
	if len(active) == 0 {
		return evaluator.Outcome{Status: model.StatusPass, Summary: "점검 대상 RPC 서비스가 비활성화되어 있습니다.", Expected: rule.Criteria.Pass, Observed: "설치된 대상 RPC unit이 inactive이고 disabled 상태입니다.", Evidence: evidence}
	}
	return evaluator.Outcome{Status: model.StatusFail, Summary: "불필요한 RPC 서비스가 활성화되어 있습니다.", Expected: rule.Criteria.Pass, Observed: strings.Join(active, ", "), Evidence: evidence}
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
	return evaluator.Outcome{Status: model.StatusUnknown, UnknownReason: model.UnknownUnsupportedConfiguration, Summary: label + " 서비스의 현재 상태와 부팅 시 활성 상태를 함께 확인할 수 없습니다.", Expected: "서비스의 현재 상태와 부팅 시 활성 상태를 모두 확인할 수 있어야 합니다.", Observed: "init=" + initSystem}
}
