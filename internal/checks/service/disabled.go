package service

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const (
	EvaluatorFingerDisabled         = "unix.service.finger_disabled"
	EvaluatorRCommandsDisabled      = "unix.service.r_commands_disabled"
	EvaluatorNISDisabled            = "unix.service.nis_disabled"
	EvaluatorLegacyDatagramDisabled = "unix.service.legacy_datagram_disabled"
	EvaluatorTelnetDisabled         = "unix.service.telnet_disabled"
	EvaluatorSNMPDisabled           = "unix.service.snmp_disabled"
)

type disabledPolicy struct {
	label          string
	units          []string
	ports          []int
	processes      []string
	xinetdServices []string
}

func Implementations() map[string]evaluator.Func {
	return map[string]evaluator.Func{
		EvaluatorDoSProneDisabled:         evaluateDoSProneDisabled,
		EvaluatorNFSDisabled:              evaluateNFSDisabled,
		EvaluatorNFSAccessControl:         evaluateNFSAccessControl,
		EvaluatorAutofsDisabled:           evaluateAutofsDisabled,
		EvaluatorRPCDisabled:              evaluateRPCDisabled,
		EvaluatorMailPatchLevel:           evaluateMailPatchLevel,
		EvaluatorMailQueueRestriction:     evaluateMailQueueRestriction,
		EvaluatorMailRelay:                evaluateMailRelay,
		EvaluatorDNSZoneTransfer:          evaluateDNSZoneTransfer,
		EvaluatorDNSDynamicUpdate:         evaluateDNSDynamicUpdate,
		EvaluatorMailUserEnumeration:      evaluateMailUserEnumeration,
		EvaluatorFTPBanner:                evaluateFTPBanner,
		EvaluatorPlaintextFTPDisabled:     evaluatePlaintextFTPDisabled,
		EvaluatorFTPAccountShell:          evaluateFTPAccountShell,
		EvaluatorFTPAccessControl:         evaluateFTPAccessControl,
		EvaluatorFTPRootLogin:             evaluateFTPRootLogin,
		EvaluatorSNMPVersion:              evaluateSNMPVersion,
		EvaluatorSNMPCredentialComplexity: evaluateSNMPCredentialComplexity,
		EvaluatorSNMPAccessControl:        evaluateSNMPAccessControl,
		EvaluatorAnonymousShare:           evaluateAnonymousShare,
		EvaluatorSchedulerPermissions:     evaluateSchedulerPermissions,
		EvaluatorLoginWarning:             evaluateLoginWarning,
		EvaluatorSudoersPermissions:       evaluateSudoersPermissions,
		EvaluatorFingerDisabled: disabledEvaluator(disabledPolicy{
			label:          "Finger",
			units:          []string{"finger.service", "finger.socket", "finger@.service"},
			ports:          []int{79},
			processes:      []string{"fingerd", "in.fingerd"},
			xinetdServices: []string{"finger"},
		}),
		EvaluatorRCommandsDisabled: disabledEvaluator(disabledPolicy{
			label:          "r 계열",
			units:          []string{"rexec.service", "rexec.socket", "rexec@.service", "rlogin.service", "rlogin.socket", "rlogin@.service", "rsh.service", "rsh.socket", "rsh@.service"},
			ports:          []int{512, 513, 514},
			processes:      []string{"in.rexecd", "in.rlogind", "in.rshd", "rexecd", "rlogind", "rshd"},
			xinetdServices: []string{"exec", "rexec", "login", "rlogin", "shell", "rsh"},
		}),
		EvaluatorNISDisabled: disabledEvaluator(disabledPolicy{
			label:     "NIS",
			units:     []string{"ypserv.service", "ypbind.service", "ypxfrd.service", "yppasswdd.service", "ypupdated.service"},
			processes: []string{"ypserv", "ypbind", "ypxfrd", "rpc.yppasswdd", "rpc.ypupdated"},
		}),
		EvaluatorLegacyDatagramDisabled: disabledEvaluator(disabledPolicy{
			label:          "TFTP 및 Talk",
			units:          []string{"tftp.service", "tftp.socket", "tftp@.service", "talk.service", "talk.socket", "talk@.service", "ntalk.service", "ntalk.socket", "ntalk@.service"},
			ports:          []int{69, 517, 518},
			processes:      []string{"in.tftpd", "tftpd", "in.talkd", "in.ntalkd", "talkd", "ntalkd"},
			xinetdServices: []string{"tftp", "talk", "ntalk"},
		}),
		EvaluatorTelnetDisabled: disabledEvaluator(disabledPolicy{
			label:          "Telnet",
			units:          []string{"telnet.service", "telnet.socket", "telnet@.service"},
			ports:          []int{23},
			processes:      []string{"in.telnetd", "telnetd"},
			xinetdServices: []string{"telnet"},
		}),
		EvaluatorSNMPDisabled: disabledEvaluator(disabledPolicy{
			label:     "SNMP",
			units:     []string{"snmpd.service", "snmpd.socket", "snmptrapd.service", "snmptrapd.socket"},
			ports:     []int{161, 162},
			processes: []string{"snmpd", "snmptrapd"},
		}),
	}
}

func disabledEvaluator(policy disabledPolicy) evaluator.Func {
	return func(ctx context.Context, _ model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
		if environment.Platform.InitSystem != "systemd" {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       fmt.Sprintf("%s 서비스의 현재 상태와 부팅 시 활성 상태를 함께 확인할 수 없습니다.", policy.label),
				Expected:      "systemd 기반 Linux 환경이 필요합니다.",
				Observed:      environment.Platform.InitSystem,
			}
		}
		units, unitEvidence, err := support.InspectUnits(ctx, environment, policy.units)
		if err != nil {
			return serviceError("systemd_inspection_failed", policy.label, err)
		}
		listeners := make(map[int][]string)
		evidence := append([]model.Evidence(nil), unitEvidence...)
		violations := make([]string, 0)
		if len(policy.ports) > 0 {
			var listenerEvidence model.Evidence
			listeners, listenerEvidence, err = support.InspectListeningPorts(ctx, environment, policy.ports)
			if err != nil {
				return serviceError("listener_inspection_failed", policy.label, err)
			}
			evidence = append(evidence, listenerEvidence)
		}
		if len(policy.processes) > 0 {
			processes, processEvidence, processErr := support.InspectProcesses(ctx, environment, policy.processes)
			if processErr != nil {
				return serviceError("process_inspection_failed", policy.label, processErr)
			}
			evidence = append(evidence, processEvidence)
			for _, process := range processes {
				violations = append(violations, process+" process running")
			}
		}
		xinetdComplete := true
		xinetdConfigured := 0
		if len(policy.xinetdServices) > 0 {
			xinetd, xinetdErr := inspectXinetdServices(ctx, environment, policy.xinetdServices)
			if xinetdErr != nil {
				return serviceError("xinetd_configuration_inspection_failed", policy.label, xinetdErr)
			}
			evidence = append(evidence, xinetd.Evidence)
			xinetdConfigured = xinetd.Configured
			xinetdComplete = xinetd.Complete
			if xinetd.Enabled > 0 {
				violations = append(violations, fmt.Sprintf("xinetd target service enabled (%d)", xinetd.Enabled))
			}
		}
		installed := false
		for _, unit := range units {
			if support.UnitInstalled(unit) {
				installed = true
			}
			if support.UnitActive(unit) {
				violations = append(violations, unit.Name+" active")
			}
			if support.UnitEnabled(unit) {
				violations = append(violations, unit.Name+" enabled")
			}
		}
		for port, lines := range listeners {
			for range lines {
				violations = append(violations, fmt.Sprintf("port %d listening", port))
			}
		}
		sort.Strings(violations)
		if len(violations) > 0 {
			return evaluator.Outcome{
				Status:   model.StatusFail,
				Summary:  fmt.Sprintf("%s 서비스의 활성 경로가 발견되었습니다.", policy.label),
				Expected: "관련 서비스, 소켓 및 리스닝 포트가 비활성화되어야 합니다.",
				Observed: strings.Join(violations, "; "),
				Evidence: evidence,
			}
		}
		if !xinetdComplete {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       fmt.Sprintf("%s 서비스의 xinetd 실효 비활성 상태를 확정할 수 없습니다.", policy.label),
				Expected:      "xinetd include 그래프와 서비스별 disable 제어를 결정적으로 확인할 수 있어야 합니다.",
				Observed:      fmt.Sprintf("xinetd target block=%d, configuration_complete=false", xinetdConfigured),
				Evidence:      evidence,
			}
		}
		installed = installed || xinetdConfigured > 0
		if !installed {
			return evaluator.Outcome{
				Status:   model.StatusNotApplicable,
				Summary:  fmt.Sprintf("%s 서버 구성요소가 설치되어 있지 않습니다.", policy.label),
				Expected: "관련 서버 구성요소가 없거나 비활성화되어야 합니다.",
				Observed: "systemd unit 및 listener 없음",
				Evidence: evidence,
			}
		}
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  fmt.Sprintf("%s 서비스가 비활성화되어 있습니다.", policy.label),
			Expected: "관련 서비스, 소켓 및 리스닝 포트가 비활성화되어야 합니다.",
			Observed: "설치된 구성요소가 inactive이며 enabled 상태가 아니고 listener가 없습니다.",
			Evidence: evidence,
		}
	}
}

func serviceError(code, label string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      fmt.Sprintf("%s 서비스 상태를 확인하지 못했습니다.", label),
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
