package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const EvaluatorIngressRestriction = "unix.network.ingress_restriction"

func Implementations() map[string]evaluator.Func {
	return map[string]evaluator.Func{
		EvaluatorIngressRestriction: evaluateIngressRestriction,
	}
}

type listenerInventory struct {
	total         int
	tcp           int
	udp           int
	wildcard      int
	specific      int
	configuration []string
}

func evaluateIngressRestriction(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	listeners, listenerEvidence, err := inspectRemoteListeners(ctx, environment)
	if err != nil {
		return ingressError("listener_collection_failed", err, nil)
	}
	evidence := []model.Evidence{listenerEvidence}
	if listeners.total == 0 {
		return evaluator.Outcome{
			Status:   model.StatusPass,
			Summary:  "외부 인터페이스에서 수신하는 TCP 또는 UDP 서비스가 없습니다.",
			Expected: rule.Criteria.Pass,
			Observed: "원격 접속 가능한 수신 소켓 0개",
			Evidence: evidence,
		}
	}

	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "방화벽 서비스의 현재 상태와 부팅 시 활성 상태를 함께 확인할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("원격 수신 소켓 %d개, init system=%s", listeners.total, nonEmpty(environment.Platform.InitSystem, "unknown")),
			Evidence:      evidence,
		}
	}

	units, rawUnitEvidence, err := support.InspectUnits(ctx, environment, []string{
		"firewalld.service",
		"nftables.service",
		"iptables.service",
		"ip6tables.service",
	})
	if err != nil {
		return ingressError("firewall_unit_collection_failed", err, evidence)
	}
	if len(units) != 4 {
		return ingressError("firewall_unit_collection_failed", fmt.Errorf("unexpected firewall unit count"), evidence)
	}
	evidence = append(evidence, summarizedFirewallUnitEvidence(units, rawUnitEvidence))

	if !environment.Commands.Available("nft") {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "실효 nftables 규칙을 수집할 수 없어 인바운드 통제를 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("원격 수신 소켓 %d개, nft 명령을 사용할 수 없음", listeners.total),
			Evidence:      evidence,
		}
	}

	nftState, nftEvidence, err := inspectNFTRuleset(ctx, environment)
	if err != nil {
		return ingressError("nft_ruleset_collection_failed", err, evidence)
	}
	evidence = append(evidence, nftEvidence)

	firewalldActive := support.UnitActive(units[0])
	firewalldEnabled := support.UnitEnabled(units[0])
	nftablesActive := support.UnitActive(units[1])
	nftablesEnabled := support.UnitEnabled(units[1])
	legacyActive := support.UnitActive(units[2]) || support.UnitActive(units[3])
	legacyEnabled := support.UnitEnabled(units[2]) || support.UnitEnabled(units[3])

	var firewalldState *firewalldInspection
	if firewalldActive {
		if !environment.Commands.Available("firewall-cmd") {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "실행 중인 firewalld의 런타임 및 영구 구성을 수집할 수 없습니다.",
				Expected:      rule.Criteria.Pass,
				Observed:      fmt.Sprintf("원격 수신 소켓 %d개, firewall-cmd 명령을 사용할 수 없음", listeners.total),
				Evidence:      evidence,
			}
		}
		collected, firewalldEvidence, collectErr := inspectFirewalld(ctx, environment)
		if collectErr != nil {
			return ingressError("firewalld_collection_failed", collectErr, evidence)
		}
		firewalldState = &collected
		evidence = append(evidence, firewalldEvidence)
	}

	configuredUnits := make([]support.UnitState, 0, len(units))
	for _, unit := range units {
		if support.UnitActive(unit) || support.UnitEnabled(unit) {
			configuredUnits = append(configuredUnits, unit)
		}
	}
	for _, unit := range configuredUnits {
		if nonstandardFirewallUnit(unit) {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "비표준 systemd 방화벽 유닛 구성이 있어 부팅 시 실효 정책을 자동으로 확정할 수 없습니다.",
				Expected:      rule.Criteria.Pass,
				Observed:      fmt.Sprintf("원격 수신 소켓 %d개, 비표준 방화벽 유닛 구성 발견", listeners.total),
				Evidence:      evidence,
			}
		}
	}

	managerCount := 0
	if firewalldActive || firewalldEnabled {
		managerCount++
	}
	if nftablesActive || nftablesEnabled {
		managerCount++
	}
	if legacyActive || legacyEnabled {
		managerCount++
	}
	if managerCount > 1 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "둘 이상의 방화벽 관리 방식이 함께 구성되어 실효 정책의 소유권을 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("원격 수신 소켓 %d개, 방화벽 관리자 %d개", listeners.total, managerCount),
			Evidence:      evidence,
		}
	}

	if firewalldActive != firewalldEnabled || nftablesActive != nftablesEnabled || legacyActive != legacyEnabled {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownAmbiguousResult,
			Summary:       "방화벽의 현재 실행 상태와 부팅 시 활성화 상태가 일치하지 않습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("원격 수신 소켓 %d개, 런타임/부팅 상태 불일치", listeners.total),
			Evidence:      evidence,
		}
	}

	if legacyActive || legacyEnabled {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "레거시 iptables 서비스가 정책을 관리하고 있어 전체 실효 규칙을 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("원격 수신 소켓 %d개, 레거시 방화벽 관리자 사용", listeners.total),
			Evidence:      evidence,
		}
	}

	if firewalldState != nil {
		if !firewalldState.runtimeMatchesPermanent {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownAmbiguousResult,
				Summary:       "firewalld 런타임 구성과 영구 구성의 동등성을 확정할 수 없습니다.",
				Expected:      rule.Criteria.Pass,
				Observed:      fmt.Sprintf("원격 수신 소켓 %d개, firewalld 런타임/영구 구성 차이 감지", listeners.total),
				Evidence:      evidence,
			}
		}
		if firewalldState.hasDirectConfiguration {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "firewalld direct 규칙이 있어 표준 영역 및 정책 구성만으로 실효 통제를 확정할 수 없습니다.",
				Expected:      rule.Criteria.Pass,
				Observed:      fmt.Sprintf("원격 수신 소켓 %d개, direct 규칙 구성됨", listeners.total),
				Evidence:      evidence,
			}
		}
	}

	if nftState.dynamicObjectCount > 0 {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "동적 nftables 객체가 있어 수집 시점의 규칙만으로 전체 인바운드 통제를 확정할 수 없습니다.",
			Expected:      rule.Criteria.Pass,
			Observed:      fmt.Sprintf("원격 수신 소켓 %d개, 동적 nftables 객체 %d개", listeners.total, nftState.dynamicObjectCount),
			Evidence:      evidence,
		}
	}

	managerDescription := "활성 방화벽 관리자 없음"
	if firewalldActive {
		managerDescription = "firewalld 활성"
	} else if nftablesActive {
		managerDescription = "nftables 활성"
	} else if nftState.tableCount > 0 {
		managerDescription = "관리 주체를 확인할 수 없는 nftables 규칙 존재"
	}
	return evaluator.Outcome{
		Status:        model.StatusUnknown,
		UnknownReason: model.UnknownManualVerification,
		Summary:       "기관이 승인한 접속 IP 및 포트 정책이나 검증된 외부 ACL 근거가 없어 적합성을 확정할 수 없습니다.",
		Expected:      rule.Criteria.Pass,
		Observed:      fmt.Sprintf("원격 수신 소켓 %d개, %s", listeners.total, managerDescription),
		Evidence:      evidence,
	}
}

func inspectRemoteListeners(ctx context.Context, environment evaluator.Environment) (listenerInventory, model.Evidence, error) {
	spec := executor.Spec{
		Name:      "ss",
		Arguments: []string{"-H", "-lntup"},
		Timeout:   15 * time.Second,
		MaxOutput: 8 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return listenerInventory{}, model.Evidence{}, fmt.Errorf("run ss listener collection: %w", err)
	}
	if result.ExitCode != 0 || result.Truncated {
		return listenerInventory{}, model.Evidence{}, fmt.Errorf("ss listener collection failed: exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}

	inventory := listenerInventory{configuration: make([]string, 0)}
	for lineNumber, raw := range normalizedLines(result.Stdout) {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return listenerInventory{}, model.Evidence{}, fmt.Errorf("parse ss output line %d: expected at least six fields", lineNumber+1)
		}
		protocol := strings.ToLower(fields[0])
		if protocol != "tcp" && protocol != "udp" {
			return listenerInventory{}, model.Evidence{}, fmt.Errorf("parse ss output line %d: unsupported transport", lineNumber+1)
		}
		address, port, wildcard, scope, parseErr := parseListenerEndpoint(fields[4])
		if parseErr != nil {
			return listenerInventory{}, model.Evidence{}, fmt.Errorf("parse ss output line %d: %w", lineNumber+1, parseErr)
		}
		if !wildcard && address.IsLoopback() {
			continue
		}

		inventory.total++
		switch protocol {
		case "tcp":
			inventory.tcp++
		case "udp":
			inventory.udp++
		}
		if wildcard {
			inventory.wildcard++
		} else {
			inventory.specific++
		}
		canonicalAddress := address.String()
		if scope != "" {
			canonicalAddress += "%" + scope
		}
		inventory.configuration = append(inventory.configuration, protocol+"\x00"+canonicalAddress+"\x00"+strconv.Itoa(port))
	}
	sort.Strings(inventory.configuration)

	facts := map[string]any{
		"remote_listener_count": inventory.total,
		"tcp_listener_count":    inventory.tcp,
		"udp_listener_count":    inventory.udp,
		"wildcard_bind_count":   inventory.wildcard,
		"specific_bind_count":   inventory.specific,
		"configuration_sha256":  hashStrings(inventory.configuration),
	}
	addPrivateCommandFacts(facts, result)
	return inventory, support.FactEvidence("ss-listener-summary", facts), nil
}

func parseListenerEndpoint(endpoint string) (netip.Addr, int, bool, string, error) {
	index := strings.LastIndexByte(endpoint, ':')
	if index < 0 || index+1 >= len(endpoint) {
		return netip.Addr{}, 0, false, "", fmt.Errorf("listener endpoint has no numeric port")
	}
	port, err := strconv.Atoi(strings.Trim(endpoint[index+1:], "[]"))
	if err != nil || port < 1 || port > 65535 {
		return netip.Addr{}, 0, false, "", fmt.Errorf("listener endpoint has an invalid port")
	}
	addressText := strings.TrimSpace(endpoint[:index])
	if addressText == "" || addressText == "*" {
		return netip.IPv6Unspecified(), port, true, "", nil
	}
	if strings.HasPrefix(addressText, "[") {
		closingBracket := strings.IndexByte(addressText, ']')
		if closingBracket < 0 {
			return netip.Addr{}, 0, false, "", fmt.Errorf("listener endpoint has an invalid numeric address")
		}
		addressText = addressText[1:closingBracket] + addressText[closingBracket+1:]
	}
	scope := ""
	if numericAddress, value, found := strings.Cut(addressText, "%"); found {
		if numericAddress == "" || value == "" || strings.ContainsAny(value, "%[]:\x00\r\n\t ") {
			return netip.Addr{}, 0, false, "", fmt.Errorf("listener endpoint has an invalid scope")
		}
		addressText = numericAddress
		scope = value
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil {
		return netip.Addr{}, 0, false, "", fmt.Errorf("listener endpoint has an invalid numeric address")
	}
	address = address.Unmap()
	return address, port, address.IsUnspecified(), scope, nil
}

func nonstandardFirewallUnit(unit support.UnitState) bool {
	fragment := strings.ReplaceAll(strings.TrimSpace(unit.FragmentPath), "\\", "/")
	if fragment == "" || (!strings.HasPrefix(fragment, "/usr/lib/systemd/system/") && !strings.HasPrefix(fragment, "/lib/systemd/system/")) {
		return true
	}
	return strings.TrimSpace(unit.DropInPaths) != ""
}

func summarizedFirewallUnitEvidence(units []support.UnitState, rawEvidence []model.Evidence) model.Evidence {
	transcriptHash := sha256.New()
	for _, item := range rawEvidence {
		if item.Command == nil {
			continue
		}
		_, _ = transcriptHash.Write([]byte(item.Command.Executable))
		_, _ = transcriptHash.Write([]byte{0})
		_, _ = transcriptHash.Write([]byte(item.Command.Stdout))
		_, _ = transcriptHash.Write([]byte{0})
		_, _ = transcriptHash.Write([]byte(item.Command.Stderr))
		_, _ = transcriptHash.Write([]byte{0})
	}
	nonstandardConfigured := 0
	for _, unit := range units {
		if (support.UnitActive(unit) || support.UnitEnabled(unit)) && nonstandardFirewallUnit(unit) {
			nonstandardConfigured++
		}
	}
	facts := map[string]any{
		"transcript_sha256":                 hex.EncodeToString(transcriptHash.Sum(nil)),
		"unit_count":                        len(units),
		"nonstandard_configured_unit_count": nonstandardConfigured,
		"firewalld_installed":               support.UnitInstalled(units[0]),
		"firewalld_active":                  support.UnitActive(units[0]),
		"firewalld_boot_enabled":            support.UnitEnabled(units[0]),
		"nftables_installed":                support.UnitInstalled(units[1]),
		"nftables_active":                   support.UnitActive(units[1]),
		"nftables_boot_enabled":             support.UnitEnabled(units[1]),
		"iptables_active":                   support.UnitActive(units[2]),
		"iptables_boot_enabled":             support.UnitEnabled(units[2]),
		"ip6tables_active":                  support.UnitActive(units[3]),
		"ip6tables_boot_enabled":            support.UnitEnabled(units[3]),
	}
	return support.FactEvidence("firewall-unit-summary", facts)
}

func addPrivateCommandFacts(facts map[string]any, result executor.Result) {
	facts["transcript_sha256"] = hashCommandResult(result)
	facts["exit_code"] = result.ExitCode
	facts["duration_ms"] = result.Duration.Milliseconds()
	facts["timed_out"] = result.TimedOut
	facts["truncated"] = result.Truncated
}

func hashCommandResult(result executor.Result) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("stdout\x00"))
	_, _ = hash.Write(result.Stdout)
	_, _ = hash.Write([]byte("\x00stderr\x00"))
	_, _ = hash.Write(result.Stderr)
	return hex.EncodeToString(hash.Sum(nil))
}

func hashStrings(values []string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func normalizedLines(data []byte) []string {
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

func nonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "unknown"
}

func ingressError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "인바운드 접속 제한 설정을 수집하거나 해석하지 못했습니다.",
		Evidence:     append([]model.Evidence(nil), evidence...),
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
