package support

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

type UnitState struct {
	Name          string
	LoadState     string
	ActiveState   string
	SubState      string
	UnitFileState string
	FragmentPath  string
	DropInPaths   string
}

func InspectUnits(ctx context.Context, environment evaluator.Environment, units []string) ([]UnitState, []model.Evidence, error) {
	states := make([]UnitState, 0, len(units))
	evidence := make([]model.Evidence, 0, len(units))
	for _, unit := range units {
		if !validUnitName(unit) {
			return nil, nil, fmt.Errorf("invalid systemd unit name %q", unit)
		}
		spec := executor.Spec{
			Name: "systemctl",
			Arguments: []string{
				"show",
				"--no-pager",
				"--property=Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths",
				"--",
				unit,
			},
			Timeout: 10 * time.Second,
		}
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect systemd unit %s: %w", unit, err)
		}
		if result.Truncated {
			return nil, nil, fmt.Errorf("inspect systemd unit %s: output was truncated", unit)
		}
		properties, parseErr := ParseKeyValueOutput(string(result.Stdout))
		if parseErr != nil {
			return nil, nil, fmt.Errorf("parse systemd unit %s: %w", unit, parseErr)
		}
		state := UnitState{
			Name:          firstNonEmptyString(properties["Id"], unit),
			LoadState:     properties["LoadState"],
			ActiveState:   properties["ActiveState"],
			SubState:      properties["SubState"],
			UnitFileState: properties["UnitFileState"],
			FragmentPath:  properties["FragmentPath"],
			DropInPaths:   properties["DropInPaths"],
		}
		if state.LoadState == "" && result.ExitCode != 0 && strings.Contains(strings.ToLower(string(result.Stderr)), "could not be found") {
			state.LoadState = "not-found"
		}
		if result.ExitCode != 0 && state.LoadState != "not-found" {
			return nil, nil, fmt.Errorf("inspect systemd unit %s: exit code %d", unit, result.ExitCode)
		}
		if state.LoadState == "" {
			return nil, nil, fmt.Errorf("inspect systemd unit %s: LoadState is missing", unit)
		}
		states = append(states, state)
		evidence = append(evidence, CommandEvidence(spec, result))
	}
	return states, evidence, nil
}

func InspectListeningPorts(ctx context.Context, environment evaluator.Environment, ports []int) (map[int][]string, model.Evidence, error) {
	return inspectListeningPorts(ctx, environment, ports, "")
}

func InspectTCPListeningPorts(ctx context.Context, environment evaluator.Environment, ports []int) (map[int][]string, model.Evidence, error) {
	return inspectListeningPorts(ctx, environment, ports, "tcp")
}

func InspectUDPListeningPorts(ctx context.Context, environment evaluator.Environment, ports []int) (map[int][]string, model.Evidence, error) {
	return inspectListeningPorts(ctx, environment, ports, "udp")
}

func inspectListeningPorts(ctx context.Context, environment evaluator.Environment, ports []int, protocol string) (map[int][]string, model.Evidence, error) {
	requested := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return nil, model.Evidence{}, fmt.Errorf("invalid network port %d", port)
		}
		requested[port] = struct{}{}
	}
	spec := executor.Spec{Name: "ss", Arguments: []string{"-H", "-lntup"}, Timeout: 15 * time.Second, MaxOutput: 2 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("inspect listening ports: %w", err)
	}
	if result.ExitCode != 0 || result.Truncated {
		return nil, model.Evidence{}, fmt.Errorf("inspect listening ports: exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	found := make(map[int][]string)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return nil, model.Evidence{}, fmt.Errorf("parse ss output line %d: expected at least 6 fields", lineNumber+1)
		}
		if protocol != "" && fields[0] != protocol {
			continue
		}
		port, parseErr := endpointPort(fields[4])
		if parseErr != nil {
			return nil, model.Evidence{}, fmt.Errorf("parse ss output line %d: %w", lineNumber+1, parseErr)
		}
		if _, wanted := requested[port]; wanted {
			found[port] = append(found[port], line)
		}
	}
	for port := range found {
		sort.Strings(found[port])
	}
	matchedCounts := make(map[string]int, len(found))
	matchedLines := make([]string, 0)
	for port, lines := range found {
		matchedCounts[strconv.Itoa(port)] = len(lines)
		matchedLines = append(matchedLines, lines...)
	}
	sort.Strings(matchedLines)
	evidence := CommandSummaryEvidence("listener-inventory-summary", spec, result, map[string]any{
		"protocol_filter":           protocol,
		"requested_port_count":      len(requested),
		"matched_port_counts":       matchedCounts,
		"matched_set_sha256":        stringSetDigest(matchedLines),
		"endpoint_details_redacted": true,
	})
	return found, evidence, nil
}

func InspectProcesses(ctx context.Context, environment evaluator.Environment, names []string) ([]string, model.Evidence, error) {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, " \t/\\") {
			return nil, model.Evidence{}, fmt.Errorf("invalid process name %q", name)
		}
		wanted[name] = struct{}{}
	}
	spec := executor.Spec{Name: "ps", Arguments: []string{"-eo", "comm="}, Timeout: 10 * time.Second, MaxOutput: 2 << 20}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("inspect processes: %w", err)
	}
	if result.ExitCode != 0 || result.Truncated {
		return nil, model.Evidence{}, fmt.Errorf("inspect processes: exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	found := make(map[string]struct{})
	for _, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
		name := strings.TrimSpace(raw)
		if _, exists := wanted[name]; exists {
			found[name] = struct{}{}
		}
	}
	processes := make([]string, 0, len(found))
	for name := range found {
		processes = append(processes, name)
	}
	sort.Strings(processes)
	evidence := CommandSummaryEvidence("process-inventory-summary", spec, result, map[string]any{
		"requested_process_count":    len(wanted),
		"matched_process_count":      len(processes),
		"matched_processes":          append([]string(nil), processes...),
		"inventory_details_redacted": true,
	})
	return processes, evidence, nil
}

// CommandSummaryEvidence records command metadata and output digests without
// retaining raw stdout or stderr in the report.
func CommandSummaryEvidence(source string, spec executor.Spec, result executor.Result, facts map[string]any) model.Evidence {
	summary := make(map[string]any, len(facts)+10)
	for key, value := range facts {
		summary[key] = value
	}
	summary["command"] = spec.Name
	summary["duration_ms"] = result.Duration.Milliseconds()
	summary["exit_code"] = result.ExitCode
	summary["stdout_bytes"] = len(result.Stdout)
	summary["stdout_sha256"] = byteDigest(result.Stdout)
	summary["stderr_bytes"] = len(result.Stderr)
	summary["stderr_sha256"] = byteDigest(result.Stderr)
	summary["timed_out"] = result.TimedOut
	summary["truncated"] = result.Truncated
	return FactEvidence(source, summary)
}

func stringSetDigest(values []string) string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func byteDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func ParseKeyValueOutput(output string) (map[string]string, error) {
	values := make(map[string]string)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("line %d is not key=value", lineNumber+1)
		}
		values[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return values, nil
}

func UnitInstalled(state UnitState) bool {
	return state.LoadState != "" && state.LoadState != "not-found"
}

func UnitActive(state UnitState) bool {
	switch state.ActiveState {
	case "active", "activating", "reloading":
		return true
	default:
		return false
	}
}

func UnitEnabled(state UnitState) bool {
	switch state.UnitFileState {
	case "enabled", "enabled-runtime", "linked", "linked-runtime":
		return true
	default:
		return false
	}
}

func endpointPort(endpoint string) (int, error) {
	index := strings.LastIndexByte(endpoint, ':')
	if index < 0 || index+1 >= len(endpoint) {
		return 0, fmt.Errorf("endpoint %q has no numeric port", endpoint)
	}
	port, err := strconv.Atoi(strings.Trim(endpoint[index+1:], "[]"))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("endpoint %q has invalid port", endpoint)
	}
	return port, nil
}

func validUnitName(value string) bool {
	if value == "" || (strings.HasPrefix(value, "-") && value != "-.mount") {
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

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
