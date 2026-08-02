package support

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

var ssProcessPattern = regexp.MustCompile(`"([^"]+)",pid=([0-9]+),`)

type ResolvedStubAssessment struct {
	Confirmed bool
	Evidence  []model.Evidence
}

func InspectSystemdResolvedStub(
	ctx context.Context,
	environment evaluator.Environment,
	listenerLines []string,
) (ResolvedStubAssessment, error) {
	if len(listenerLines) == 0 {
		return ResolvedStubAssessment{}, nil
	}
	spec := executor.Spec{
		Name: "systemctl",
		Arguments: []string{
			"show",
			"--no-pager",
			"--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths",
			"--",
			"systemd-resolved.service",
		},
		Timeout:   10 * time.Second,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return ResolvedStubAssessment{}, fmt.Errorf("inspect systemd-resolved unit: %w", err)
	}
	evidence := []model.Evidence{CommandSummaryEvidence("systemd-resolved-unit-summary", spec, result, map[string]any{
		"content_redacted": true,
	})}
	if result.Truncated {
		return ResolvedStubAssessment{Evidence: evidence}, fmt.Errorf(
			"inspect systemd-resolved unit: exit=%d truncated=%t",
			result.ExitCode,
			result.Truncated,
		)
	}
	if result.ExitCode != 0 {
		if strings.Contains(strings.ToLower(string(result.Stderr)), "could not be found") {
			evidence = append(evidence, FactEvidence("systemd-resolved-stub-summary", map[string]any{
				"unit":                      "systemd-resolved.service",
				"unit_installed":            false,
				"listener_count":            len(listenerLines),
				"confirmed_local_stub_only": false,
			}))
			return ResolvedStubAssessment{Evidence: evidence}, nil
		}
		return ResolvedStubAssessment{Evidence: evidence}, fmt.Errorf(
			"inspect systemd-resolved unit: exit=%d",
			result.ExitCode,
		)
	}
	properties, err := ParseKeyValueOutput(string(result.Stdout))
	if err != nil {
		return ResolvedStubAssessment{Evidence: evidence}, fmt.Errorf("parse systemd-resolved unit: %w", err)
	}
	mainPID, pidErr := strconv.Atoi(properties["MainPID"])
	unitActive := properties["Id"] == "systemd-resolved.service" &&
		properties["LoadState"] == "loaded" &&
		properties["ActiveState"] == "active" &&
		mainPID > 1 &&
		pidErr == nil
	fragmentPath := strings.ReplaceAll(strings.TrimSpace(properties["FragmentPath"]), "\\", "/")
	vendorUnit := strings.HasPrefix(fragmentPath, "/usr/lib/systemd/system/") ||
		strings.HasPrefix(fragmentPath, "/lib/systemd/system/")
	standardUnit := unitActive && vendorUnit && strings.TrimSpace(properties["DropInPaths"]) == ""

	addresses := make(map[string]struct{})
	protocols := make(map[string]int)
	matchedMainPID := 0
	standardAddresses := 0
	fullyAttributed := true
	for _, raw := range listenerLines {
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) < 6 {
			return ResolvedStubAssessment{Evidence: evidence}, fmt.Errorf("parse systemd-resolved listener: expected at least 6 fields")
		}
		protocol := fields[0]
		if protocol != "tcp" && protocol != "udp" {
			fullyAttributed = false
			continue
		}
		address, port, parseErr := parseSSLocalEndpoint(fields[4])
		if parseErr != nil {
			return ResolvedStubAssessment{Evidence: evidence}, fmt.Errorf("parse systemd-resolved listener: %w", parseErr)
		}
		protocols[protocol]++
		addresses[address.String()] = struct{}{}
		if port == 53 && isStandardResolvedStubAddress(address) {
			standardAddresses++
		} else {
			fullyAttributed = false
		}

		matches := ssProcessPattern.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 {
			fullyAttributed = false
			continue
		}
		lineOwnedByMainPID := true
		for _, match := range matches {
			pid, parseErr := strconv.Atoi(match[2])
			if parseErr != nil || (match[1] != "systemd-resolve" && match[1] != "systemd-resolved") || pid != mainPID {
				lineOwnedByMainPID = false
			}
		}
		if lineOwnedByMainPID {
			matchedMainPID++
		} else {
			fullyAttributed = false
		}
	}
	addressSet := make([]string, 0, len(addresses))
	for address := range addresses {
		addressSet = append(addressSet, address)
	}
	sort.Strings(addressSet)
	confirmed := standardUnit && fullyAttributed &&
		standardAddresses == len(listenerLines) &&
		matchedMainPID == len(listenerLines)
	evidence = append(evidence, FactEvidence("systemd-resolved-stub-summary", map[string]any{
		"unit":                         "systemd-resolved.service",
		"unit_active":                  unitActive,
		"vendor_unit":                  vendorUnit,
		"drop_in_count":                countSystemdDropInPaths(properties["DropInPaths"]),
		"main_pid":                     mainPID,
		"listener_count":               len(listenerLines),
		"standard_stub_listener_count": standardAddresses,
		"main_pid_listener_count":      matchedMainPID,
		"listener_protocol_counts":     protocols,
		"listener_addresses":           addressSet,
		"confirmed_local_stub_only":    confirmed,
		"content_redacted":             true,
	}))
	return ResolvedStubAssessment{Confirmed: confirmed, Evidence: evidence}, nil
}

func parseSSLocalEndpoint(endpoint string) (netip.Addr, int, error) {
	index := strings.LastIndexByte(endpoint, ':')
	if index < 0 || index+1 >= len(endpoint) {
		return netip.Addr{}, 0, fmt.Errorf("endpoint %q has no port", endpoint)
	}
	port, err := strconv.Atoi(strings.Trim(endpoint[index+1:], "[]"))
	if err != nil || port < 1 || port > 65535 {
		return netip.Addr{}, 0, fmt.Errorf("endpoint %q has an invalid port", endpoint)
	}
	addressText := strings.Trim(endpoint[:index], "[]")
	if zoneIndex := strings.LastIndexByte(addressText, '%'); zoneIndex >= 0 {
		addressText = addressText[:zoneIndex]
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("endpoint %q has an invalid address", endpoint)
	}
	return address.Unmap(), port, nil
}

func isStandardResolvedStubAddress(address netip.Addr) bool {
	return address == netip.MustParseAddr("127.0.0.53") ||
		address == netip.MustParseAddr("127.0.0.54")
}

func countSystemdDropInPaths(value string) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	return len(strings.Fields(value))
}
