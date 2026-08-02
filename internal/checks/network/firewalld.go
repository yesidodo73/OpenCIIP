package network

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const maximumFirewalldObjects = 128

const firewalldConfigurationPath = "/etc/firewalld/firewalld.conf"

type firewalldInspection struct {
	runtimeMatchesPermanent bool
	hasDirectConfiguration  bool
}

type firewalldSnapshot struct {
	defaultZone     string
	activeZoneCount int
	zones           map[string]firewalldObject
	policies        map[string]firewalldObject
	directRules     []string
	passthroughs    []string
}

type firewalldObject map[string][]string

type firewalldTranscript struct {
	digest       hash.Hash
	commandCount int
}

func inspectFirewalld(ctx context.Context, environment evaluator.Environment) (firewalldInspection, model.Evidence, error) {
	runtimeTranscript := newFirewalldTranscript()
	permanentTranscript := newFirewalldTranscript()

	runtimeDefaultZone, permanentDefaultZone, err := collectFirewalldDefaultZones(ctx, environment, runtimeTranscript, permanentTranscript)
	if err != nil {
		return firewalldInspection{}, model.Evidence{}, err
	}

	runtime, err := collectRuntimeFirewalld(ctx, environment, runtimeDefaultZone, runtimeTranscript)
	if err != nil {
		return firewalldInspection{}, model.Evidence{}, err
	}
	permanent, err := collectPermanentFirewalld(ctx, environment, permanentDefaultZone, permanentTranscript)
	if err != nil {
		return firewalldInspection{}, model.Evidence{}, err
	}

	runtimeHash := runtime.configurationHash()
	permanentHash := permanent.configurationHash()
	inspection := firewalldInspection{
		runtimeMatchesPermanent: runtimeHash == permanentHash,
		hasDirectConfiguration: len(runtime.directRules) > 0 || len(runtime.passthroughs) > 0 ||
			len(permanent.directRules) > 0 || len(permanent.passthroughs) > 0,
	}
	facts := map[string]any{
		"runtime_configuration_sha256":      runtimeHash,
		"permanent_configuration_sha256":    permanentHash,
		"default_zone_match":                runtimeDefaultZone == permanentDefaultZone,
		"runtime_permanent_match":           inspection.runtimeMatchesPermanent,
		"runtime_transcript_sha256":         runtimeTranscript.sum(),
		"permanent_transcript_sha256":       permanentTranscript.sum(),
		"runtime_command_count":             runtimeTranscript.commandCount,
		"permanent_command_count":           permanentTranscript.commandCount,
		"runtime_active_zone_count":         runtime.activeZoneCount,
		"permanent_active_zone_count":       permanent.activeZoneCount,
		"runtime_evaluated_zone_count":      len(runtime.zones),
		"permanent_evaluated_zone_count":    len(permanent.zones),
		"runtime_service_count":             runtime.valueCount("services"),
		"permanent_service_count":           permanent.valueCount("services"),
		"runtime_port_count":                runtime.valueCount("ports"),
		"permanent_port_count":              permanent.valueCount("ports"),
		"runtime_rich_rule_count":           runtime.valueCount("rich rules"),
		"permanent_rich_rule_count":         permanent.valueCount("rich rules"),
		"runtime_default_interface_count":   runtime.zones[runtime.defaultZone].valueCount("interfaces"),
		"permanent_default_interface_count": permanent.zones[permanent.defaultZone].valueCount("interfaces"),
		"runtime_policy_count":              len(runtime.policies),
		"permanent_policy_count":            len(permanent.policies),
		"runtime_direct_rule_count":         len(runtime.directRules) + len(runtime.passthroughs),
		"permanent_direct_rule_count":       len(permanent.directRules) + len(permanent.passthroughs),
	}
	return inspection, support.FactEvidence("firewalld-configuration-summary", facts), nil
}

func collectFirewalldDefaultZones(
	ctx context.Context,
	environment evaluator.Environment,
	runtimeTranscript *firewalldTranscript,
	permanentTranscript *firewalldTranscript,
) (string, string, error) {
	runtimeResult, err := runFirewalldCommand(ctx, environment, []string{"--get-default-zone"}, "default-zone", runtimeTranscript)
	if err != nil {
		return "", "", err
	}
	runtimeDefaultZone, err := parseSingleFirewalldName(runtimeResult.Stdout)
	if err != nil {
		return "", "", fmt.Errorf("parse firewalld runtime default zone: %w", err)
	}
	configuration, _, readErr := environment.Files.ReadFile(ctx, firewalldConfigurationPath, 1<<20)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("read firewalld permanent default zone: %w", readErr)
	}
	permanentTranscript.addSource("default-zone-configuration", configuration)
	permanentDefaultZone, err := parsePermanentFirewalldDefaultZone(configuration, errors.Is(readErr, os.ErrNotExist))
	if err != nil {
		return "", "", fmt.Errorf("parse firewalld permanent default zone: %w", err)
	}
	return runtimeDefaultZone, permanentDefaultZone, nil
}

func parsePermanentFirewalldDefaultZone(data []byte, configurationMissing bool) (string, error) {
	// firewalld uses public when firewalld.conf or DefaultZone is absent.
	// --set-default-zone changes both runtime and permanent state, while
	// --get-default-zone is a stand-alone option and cannot be combined with
	// --permanent. Reading the persisted setting also detects manual edits that
	// have not yet been loaded into the daemon.
	defaultZone := "public"
	if configurationMissing {
		return defaultZone, nil
	}
	found := false
	for lineNumber, raw := range normalizedLines(data) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, hasValue := strings.Cut(line, "=")
		if strings.TrimSpace(key) != "DefaultZone" {
			continue
		}
		if !hasValue || strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("DefaultZone on line %d has no value", lineNumber+1)
		}
		if found {
			return "", fmt.Errorf("DefaultZone is declared more than once")
		}
		defaultZone = strings.TrimSpace(value)
		if err := validateFirewalldName(defaultZone); err != nil {
			return "", fmt.Errorf("DefaultZone on line %d: %w", lineNumber+1, err)
		}
		found = true
	}
	return defaultZone, nil
}

func collectRuntimeFirewalld(
	ctx context.Context,
	environment evaluator.Environment,
	defaultZone string,
	transcript *firewalldTranscript,
) (firewalldSnapshot, error) {
	activeResult, err := runFirewalldCommand(ctx, environment, []string{"--get-active-zones"}, "active-zones", transcript)
	if err != nil {
		return firewalldSnapshot{}, err
	}
	activeZones, err := parseActiveFirewalldZones(activeResult.Stdout)
	if err != nil {
		return firewalldSnapshot{}, fmt.Errorf("parse firewalld runtime active zones: %w", err)
	}
	zonesToInspect := append([]string(nil), activeZones...)
	zonesToInspect = append(zonesToInspect, defaultZone)
	zonesToInspect = uniqueSortedStrings(zonesToInspect)

	snapshot := firewalldSnapshot{
		defaultZone:     defaultZone,
		activeZoneCount: len(activeZones),
		zones:           make(map[string]firewalldObject, len(zonesToInspect)),
		policies:        make(map[string]firewalldObject),
	}
	for _, zone := range zonesToInspect {
		result, runErr := runFirewalldCommand(ctx, environment, []string{"--zone=" + zone, "--list-all"}, "zone-configuration", transcript)
		if runErr != nil {
			return firewalldSnapshot{}, runErr
		}
		configuration, parseErr := parseFirewalldObject(result.Stdout)
		if parseErr != nil {
			return firewalldSnapshot{}, fmt.Errorf("parse firewalld runtime zone configuration: %w", parseErr)
		}
		snapshot.zones[zone] = configuration
	}
	if err := collectFirewalldPolicies(ctx, environment, false, transcript, &snapshot); err != nil {
		return firewalldSnapshot{}, err
	}
	if err := collectFirewalldDirectConfiguration(ctx, environment, false, transcript, &snapshot); err != nil {
		return firewalldSnapshot{}, err
	}
	return snapshot, nil
}

func collectPermanentFirewalld(
	ctx context.Context,
	environment evaluator.Environment,
	defaultZone string,
	transcript *firewalldTranscript,
) (firewalldSnapshot, error) {
	zonesResult, err := runFirewalldCommand(ctx, environment, []string{"--permanent", "--get-zones"}, "available-zones", transcript)
	if err != nil {
		return firewalldSnapshot{}, err
	}
	zoneNames, err := parseFirewalldNames(zonesResult.Stdout)
	if err != nil {
		return firewalldSnapshot{}, fmt.Errorf("parse firewalld permanent zones: %w", err)
	}
	if !containsString(zoneNames, defaultZone) {
		return firewalldSnapshot{}, fmt.Errorf("firewalld default zone is absent from permanent configuration")
	}

	allConfigurations := make(map[string]firewalldObject, len(zoneNames))
	activeZones := make([]string, 0)
	for _, zone := range zoneNames {
		result, runErr := runFirewalldCommand(ctx, environment, []string{"--permanent", "--zone=" + zone, "--list-all"}, "zone-configuration", transcript)
		if runErr != nil {
			return firewalldSnapshot{}, runErr
		}
		configuration, parseErr := parseFirewalldObject(result.Stdout)
		if parseErr != nil {
			return firewalldSnapshot{}, fmt.Errorf("parse firewalld permanent zone configuration: %w", parseErr)
		}
		allConfigurations[zone] = configuration
		if configuration.valueCount("interfaces") > 0 || configuration.valueCount("sources") > 0 {
			activeZones = append(activeZones, zone)
		}
	}

	zonesToInspect := append([]string(nil), activeZones...)
	zonesToInspect = append(zonesToInspect, defaultZone)
	zonesToInspect = uniqueSortedStrings(zonesToInspect)
	snapshot := firewalldSnapshot{
		defaultZone:     defaultZone,
		activeZoneCount: len(activeZones),
		zones:           make(map[string]firewalldObject, len(zonesToInspect)),
		policies:        make(map[string]firewalldObject),
	}
	for _, zone := range zonesToInspect {
		snapshot.zones[zone] = allConfigurations[zone]
	}
	if err := collectFirewalldPolicies(ctx, environment, true, transcript, &snapshot); err != nil {
		return firewalldSnapshot{}, err
	}
	if err := collectFirewalldDirectConfiguration(ctx, environment, true, transcript, &snapshot); err != nil {
		return firewalldSnapshot{}, err
	}
	return snapshot, nil
}

func collectFirewalldPolicies(
	ctx context.Context,
	environment evaluator.Environment,
	permanent bool,
	transcript *firewalldTranscript,
	snapshot *firewalldSnapshot,
) error {
	arguments := firewalldArguments(permanent, "--get-policies")
	policiesResult, err := runFirewalldCommand(ctx, environment, arguments, "available-policies", transcript)
	if err != nil {
		return err
	}
	policyNames, err := parseFirewalldNames(policiesResult.Stdout)
	if err != nil {
		return fmt.Errorf("parse firewalld policies: %w", err)
	}
	for _, policy := range policyNames {
		arguments = firewalldArguments(permanent, "--policy="+policy, "--list-all")
		result, runErr := runFirewalldCommand(ctx, environment, arguments, "policy-configuration", transcript)
		if runErr != nil {
			return runErr
		}
		configuration, parseErr := parseFirewalldObject(result.Stdout)
		if parseErr != nil {
			return fmt.Errorf("parse firewalld policy configuration: %w", parseErr)
		}
		snapshot.policies[policy] = configuration
	}
	return nil
}

func collectFirewalldDirectConfiguration(
	ctx context.Context,
	environment evaluator.Environment,
	permanent bool,
	transcript *firewalldTranscript,
	snapshot *firewalldSnapshot,
) error {
	rulesResult, err := runFirewalldCommand(
		ctx,
		environment,
		firewalldArguments(permanent, "--direct", "--get-all-rules"),
		"direct-rules",
		transcript,
	)
	if err != nil {
		return err
	}
	passthroughResult, err := runFirewalldCommand(
		ctx,
		environment,
		firewalldArguments(permanent, "--direct", "--get-all-passthroughs"),
		"direct-passthroughs",
		transcript,
	)
	if err != nil {
		return err
	}
	snapshot.directRules = normalizedNonEmptyLines(rulesResult.Stdout)
	snapshot.passthroughs = normalizedNonEmptyLines(passthroughResult.Stdout)
	return nil
}

func runFirewalldCommand(
	ctx context.Context,
	environment evaluator.Environment,
	arguments []string,
	operation string,
	transcript *firewalldTranscript,
) (executor.Result, error) {
	spec := executor.Spec{
		Name:      "firewall-cmd",
		Arguments: arguments,
		Timeout:   30 * time.Second,
		MaxOutput: 8 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return executor.Result{}, fmt.Errorf("run firewalld %s collection: %w", operation, err)
	}
	if result.ExitCode != 0 || result.Truncated {
		return executor.Result{}, fmt.Errorf("firewalld %s collection failed: exit=%d truncated=%t", operation, result.ExitCode, result.Truncated)
	}
	transcript.add(operation, result)
	return result, nil
}

func parseActiveFirewalldZones(data []byte) ([]string, error) {
	zones := make([]string, 0)
	for lineNumber, raw := range normalizedLines(data) {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		first, _ := firstRune(raw)
		if unicode.IsSpace(first) {
			if len(zones) == 0 {
				return nil, fmt.Errorf("binding precedes zone on line %d", lineNumber+1)
			}
			continue
		}
		name := strings.TrimSpace(raw)
		if err := validateFirewalldName(name); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		zones = append(zones, name)
	}
	return uniqueFirewalldNames(zones)
}

func parseSingleFirewalldName(data []byte) (string, error) {
	names, err := parseFirewalldNames(data)
	if err != nil {
		return "", err
	}
	if len(names) != 1 {
		return "", fmt.Errorf("expected exactly one name")
	}
	return names[0], nil
}

func parseFirewalldNames(data []byte) ([]string, error) {
	fields := strings.Fields(string(data))
	if len(fields) > maximumFirewalldObjects {
		return nil, fmt.Errorf("object count exceeds %d", maximumFirewalldObjects)
	}
	for _, name := range fields {
		if err := validateFirewalldName(name); err != nil {
			return nil, err
		}
	}
	return uniqueFirewalldNames(fields)
}

func validateFirewalldName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("invalid firewalld object name")
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' {
			return fmt.Errorf("invalid firewalld object name")
		}
	}
	return nil
}

func uniqueFirewalldNames(values []string) ([]string, error) {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("duplicate firewalld object name")
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	if len(result) > maximumFirewalldObjects {
		return nil, fmt.Errorf("object count exceeds %d", maximumFirewalldObjects)
	}
	sort.Strings(result)
	return result, nil
}

func parseFirewalldObject(data []byte) (firewalldObject, error) {
	object := make(firewalldObject)
	currentKey := ""
	headerSeen := false
	propertyIndent := -1
	for lineNumber, raw := range normalizedLines(data) {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		indent := leadingWhitespace(raw)
		line := strings.TrimSpace(raw)
		if indent == 0 {
			if headerSeen {
				return nil, fmt.Errorf("multiple object headers")
			}
			headerSeen = true
			continue
		}
		if !headerSeen {
			return nil, fmt.Errorf("property precedes object header on line %d", lineNumber+1)
		}
		if propertyIndent < 0 {
			propertyIndent = indent
		}
		if indent < propertyIndent {
			return nil, fmt.Errorf("line %d has inconsistent indentation", lineNumber+1)
		}
		if indent == propertyIndent {
			key, value, found := strings.Cut(line, ":")
			if !found || strings.TrimSpace(key) == "" {
				return nil, fmt.Errorf("line %d is not a property", lineNumber+1)
			}
			currentKey = strings.ToLower(strings.TrimSpace(key))
			appendFirewalldValue(object, currentKey, strings.TrimSpace(value))
			continue
		}
		if currentKey == "" {
			return nil, fmt.Errorf("line %d has no parent property", lineNumber+1)
		}
		appendFirewalldValue(object, currentKey, line)
	}
	if !headerSeen {
		return nil, fmt.Errorf("object header is missing")
	}
	for key := range object {
		sort.Strings(object[key])
	}
	return object, nil
}

func appendFirewalldValue(object firewalldObject, key, value string) {
	if value == "" {
		if _, exists := object[key]; !exists {
			object[key] = nil
		}
		return
	}
	switch key {
	case "interfaces", "sources", "services", "ports", "protocols", "source-ports", "icmp-blocks", "ingress-zones", "egress-zones":
		for _, field := range strings.Fields(value) {
			object[key] = append(object[key], field)
		}
	default:
		object[key] = append(object[key], strings.Join(strings.Fields(value), " "))
	}
}

func (object firewalldObject) valueCount(key string) int {
	return len(object[key])
}

func (snapshot firewalldSnapshot) valueCount(key string) int {
	count := 0
	for _, zone := range snapshot.zones {
		count += zone.valueCount(key)
	}
	for _, policy := range snapshot.policies {
		count += policy.valueCount(key)
	}
	return count
}

func (snapshot firewalldSnapshot) configurationHash() string {
	values := []string{"default-zone\x00" + snapshot.defaultZone}
	zoneNames := sortedMapKeys(snapshot.zones)
	for _, name := range zoneNames {
		values = append(values, "zone\x00"+name)
		values = append(values, canonicalFirewalldObject(snapshot.zones[name])...)
	}
	policyNames := sortedMapKeys(snapshot.policies)
	for _, name := range policyNames {
		values = append(values, "policy\x00"+name)
		values = append(values, canonicalFirewalldObject(snapshot.policies[name])...)
	}
	for _, rule := range snapshot.directRules {
		values = append(values, "direct\x00"+rule)
	}
	for _, passthrough := range snapshot.passthroughs {
		values = append(values, "passthrough\x00"+passthrough)
	}
	return hashStrings(values)
}

func canonicalFirewalldObject(object firewalldObject) []string {
	keys := sortedMapKeys(object)
	values := make([]string, 0)
	for _, key := range keys {
		if len(object[key]) == 0 {
			values = append(values, key+"\x00")
			continue
		}
		for _, value := range object[key] {
			values = append(values, key+"\x00"+value)
		}
	}
	return values
}

func sortedMapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func normalizedNonEmptyLines(data []byte) []string {
	lines := make([]string, 0)
	for _, raw := range normalizedLines(data) {
		line := strings.Join(strings.Fields(raw), " ")
		if line != "" {
			lines = append(lines, line)
		}
	}
	sort.Strings(lines)
	return lines
}

func uniqueSortedStrings(values []string) []string {
	sort.Strings(values)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func containsString(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func firewalldArguments(permanent bool, values ...string) []string {
	arguments := make([]string, 0, len(values)+1)
	if permanent {
		arguments = append(arguments, "--permanent")
	}
	return append(arguments, values...)
}

func leadingWhitespace(value string) int {
	columns := 0
	for _, character := range value {
		switch character {
		case ' ':
			columns++
		case '\t':
			columns += 8 - columns%8
		default:
			if unicode.IsSpace(character) {
				columns++
				continue
			}
			return columns
		}
	}
	return columns
}

func firstRune(value string) (rune, int) {
	for _, character := range value {
		return character, 1
	}
	return 0, 0
}

func newFirewalldTranscript() *firewalldTranscript {
	return &firewalldTranscript{digest: sha256.New()}
}

func (transcript *firewalldTranscript) add(operation string, result executor.Result) {
	transcript.addSource(operation, result.Stdout, result.Stderr)
	transcript.commandCount++
}

func (transcript *firewalldTranscript) addSource(operation string, values ...[]byte) {
	_, _ = transcript.digest.Write([]byte(operation))
	_, _ = transcript.digest.Write([]byte{0})
	for _, value := range values {
		_, _ = transcript.digest.Write(value)
		_, _ = transcript.digest.Write([]byte{0})
	}
}

func (transcript *firewalldTranscript) sum() string {
	return hex.EncodeToString(transcript.digest.Sum(nil))
}
