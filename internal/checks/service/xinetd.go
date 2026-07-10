package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	xinetdRootConfig       = "/etc/xinetd.conf"
	xinetdMaxDepth         = 8
	xinetdMaxFiles         = 128
	xinetdMaxDirectorySize = 256
	xinetdMaxFileSize      = 1 << 20
	xinetdMaxTotalSize     = 4 << 20
	xinetdMaxBlocks        = 512
	xinetdMaxNodes         = 1024
	xinetdMaxAssignments   = 4096
	xinetdMaxTokens        = 131072
	xinetdMaxPathSize      = 4096
	xinetdMaxIdentifier    = 256
)

type xinetdInspection struct {
	Configured    int
	Enabled       int
	Disabled      int
	Indeterminate int
	Complete      bool
	Evidence      model.Evidence
}

type xinetdCollector struct {
	ctx        context.Context
	files      system.Reader
	targets    map[string]struct{}
	visited    map[string]struct{}
	paths      []string
	contents   []string
	services   []xinetdService
	defaults   xinetdDefaults
	defaultSet bool
	totalSize  int
	complete   bool
	reasons    map[string]struct{}
}

type xinetdDefaults struct {
	disable     *bool
	disableSeen bool
	disabled    map[string]struct{}
	enabled     map[string]struct{}
	enabledSeen bool
}

type xinetdService struct {
	name            string
	id              string
	disable         *bool
	disableKnown    bool
	disableFlag     bool
	controlComplete bool
}

type xinetdNode struct {
	kind       string
	include    string
	defaults   []xinetdAssignment
	service    xinetdParsedService
	sourceLine int
}

type xinetdParsedService struct {
	name        string
	assignments []xinetdAssignment
}

type xinetdAssignment struct {
	key      string
	operator string
	values   []string
	line     int
}

type xinetdToken struct {
	value string
	line  int
}

func inspectXinetdServices(
	ctx context.Context,
	environment evaluator.Environment,
	targetNames []string,
) (xinetdInspection, error) {
	targets := make(map[string]struct{}, len(targetNames))
	for _, name := range targetNames {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || strings.ContainsAny(name, " \t/\\") {
			return xinetdInspection{}, errors.New("invalid xinetd target service name")
		}
		targets[name] = struct{}{}
	}
	collector := &xinetdCollector{
		ctx:      ctx,
		files:    environment.Files,
		targets:  targets,
		visited:  make(map[string]struct{}),
		complete: true,
		reasons:  make(map[string]struct{}),
		defaults: xinetdDefaults{
			disabled: make(map[string]struct{}),
			enabled:  make(map[string]struct{}),
		},
	}
	if collector.files == nil {
		return xinetdInspection{}, errors.New("xinetd configuration reader is unavailable")
	}

	exists, err := collector.files.Exists(xinetdRootConfig)
	if err != nil {
		return xinetdInspection{}, errors.New("inspect the xinetd root configuration")
	}
	if exists {
		if err := collector.visitFile(xinetdRootConfig, 0); err != nil {
			return xinetdInspection{}, err
		}
	}

	inspection := collector.finish()
	inspection.Evidence = support.FactEvidence("xinetd-configuration-summary", map[string]any{
		"configuration_present":         exists,
		"configuration_complete":        inspection.Complete,
		"configuration_file_count":      len(collector.paths),
		"configuration_path_set_sha256": digestStrings(collector.paths),
		"configuration_set_sha256":      digestStrings(collector.contents),
		"target_block_count":            inspection.Configured,
		"enabled_target_count":          inspection.Enabled,
		"disabled_target_count":         inspection.Disabled,
		"indeterminate_target_count":    inspection.Indeterminate,
		"incomplete_reason_codes":       sortedStringSet(collector.reasons),
		"paths_redacted":                true,
		"contents_redacted":             true,
		"bounded_interpretation":        true,
	})
	return inspection, nil
}

func (collector *xinetdCollector) visitFile(filePath string, depth int) error {
	if !collector.complete {
		return nil
	}
	if depth > xinetdMaxDepth {
		collector.markIncomplete("include_depth_exceeded")
		return nil
	}
	canonical, valid := canonicalXinetdPath(filePath)
	if !valid {
		collector.markIncomplete("invalid_include_path")
		return nil
	}
	if _, duplicate := collector.visited[canonical]; duplicate {
		collector.markIncomplete("duplicate_or_recursive_include")
		return nil
	}
	if len(collector.visited) >= xinetdMaxFiles {
		collector.markIncomplete("configuration_file_limit_exceeded")
		return nil
	}
	metadata, err := collector.files.Lstat(canonical)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			collector.markIncomplete("included_path_missing")
			return nil
		}
		return errors.New("inspect an xinetd configuration file")
	}
	if metadata.FileType != "regular" {
		collector.markIncomplete("included_path_not_regular")
		return nil
	}
	collector.visited[canonical] = struct{}{}
	data, readMetadata, err := collector.files.ReadFile(collector.ctx, canonical, xinetdMaxFileSize)
	if err != nil {
		if errors.Is(err, system.ErrReadLimit) || errors.Is(err, system.ErrNotRegularFile) {
			collector.markIncomplete("configuration_file_unsupported")
			return nil
		}
		if errors.Is(err, os.ErrNotExist) {
			collector.markIncomplete("configuration_changed_during_read")
			return nil
		}
		return errors.New("read an xinetd configuration file")
	}
	if readMetadata.FileType != "regular" ||
		(metadata.Device != 0 && readMetadata.Device != 0 && metadata.Device != readMetadata.Device) ||
		(metadata.Inode != 0 && readMetadata.Inode != 0 && metadata.Inode != readMetadata.Inode) {
		collector.markIncomplete("configuration_changed_during_read")
		return nil
	}
	collector.totalSize += len(data)
	if collector.totalSize > xinetdMaxTotalSize {
		collector.markIncomplete("configuration_total_size_exceeded")
		return nil
	}
	collector.paths = append(collector.paths, canonical)
	contentDigest := sha256.Sum256(data)
	collector.contents = append(collector.contents, hex.EncodeToString(contentDigest[:]))

	nodes, parseErr := parseXinetdDocument(data)
	if parseErr != nil {
		collector.markIncomplete("configuration_syntax_unsupported")
		return nil
	}
	for _, node := range nodes {
		if !collector.complete {
			break
		}
		switch node.kind {
		case "include":
			if err := collector.visitFile(node.include, depth+1); err != nil {
				return err
			}
		case "includedir":
			if err := collector.visitDirectory(node.include, depth+1); err != nil {
				return err
			}
		case "defaults":
			collector.addDefaults(node.defaults)
		case "service":
			collector.addService(node.service)
		default:
			collector.markIncomplete("configuration_syntax_unsupported")
		}
	}
	return nil
}

func (collector *xinetdCollector) visitDirectory(directoryPath string, depth int) error {
	if depth > xinetdMaxDepth {
		collector.markIncomplete("include_depth_exceeded")
		return nil
	}
	canonical, valid := canonicalXinetdPath(directoryPath)
	if !valid {
		collector.markIncomplete("invalid_includedir_path")
		return nil
	}
	metadata, err := collector.files.Lstat(canonical)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			collector.markIncomplete("included_directory_missing")
			return nil
		}
		return errors.New("inspect an xinetd configuration directory")
	}
	if metadata.FileType != "directory" {
		collector.markIncomplete("included_path_not_directory")
		return nil
	}
	entries, err := collector.files.ReadDir(canonical)
	if err != nil {
		return errors.New("read an xinetd configuration directory")
	}
	eligible := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || len(name) > xinetdMaxIdentifier || strings.ContainsAny(name, "/\\\x00") {
			collector.markIncomplete("invalid_includedir_entry")
			continue
		}
		if strings.Contains(name, ".") || strings.HasSuffix(name, "~") {
			continue
		}
		eligible = append(eligible, name)
	}
	if len(eligible) > xinetdMaxDirectorySize {
		collector.markIncomplete("included_directory_limit_exceeded")
		return nil
	}
	sort.Strings(eligible)
	for _, name := range eligible {
		if err := collector.visitFile(path.Join(canonical, name), depth); err != nil {
			return err
		}
	}
	return nil
}

func (collector *xinetdCollector) addDefaults(assignments []xinetdAssignment) {
	if collector.defaultSet {
		collector.markIncomplete("duplicate_defaults_block")
		return
	}
	collector.defaultSet = true
	for _, assignment := range assignments {
		switch assignment.key {
		case "disable":
			value, known := xinetdYesNo(assignment)
			if collector.defaults.disableSeen || !known {
				collector.markIncomplete("ambiguous_default_disable")
				continue
			}
			collector.defaults.disableSeen = true
			collector.defaults.disable = &value
		case "disabled":
			if !addXinetdSetValues(collector.defaults.disabled, assignment, true) {
				collector.markIncomplete("ambiguous_default_disabled_control")
			}
		case "enabled":
			collector.defaults.enabledSeen = true
			if !addXinetdSetValues(collector.defaults.enabled, assignment, true) {
				collector.markIncomplete("ambiguous_default_enabled_control")
			}
		}
	}
}

func (collector *xinetdCollector) addService(parsed xinetdParsedService) {
	if len(collector.services) >= xinetdMaxBlocks {
		collector.markIncomplete("service_block_limit_exceeded")
		return
	}
	service := xinetdService{
		name:            parsed.name,
		id:              parsed.name,
		disableKnown:    true,
		controlComplete: true,
	}
	idSeen := false
	disableSeen := false
	flagsSeen := false
	flags := make(map[string]struct{})
	for _, assignment := range parsed.assignments {
		switch assignment.key {
		case "id":
			if idSeen || assignment.operator != "=" || len(assignment.values) != 1 || !validXinetdIdentifier(assignment.values[0]) {
				service.controlComplete = false
				continue
			}
			idSeen = true
			service.id = assignment.values[0]
		case "disable":
			value, known := xinetdYesNo(assignment)
			if disableSeen || !known {
				service.disableKnown = false
				service.controlComplete = false
				continue
			}
			disableSeen = true
			service.disable = &value
		case "flags":
			if flagsSeen || !addXinetdSetValues(flags, assignment, false) {
				service.controlComplete = false
			}
			flagsSeen = true
		}
	}
	_, service.disableFlag = flags["disable"]
	collector.services = append(collector.services, service)
}

func (collector *xinetdCollector) finish() xinetdInspection {
	idCounts := make(map[string]int, len(collector.services))
	for _, service := range collector.services {
		idCounts[service.id]++
	}
	for _, count := range idCounts {
		if count > 1 {
			collector.markIncomplete("duplicate_service_id")
			break
		}
	}
	inspection := xinetdInspection{Complete: collector.complete}
	for _, service := range collector.services {
		if _, target := collector.targets[strings.ToLower(service.name)]; !target {
			continue
		}
		inspection.Configured++
		if !service.controlComplete || !service.disableKnown {
			collector.reasons["ambiguous_service_control"] = struct{}{}
		}
		if !collector.complete || !service.controlComplete || !service.disableKnown || idCounts[service.id] != 1 {
			inspection.Indeterminate++
			inspection.Complete = false
			continue
		}
		if collector.serviceEnabled(service) {
			inspection.Enabled++
		} else {
			inspection.Disabled++
		}
	}
	if !collector.complete {
		inspection.Complete = false
	}
	return inspection
}

func (collector *xinetdCollector) serviceEnabled(service xinetdService) bool {
	disabled := false
	if collector.defaults.disable != nil {
		disabled = *collector.defaults.disable
	}
	if service.disable != nil {
		disabled = *service.disable
	}
	if service.disableFlag {
		disabled = true
	}
	if _, listed := collector.defaults.disabled[service.id]; listed {
		disabled = true
	}
	if collector.defaults.enabledSeen {
		if _, listed := collector.defaults.enabled[service.id]; !listed {
			disabled = true
		}
	}
	return !disabled
}

func (collector *xinetdCollector) markIncomplete(reason string) {
	collector.complete = false
	collector.reasons[reason] = struct{}{}
}

func parseXinetdDocument(data []byte) ([]xinetdNode, error) {
	tokens, err := tokenizeXinetd(data)
	if err != nil {
		return nil, err
	}
	parser := xinetdParser{tokens: tokens}
	return parser.parse()
}

type xinetdParser struct {
	tokens []xinetdToken
	index  int
}

func (parser *xinetdParser) parse() ([]xinetdNode, error) {
	nodes := make([]xinetdNode, 0)
	for {
		parser.skipNewlines()
		if parser.done() {
			return nodes, nil
		}
		header := parser.take()
		if len(nodes) >= xinetdMaxNodes {
			return nil, errors.New("xinetd document contains too many declarations")
		}
		switch strings.ToLower(header.value) {
		case "include", "includedir":
			values, err := parser.lineValues()
			if err != nil || len(values) != 1 {
				return nil, fmt.Errorf("line %d has an invalid include directive", header.line)
			}
			nodes = append(nodes, xinetdNode{kind: strings.ToLower(header.value), include: values[0], sourceLine: header.line})
		case "defaults":
			assignments, err := parser.block("")
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, xinetdNode{kind: "defaults", defaults: assignments, sourceLine: header.line})
		case "service":
			name, err := parser.serviceName()
			if err != nil {
				return nil, err
			}
			assignments, err := parser.block(name)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, xinetdNode{kind: "service", service: xinetdParsedService{name: name, assignments: assignments}, sourceLine: header.line})
		default:
			return nil, fmt.Errorf("line %d has an unsupported top-level declaration", header.line)
		}
	}
}

func (parser *xinetdParser) serviceName() (string, error) {
	if parser.done() || parser.peek().value == "\n" || parser.peek().value == "{" {
		return "", errors.New("service declaration is missing a name")
	}
	name := parser.take().value
	if !validXinetdIdentifier(name) {
		return "", errors.New("service declaration has an invalid name")
	}
	return name, nil
}

func (parser *xinetdParser) block(_ string) ([]xinetdAssignment, error) {
	parser.skipNewlines()
	if parser.done() || parser.take().value != "{" {
		return nil, errors.New("xinetd block is missing an opening brace")
	}
	assignments := make([]xinetdAssignment, 0)
	for {
		parser.skipNewlines()
		if parser.done() {
			return nil, errors.New("xinetd block is missing a closing brace")
		}
		if parser.peek().value == "}" {
			parser.take()
			if !parser.done() && parser.peek().value != "\n" {
				return nil, errors.New("xinetd block has trailing tokens")
			}
			return assignments, nil
		}
		key := parser.take()
		if key.value == "{" || key.value == "=" || key.value == "+=" || key.value == "-=" {
			return nil, fmt.Errorf("line %d has an invalid assignment", key.line)
		}
		if parser.done() {
			return nil, fmt.Errorf("line %d has an incomplete assignment", key.line)
		}
		operator := parser.take()
		if operator.value != "=" && operator.value != "+=" && operator.value != "-=" {
			return nil, fmt.Errorf("line %d is missing an assignment operator", key.line)
		}
		values := make([]string, 0)
		for !parser.done() && parser.peek().value != "\n" && parser.peek().value != "}" {
			value := parser.take()
			if value.value == "{" || value.value == "=" || value.value == "+=" || value.value == "-=" {
				return nil, fmt.Errorf("line %d has an invalid assignment value", value.line)
			}
			values = append(values, value.value)
		}
		if len(assignments) >= xinetdMaxAssignments {
			return nil, errors.New("xinetd block contains too many assignments")
		}
		assignments = append(assignments, xinetdAssignment{
			key: strings.ToLower(key.value), operator: operator.value, values: values, line: key.line,
		})
	}
}

func (parser *xinetdParser) lineValues() ([]string, error) {
	values := make([]string, 0)
	for !parser.done() && parser.peek().value != "\n" {
		value := parser.take()
		if value.value == "{" || value.value == "}" || value.value == "=" || value.value == "+=" || value.value == "-=" {
			return nil, errors.New("invalid directive value")
		}
		values = append(values, value.value)
	}
	return values, nil
}

func (parser *xinetdParser) skipNewlines() {
	for !parser.done() && parser.peek().value == "\n" {
		parser.index++
	}
}

func (parser *xinetdParser) done() bool        { return parser.index >= len(parser.tokens) }
func (parser *xinetdParser) peek() xinetdToken { return parser.tokens[parser.index] }
func (parser *xinetdParser) take() xinetdToken {
	token := parser.tokens[parser.index]
	parser.index++
	return token
}

func tokenizeXinetd(data []byte) ([]xinetdToken, error) {
	tokens := make([]xinetdToken, 0, len(data)/4)
	line := 1
	for index := 0; index < len(data); {
		if len(tokens) >= xinetdMaxTokens {
			return nil, errors.New("xinetd document contains too many tokens")
		}
		character := data[index]
		switch character {
		case '\r':
			if index+1 < len(data) && data[index+1] == '\n' {
				index++
			}
			tokens = append(tokens, xinetdToken{value: "\n", line: line})
			line++
			index++
		case '\n':
			tokens = append(tokens, xinetdToken{value: "\n", line: line})
			line++
			index++
		case ' ', '\t', '\v', '\f':
			index++
		case '#':
			for index < len(data) && data[index] != '\r' && data[index] != '\n' {
				index++
			}
		case '{', '}':
			tokens = append(tokens, xinetdToken{value: string(character), line: line})
			index++
		case '=', '+', '-':
			operator := string(character)
			if character != '=' {
				if index+1 >= len(data) || data[index+1] != '=' {
					word, next := xinetdBareWord(data, index)
					tokens = append(tokens, xinetdToken{value: word, line: line})
					index = next
					continue
				}
				operator += "="
				index++
			}
			tokens = append(tokens, xinetdToken{value: operator, line: line})
			index++
		case '\'', '"':
			value, next, err := xinetdQuotedWord(data, index, line)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, xinetdToken{value: value, line: line})
			index = next
		default:
			if character == 0 || (character < 0x20 && !unicode.IsSpace(rune(character))) {
				return nil, fmt.Errorf("line %d contains an unsupported control character", line)
			}
			word, next := xinetdBareWord(data, index)
			tokens = append(tokens, xinetdToken{value: word, line: line})
			index = next
		}
	}
	return tokens, nil
}

func xinetdBareWord(data []byte, start int) (string, int) {
	index := start
	for index < len(data) {
		character := data[index]
		if character == '\r' || character == '\n' || character == ' ' || character == '\t' || character == '\v' || character == '\f' ||
			character == '#' || character == '{' || character == '}' || character == '=' ||
			((character == '+' || character == '-') && index+1 < len(data) && data[index+1] == '=') {
			break
		}
		index++
	}
	return string(data[start:index]), index
}

func xinetdQuotedWord(data []byte, start, line int) (string, int, error) {
	quote := data[start]
	var value strings.Builder
	for index := start + 1; index < len(data); index++ {
		character := data[index]
		if character == '\r' || character == '\n' {
			return "", 0, fmt.Errorf("line %d has an unterminated quoted value", line)
		}
		if character == quote {
			return value.String(), index + 1, nil
		}
		if character == '\\' {
			if index+1 >= len(data) {
				return "", 0, fmt.Errorf("line %d has an unterminated escape", line)
			}
			index++
			character = data[index]
		}
		value.WriteByte(character)
	}
	return "", 0, fmt.Errorf("line %d has an unterminated quoted value", line)
}

func xinetdYesNo(assignment xinetdAssignment) (bool, bool) {
	if assignment.operator != "=" || len(assignment.values) != 1 {
		return false, false
	}
	switch strings.ToLower(assignment.values[0]) {
	case "yes":
		return true, true
	case "no":
		return false, true
	default:
		return false, false
	}
}

func addXinetdSetValues(values map[string]struct{}, assignment xinetdAssignment, caseSensitive bool) bool {
	if assignment.operator != "=" {
		return false
	}
	for _, value := range assignment.values {
		if !validXinetdIdentifier(value) {
			return false
		}
		if !caseSensitive {
			value = strings.ToLower(value)
		}
		values[value] = struct{}{}
	}
	return true
}

func validXinetdIdentifier(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= xinetdMaxIdentifier && !strings.ContainsAny(value, " \t\r\n/\\{}=#\x00")
}

func canonicalXinetdPath(value string) (string, bool) {
	if value == "" || len(value) > xinetdMaxPathSize || strings.IndexByte(value, 0) >= 0 || !strings.HasPrefix(value, "/") || strings.Contains(value, "\\") {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned == "/" {
		return "", false
	}
	return cleaned, true
}

func digestStrings(values []string) string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func sortedStringSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
