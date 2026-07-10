package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

var errFTPUnsupportedConfiguration = errors.New("unsupported FTP configuration")

const (
	vsftpdConfigurationPath  = "/etc/vsftpd/vsftpd.conf"
	proFTPDConfigurationPath = "/etc/proftpd.conf"
	maximumFTPConfigFiles    = 256
	maximumFTPIncludeDepth   = 64
)

type vsftpdConfiguration struct {
	settings      map[string]string
	directives    int
	overrides     int
	dynamicConfig bool
	digest        string
}

type proFTPDNode struct {
	name     string
	args     []string
	block    bool
	children []proFTPDNode
}

type proFTPDStatement struct {
	name    string
	args    []string
	opening bool
	closing bool
}

type proFTPDConfiguration struct {
	nodes      []proFTPDNode
	files      int
	directives int
	includes   int
	digest     string
}

type proFTPDLoader struct {
	files       system.Reader
	digest      hash.Hash
	uniqueFiles map[string]struct{}
	loads       int
	directives  int
	includes    int
}

func inspectFTPTarget(ctx context.Context, environment evaluator.Environment) (serviceTarget, *evaluator.Outcome) {
	target, terminal := inspectServiceTarget(ctx, environment, "FTP 서비스", ftpRootLoginProducts, []int{21, 990}, "tcp")
	if terminal != nil {
		terminal.Evidence = sanitizeFTPEvidence(terminal.Evidence)
		return serviceTarget{}, terminal
	}
	target.evidence = sanitizeFTPEvidence(target.evidence)
	return target, nil
}

func inspectFTPComponents(ctx context.Context, environment evaluator.Environment) (present, absenceKnown, explicitlyDisabled bool, evidence []model.Evidence, err error) {
	unitNames := make([]string, 0)
	unitProducts := make(map[string]string)
	for _, product := range ftpRootLoginProducts {
		unitNames = append(unitNames, product.units...)
		for _, unit := range product.units {
			if previous, duplicate := unitProducts[unit]; duplicate && previous != product.id {
				return false, false, false, nil, fmt.Errorf("FTP unit %s is shared by multiple products", unit)
			}
			unitProducts[unit] = product.id
		}
	}
	unitNames = uniqueStrings(unitNames)
	units, unitEvidence, err := support.InspectUnits(ctx, environment, unitNames)
	if err != nil {
		return false, false, false, nil, err
	}
	evidence = append(evidence, sanitizeFTPEvidence(unitEvidence)...)
	installedUnits := 0
	installedUnitProducts := make(map[string]bool)
	explicitlyDisabled = true
	for index, unit := range units {
		if !support.UnitInstalled(unit) {
			continue
		}
		installedUnits++
		installedUnitProducts[unitProducts[unitNames[index]]] = true
		present = true
		explicitlyDisabled = explicitlyDisabled && ftpUnitExplicitlyDisabled(unit)
	}
	if !environment.Commands.Available("rpm") {
		evidence = append(evidence, support.FactEvidence("ftp-package-inventory-summary", map[string]any{
			"rpm_available": false, "component_present": present,
			"installed_unit_count": installedUnits, "explicitly_disabled": present && explicitlyDisabled,
		}))
		return present, present, present && explicitlyDisabled, evidence, nil
	}
	absenceKnown = true
	installedPackages := 0
	for _, packageName := range []string{"vsftpd", "proftpd", "pure-ftpd"} {
		spec := executor.Spec{
			Name: "rpm", Arguments: []string{"-q", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n", packageName},
			Timeout: 30 * time.Second, MaxOutput: 1 << 20,
		}
		result, runErr := environment.Commands.Run(ctx, spec)
		if runErr != nil {
			return false, false, false, evidence, runErr
		}
		evidence = append(evidence, privateCommandSummary(spec, result))
		if result.Truncated {
			return false, false, false, evidence, fmt.Errorf("FTP package query was truncated")
		}
		switch result.ExitCode {
		case 0:
			installedPackages++
			present = true
			if !installedUnitProducts[packageName] {
				explicitlyDisabled = false
			}
		case 1:
		default:
			return false, false, false, evidence, fmt.Errorf("FTP package query exit=%d", result.ExitCode)
		}
	}
	evidence = append(evidence, support.FactEvidence("ftp-package-inventory-summary", map[string]any{
		"rpm_available": true, "installed_package_count": installedPackages, "installed_unit_count": installedUnits,
		"component_present": present, "explicitly_disabled": present && explicitlyDisabled,
	}))
	return present, absenceKnown, present && explicitlyDisabled, evidence, nil
}

func ftpUnitExplicitlyDisabled(unit support.UnitState) bool {
	switch unit.UnitFileState {
	case "disabled", "masked":
		return !support.UnitActive(unit) && !support.UnitEnabled(unit)
	default:
		return false
	}
}

func sanitizeFTPEvidence(evidence []model.Evidence) []model.Evidence {
	sanitized := make([]model.Evidence, 0, len(evidence))
	for _, item := range evidence {
		if item.Command == nil {
			if item.Redacted {
				sanitized = append(sanitized, item)
			}
			continue
		}
		stdoutDigest := sha256.Sum256([]byte(item.Command.Stdout))
		stderrDigest := sha256.Sum256([]byte(item.Command.Stderr))
		sanitized = append(sanitized, support.FactEvidence("ftp-target-command-summary", map[string]any{
			"command_name":      path.Base(item.Command.Executable),
			"exit_code":         item.Command.ExitCode,
			"duration_ms":       item.Command.DurationMS,
			"timed_out":         item.Command.TimedOut,
			"truncated":         item.Command.Truncated,
			"stdout_sha256":     hex.EncodeToString(stdoutDigest[:]),
			"stderr_sha256":     hex.EncodeToString(stderrDigest[:]),
			"stdout_line_count": countNonEmptyTextLines(item.Command.Stdout),
			"content_redacted":  true,
		}))
	}
	return sanitized
}

func inspectVSFTPDConfiguration(ctx context.Context, environment evaluator.Environment, evidence []model.Evidence) (vsftpdConfiguration, []model.Evidence, error) {
	data, _, err := environment.Files.ReadFile(ctx, vsftpdConfigurationPath, 2<<20)
	if err != nil {
		return vsftpdConfiguration{}, evidence, ftpPrivateFileError("read vsftpd configuration", err)
	}
	configuration, err := parseVSFTPDConfiguration(data)
	if err != nil {
		return vsftpdConfiguration{}, evidence, err
	}
	evidence = append(evidence, support.FactEvidence("vsftpd-configuration-summary", map[string]any{
		"configuration_sha256":  configuration.digest,
		"directive_count":       configuration.directives,
		"override_count":        configuration.overrides,
		"dynamic_configuration": configuration.dynamicConfig,
		"content_redacted":      true,
	}))
	return configuration, evidence, nil
}

func parseVSFTPDConfiguration(data []byte) (vsftpdConfiguration, error) {
	configuration := vsftpdConfiguration{settings: make(map[string]string)}
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || strings.TrimSpace(key) != key || strings.TrimSpace(value) != value {
			return vsftpdConfiguration{}, fmt.Errorf("vsftpd line %d is not a canonical key=value directive", lineNumber+1)
		}
		key = strings.ToLower(key)
		if _, exists := configuration.settings[key]; exists {
			configuration.overrides++
		}
		configuration.settings[key] = value
		configuration.directives++
		switch key {
		case "include", "include_file", "config_file":
			configuration.dynamicConfig = true
		}
	}
	digest := sha256.Sum256(data)
	configuration.digest = hex.EncodeToString(digest[:])
	return configuration, nil
}

func inspectProFTPDConfiguration(ctx context.Context, environment evaluator.Environment, evidence []model.Evidence) (proFTPDConfiguration, []model.Evidence, error) {
	loader := &proFTPDLoader{
		files:       environment.Files,
		digest:      sha256.New(),
		uniqueFiles: make(map[string]struct{}),
	}
	statements, err := loader.load(ctx, proFTPDConfigurationPath, make(map[string]struct{}), 0)
	if err != nil {
		return proFTPDConfiguration{}, evidence, err
	}
	index := 0
	nodes, err := parseProFTPDNodes(statements, &index, "", 0)
	if err != nil {
		return proFTPDConfiguration{}, evidence, err
	}
	if index != len(statements) {
		return proFTPDConfiguration{}, evidence, fmt.Errorf("ProFTPD configuration has trailing statements")
	}
	configuration := proFTPDConfiguration{
		nodes:      nodes,
		files:      len(loader.uniqueFiles),
		directives: loader.directives,
		includes:   loader.includes,
		digest:     hex.EncodeToString(loader.digest.Sum(nil)),
	}
	evidence = append(evidence, support.FactEvidence("proftpd-configuration-summary", map[string]any{
		"configuration_sha256": configuration.digest,
		"file_count":           configuration.files,
		"directive_count":      configuration.directives,
		"include_count":        configuration.includes,
		"content_redacted":     true,
	}))
	return configuration, evidence, nil
}

func (loader *proFTPDLoader) load(
	ctx context.Context,
	filePath string,
	stack map[string]struct{},
	depth int,
) ([]proFTPDStatement, error) {
	if depth >= maximumFTPIncludeDepth {
		return nil, fmt.Errorf("ProFTPD include depth exceeds %d", maximumFTPIncludeDepth)
	}
	if _, exists := stack[filePath]; exists {
		return nil, fmt.Errorf("ProFTPD include cycle detected")
	}
	if loader.loads >= maximumFTPConfigFiles {
		return nil, fmt.Errorf("ProFTPD configuration file count exceeds %d", maximumFTPConfigFiles)
	}
	loader.loads++
	metadata, err := loader.files.Lstat(filePath)
	if err != nil {
		return nil, ftpPrivateFileError("inspect ProFTPD configuration", err)
	}
	if metadata.FileType == "symlink" {
		return nil, fmt.Errorf("%w: ProFTPD include uses a symbolic link", errFTPUnsupportedConfiguration)
	}
	data, _, err := loader.files.ReadFile(ctx, filePath, 2<<20)
	if err != nil {
		return nil, ftpPrivateFileError("read ProFTPD configuration", err)
	}
	loader.uniqueFiles[filePath] = struct{}{}
	_, _ = loader.digest.Write([]byte(filePath))
	_, _ = loader.digest.Write([]byte{0})
	_, _ = loader.digest.Write(data)
	_, _ = loader.digest.Write([]byte{0})

	parsed, err := parseProFTPDStatements(data)
	if err != nil {
		return nil, err
	}
	stack[filePath] = struct{}{}
	defer delete(stack, filePath)
	expanded := make([]proFTPDStatement, 0, len(parsed))
	for _, statement := range parsed {
		if statement.opening || statement.closing || statement.name != "include" {
			expanded = append(expanded, statement)
			if !statement.opening && !statement.closing {
				loader.directives++
			}
			continue
		}
		if len(statement.args) != 1 || !path.IsAbs(statement.args[0]) || strings.Contains(statement.args[0], "%{") {
			return nil, fmt.Errorf("%w: ProFTPD include path is not a supported absolute pattern", errFTPUnsupportedConfiguration)
		}
		matches, err := expandFTPConfigPattern(loader.files, statement.args[0])
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return nil, fmt.Errorf("%w: ProFTPD include pattern has no matches", errFTPUnsupportedConfiguration)
		}
		loader.includes++
		for _, includedPath := range matches {
			included, loadErr := loader.load(ctx, includedPath, stack, depth+1)
			if loadErr != nil {
				return nil, loadErr
			}
			expanded = append(expanded, included...)
		}
	}
	return expanded, nil
}

func parseProFTPDStatements(data []byte) ([]proFTPDStatement, error) {
	logicalLines, err := proFTPDLogicalLines(data)
	if err != nil {
		return nil, err
	}
	statements := make([]proFTPDStatement, 0, len(logicalLines))
	for lineNumber, raw := range logicalLines {
		line, err := stripProFTPDComment(raw)
		if err != nil {
			return nil, fmt.Errorf("ProFTPD line %d: %w", lineNumber+1, err)
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		statement := proFTPDStatement{}
		if strings.HasPrefix(line, "<") {
			if !strings.HasSuffix(line, ">") {
				return nil, fmt.Errorf("ProFTPD line %d has an unterminated block tag", lineNumber+1)
			}
			inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<"), ">"))
			if strings.HasPrefix(inner, "/") {
				statement.closing = true
				inner = strings.TrimSpace(strings.TrimPrefix(inner, "/"))
			} else {
				statement.opening = true
			}
			fields, splitErr := splitProFTPDFields(inner)
			if splitErr != nil || len(fields) == 0 {
				return nil, fmt.Errorf("ProFTPD line %d has an invalid block tag", lineNumber+1)
			}
			statement.name = strings.ToLower(fields[0])
			statement.args = fields[1:]
			if statement.closing && len(statement.args) != 0 {
				return nil, fmt.Errorf("ProFTPD line %d has arguments on a closing tag", lineNumber+1)
			}
			statements = append(statements, statement)
			continue
		}
		fields, splitErr := splitProFTPDFields(line)
		if splitErr != nil || len(fields) == 0 {
			return nil, fmt.Errorf("ProFTPD line %d has invalid quoting", lineNumber+1)
		}
		statement.name = strings.ToLower(fields[0])
		statement.args = fields[1:]
		statements = append(statements, statement)
	}
	return statements, nil
}

func parseProFTPDNodes(statements []proFTPDStatement, index *int, closing string, depth int) ([]proFTPDNode, error) {
	if depth >= maximumFTPIncludeDepth {
		return nil, fmt.Errorf("ProFTPD block depth exceeds %d", maximumFTPIncludeDepth)
	}
	nodes := make([]proFTPDNode, 0)
	for *index < len(statements) {
		statement := statements[*index]
		(*index)++
		if statement.closing {
			if closing == "" || statement.name != closing {
				return nil, fmt.Errorf("ProFTPD block closing tag does not match")
			}
			return nodes, nil
		}
		node := proFTPDNode{name: statement.name, args: append([]string(nil), statement.args...), block: statement.opening}
		if statement.opening {
			children, err := parseProFTPDNodes(statements, index, statement.name, depth+1)
			if err != nil {
				return nil, err
			}
			node.children = children
		}
		nodes = append(nodes, node)
	}
	if closing != "" {
		return nil, fmt.Errorf("ProFTPD block is not closed")
	}
	return nodes, nil
}

func expandFTPConfigPattern(files system.Reader, pattern string) ([]string, error) {
	cleaned := path.Clean(pattern)
	if !path.IsAbs(cleaned) {
		return nil, fmt.Errorf("ProFTPD include pattern is not absolute")
	}
	segments := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")
	candidates := []string{"/"}
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		next := make([]string, 0)
		for _, parent := range candidates {
			if !strings.ContainsAny(segment, "*?[") {
				next = append(next, path.Join(parent, segment))
				continue
			}
			entries, err := files.ReadDir(parent)
			if err != nil {
				return nil, ftpPrivateFileError("read ProFTPD include directory", err)
			}
			for _, entry := range entries {
				matched, matchErr := path.Match(segment, entry.Name())
				if matchErr != nil {
					return nil, fmt.Errorf("ProFTPD include pattern is invalid")
				}
				if matched {
					next = append(next, path.Join(parent, entry.Name()))
				}
			}
		}
		for _, candidate := range next {
			metadata, err := files.Lstat(candidate)
			if err != nil {
				return nil, ftpPrivateFileError("inspect ProFTPD include path", err)
			}
			if metadata.FileType == "symlink" {
				return nil, fmt.Errorf("%w: ProFTPD include path traverses a symbolic link", errFTPUnsupportedConfiguration)
			}
		}
		candidates = next
		if len(candidates) > maximumFTPConfigFiles {
			return nil, fmt.Errorf("ProFTPD include expansion exceeds %d files", maximumFTPConfigFiles)
		}
	}
	expanded := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		metadata, err := files.Lstat(candidate)
		if err != nil {
			return nil, ftpPrivateFileError("inspect ProFTPD include path", err)
		}
		if metadata.FileType != "directory" {
			expanded = append(expanded, candidate)
			continue
		}
		entries, err := files.ReadDir(candidate)
		if err != nil {
			return nil, ftpPrivateFileError("read ProFTPD included directory", err)
		}
		for _, entry := range entries {
			childPath := path.Join(candidate, entry.Name())
			childMetadata, statErr := files.Lstat(childPath)
			if statErr != nil {
				return nil, ftpPrivateFileError("inspect ProFTPD included file", statErr)
			}
			switch childMetadata.FileType {
			case "regular":
				expanded = append(expanded, childPath)
			case "symlink":
				return nil, fmt.Errorf("%w: ProFTPD included directory contains a symbolic link", errFTPUnsupportedConfiguration)
			default:
				return nil, fmt.Errorf("%w: ProFTPD included directory contains a non-regular entry", errFTPUnsupportedConfiguration)
			}
		}
	}
	if len(expanded) > maximumFTPConfigFiles {
		return nil, fmt.Errorf("ProFTPD include expansion exceeds %d files", maximumFTPConfigFiles)
	}
	sort.Strings(expanded)
	return expanded, nil
}

func proFTPDLogicalLines(data []byte) ([]string, error) {
	physical := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	logical := make([]string, 0, len(physical))
	var pending strings.Builder
	for _, raw := range physical {
		commentFree, err := stripProFTPDComment(raw)
		if err != nil {
			return nil, err
		}
		trimmedRight := strings.TrimRightFunc(commentFree, unicode.IsSpace)
		continuation := hasOddTrailingBackslash(trimmedRight)
		if continuation {
			pending.WriteString(strings.TrimSuffix(trimmedRight, "\\"))
			pending.WriteByte(' ')
			continue
		}
		pending.WriteString(commentFree)
		logical = append(logical, pending.String())
		pending.Reset()
	}
	if pending.Len() > 0 {
		return nil, fmt.Errorf("ProFTPD configuration ends with a continuation")
	}
	return logical, nil
}

func hasOddTrailingBackslash(value string) bool {
	count := 0
	for index := len(value) - 1; index >= 0 && value[index] == '\\'; index-- {
		count++
	}
	return count%2 == 1
}

func stripProFTPDComment(line string) (string, error) {
	quote := rune(0)
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
		if quote != 0 {
			if character == quote {
				quote = 0
			}
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			continue
		}
		if character == '#' {
			return line[:index], nil
		}
	}
	if quote != 0 {
		return "", fmt.Errorf("unterminated quote")
	}
	return line, nil
}

func splitProFTPDFields(line string) ([]string, error) {
	fields := make([]string, 0)
	var current strings.Builder
	quote := rune(0)
	escaped := false
	started := false
	flush := func() {
		if started {
			fields = append(fields, current.String())
			current.Reset()
			started = false
		}
	}
	for _, character := range line {
		if escaped {
			current.WriteRune(character)
			started = true
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			started = true
			continue
		}
		if quote != 0 {
			if character == quote {
				quote = 0
			} else {
				current.WriteRune(character)
			}
			started = true
			continue
		}
		if character == '\'' || character == '"' {
			quote = character
			started = true
			continue
		}
		if unicode.IsSpace(character) {
			flush()
			continue
		}
		current.WriteRune(character)
		started = true
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unterminated quote or escape")
	}
	flush()
	return fields, nil
}

func proFTPDServerScopes(nodes []proFTPDNode) [][]proFTPDNode {
	scopes := [][]proFTPDNode{nodes}
	for _, node := range nodes {
		if node.block && node.name == "virtualhost" {
			scopes = append(scopes, node.children)
		}
	}
	return scopes
}

func directProFTPDNodes(nodes []proFTPDNode, name string) []proFTPDNode {
	result := make([]proFTPDNode, 0)
	for _, node := range nodes {
		if node.name == name {
			result = append(result, node)
		}
	}
	return result
}

func allProFTPDNodes(nodes []proFTPDNode, names map[string]bool) []proFTPDNode {
	result := make([]proFTPDNode, 0)
	var visit func([]proFTPDNode)
	visit = func(current []proFTPDNode) {
		for _, node := range current {
			if names[node.name] {
				result = append(result, node)
			}
			if node.block {
				visit(node.children)
			}
		}
	}
	visit(nodes)
	return result
}

func singleProFTPDDirective(nodes []proFTPDNode, name string) (proFTPDNode, string) {
	found := directProFTPDNodes(nodes, name)
	if len(found) == 0 {
		return proFTPDNode{}, "missing"
	}
	canonical := strings.Join(found[0].args, "\x00")
	for _, node := range found[1:] {
		if strings.Join(node.args, "\x00") != canonical {
			return proFTPDNode{}, "conflict"
		}
	}
	return found[len(found)-1], "ok"
}

func hasProFTPDDynamicScope(nodes []proFTPDNode, relevant map[string]bool) bool {
	dynamicBlocks := map[string]bool{
		"ifmodule": true, "ifdefine": true, "ifsession": true, "ifuser": true, "ifgroup": true, "ifclass": true,
	}
	var containsRelevant func([]proFTPDNode) bool
	containsRelevant = func(current []proFTPDNode) bool {
		for _, node := range current {
			if relevant[node.name] {
				return true
			}
			if node.block && containsRelevant(node.children) {
				return true
			}
		}
		return false
	}
	var visit func([]proFTPDNode) bool
	visit = func(current []proFTPDNode) bool {
		for _, node := range current {
			if node.block && dynamicBlocks[node.name] && containsRelevant(node.children) {
				return true
			}
			if node.block && visit(node.children) {
				return true
			}
		}
		return false
	}
	return visit(nodes)
}

func readFTPPrivateFile(ctx context.Context, files system.Reader, filePath string) ([]byte, model.Evidence, error) {
	if !path.IsAbs(filePath) || strings.Contains(filePath, "%{") {
		return nil, model.Evidence{}, fmt.Errorf("%w: FTP referenced file path is dynamic or relative", errFTPUnsupportedConfiguration)
	}
	data, _, err := files.ReadFile(ctx, filePath, 1<<20)
	if err != nil {
		return nil, model.Evidence{}, ftpPrivateFileError("read FTP referenced file", err)
	}
	digest := sha256.Sum256(data)
	return data, support.FactEvidence("ftp-referenced-file-summary", map[string]any{
		"sha256":           hex.EncodeToString(digest[:]),
		"byte_count":       len(data),
		"line_count":       countNonEmptyTextLines(string(data)),
		"content_redacted": true,
	}), nil
}

func countNonEmptyTextLines(content string) int {
	count := 0
	for _, line := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func canonicalFTPText(value string) string {
	return strings.TrimRight(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
}

func hashFTPStrings(values []string) string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	digest := sha256.New()
	for _, value := range values {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func ftpPrivateFileError(operation string, err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s: file not found", operation)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%s: permission denied", operation)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: operation canceled", operation)
	default:
		return fmt.Errorf("%s: file access failed", operation)
	}
}

func ftpCheckError(code string, err error, evidence []model.Evidence) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "FTP 서비스 설정을 수집하거나 해석하지 못했습니다.",
		Evidence:     evidence,
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}

func isFTPNonLoginShell(shell string) bool {
	switch strings.TrimSpace(shell) {
	case "/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false":
		return true
	default:
		return false
	}
}
