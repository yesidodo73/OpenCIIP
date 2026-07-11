package logging

import (
	"context"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/checks/support"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const (
	EvaluatorLogFilePermissions = "unix.log.file_permissions"
	maxLogFiles                 = 4096
	aclBatchSize                = 48
)

type logMountInfo struct {
	target  string
	fstype  string
	options string
}

type logInventory struct {
	files             []system.FileMetadata
	evidence          []model.Evidence
	incomplete        bool
	symlinkFiles      int
	crossDeviceMounts int
}

type aclAssessment struct {
	clearReasons     []string
	ambiguousReasons []string
}

func evaluateLogFilePermissions(ctx context.Context, rule model.ResolvedRule, environment evaluator.Environment) evaluator.Outcome {
	expected := strings.TrimSpace(rule.Criteria.Pass)
	if expected == "" {
		expected = "영속 로그 파일은 root 소유이고 권한과 ACL이 0644 허용 비트 이내여야 합니다."
	}
	if environment.Platform.InitSystem != "systemd" {
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "활성 로깅 서비스와 로그 파일 범위를 지원하는 방식으로 확인할 수 없습니다.",
			Expected:      expected,
			Observed:      environment.Platform.InitSystem,
		}
	}

	units, unitEvidence, err := support.InspectUnits(ctx, environment, []string{
		"rsyslog.service",
		"systemd-journald.service",
		"auditd.service",
	})
	if err != nil {
		return logFilePermissionError("logging_service_inspection_failed", err)
	}
	evidence := append([]model.Evidence(nil), unitEvidence...)
	activeUnits := make([]string, 0, len(units))
	for _, unit := range units {
		if support.UnitActive(unit) {
			activeUnits = append(activeUnits, unit.Name)
		}
	}
	sort.Strings(activeUnits)
	processes, processEvidence, err := support.InspectProcesses(ctx, environment, []string{"rsyslogd", "systemd-journal", "auditd"})
	if err != nil {
		return logFilePermissionError("logging_process_inspection_failed", err)
	}
	evidence = append(evidence, processEvidence)
	evidence = append(evidence, support.FactEvidence("logging-backends", map[string]any{
		"active_processes": processes,
		"active_units":     activeUnits,
	}))

	mount, mountEvidence, err := inspectLogMount(ctx, environment)
	if err != nil {
		return logFilePermissionError("log_mount_inspection_failed", err)
	}
	evidence = append(evidence, mountEvidence)
	switch strings.ToLower(mount.fstype) {
	case "tmpfs", "ramfs":
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "/var/log가 비영속 메모리 파일 시스템에 있어 적용할 영속 로그 파일이 없습니다.",
			Expected: expected,
			Observed: fmt.Sprintf("target=%s fstype=%s", mount.target, mount.fstype),
			Evidence: evidence,
		}
	case "overlay", "aufs":
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: model.UnknownUnsupportedConfiguration,
			Summary:       "/var/log의 영속성 경계를 확정할 수 없는 파일 시스템입니다.",
			Expected:      expected,
			Observed:      fmt.Sprintf("target=%s fstype=%s", mount.target, mount.fstype),
			Evidence:      evidence,
		}
	}

	inventory, err := inventoryLogFiles(ctx, environment.Files)
	if err != nil {
		return logFilePermissionError("log_inventory_failed", err)
	}
	evidence = append(evidence, inventory.evidence...)
	evidence = append(evidence, support.FactEvidence("/var/log", map[string]any{
		"regular_files":       len(inventory.files),
		"inventory_complete":  !inventory.incomplete,
		"symlink_files":       inventory.symlinkFiles,
		"cross_device_mounts": inventory.crossDeviceMounts,
	}))
	if len(inventory.files) == 0 {
		if inventory.incomplete {
			return evaluator.Outcome{
				Status:        model.StatusUnknown,
				UnknownReason: model.UnknownUnsupportedConfiguration,
				Summary:       "영속 로그 파일 목록을 완전히 수집하지 못했습니다.",
				Expected:      expected,
				Observed:      "확인 가능한 regular 로그 파일이 없고 일부 경계는 미확인 상태입니다.",
				Evidence:      evidence,
			}
		}
		return evaluator.Outcome{
			Status:   model.StatusNotApplicable,
			Summary:  "적용 가능한 영속 regular 로그 파일이 없습니다.",
			Expected: expected,
			Observed: "/var/log regular file count=0",
			Evidence: evidence,
		}
	}

	paths := make([]string, len(inventory.files))
	for index, metadata := range inventory.files {
		paths[index] = metadata.Path
	}
	aclResults, aclEvidence, err := inspectLogACLs(ctx, environment, paths)
	if err != nil {
		return logFilePermissionError("log_acl_inspection_failed", err)
	}
	evidence = append(evidence, aclEvidence...)

	clearViolations := make([]string, 0)
	ambiguous := make([]string, 0)
	for _, metadata := range inventory.files {
		assessment, exists := aclResults[metadata.Path]
		if !exists {
			ambiguous = append(ambiguous, metadata.Path+": ACL 결과 없음")
			continue
		}
		clear, uncertain := assessLogFile(metadata, assessment)
		clearViolations = append(clearViolations, clear...)
		ambiguous = append(ambiguous, uncertain...)
	}
	if inventory.incomplete {
		ambiguous = append(ambiguous, "/var/log: 별도 마운트 또는 지원하지 않는 경로로 인해 파일 목록이 불완전함")
	}
	sort.Strings(clearViolations)
	sort.Strings(ambiguous)
	evidence = append(evidence, support.FactEvidence("log-file-permission-findings", map[string]any{
		"clear_violation_count": len(clearViolations),
		"ambiguous_count":       len(ambiguous),
		"clear_violations":      limitedStrings(clearViolations, 100),
		"ambiguous_findings":    limitedStrings(ambiguous, 100),
	}))

	if len(clearViolations) > 0 {
		return evaluator.Outcome{
			Status:   model.StatusFail,
			Summary:  "영속 로그 파일에서 예외로 정당화하기 어려운 위험 권한이 확인되었습니다.",
			Expected: expected,
			Observed: summarizeStrings(clearViolations, 12),
			Evidence: evidence,
		}
	}
	if inventory.incomplete || len(ambiguous) > 0 {
		reason := model.UnknownAmbiguousResult
		summary := "Rocky 기본값 또는 비-root 데몬 요구와 구분할 수 없는 로그 파일 소유권·권한이 있습니다."
		if inventory.incomplete {
			reason = model.UnknownUnsupportedConfiguration
			summary = "일부 로그 경로의 영속성 또는 파일 목록을 완전히 확인하지 못했습니다."
		}
		return evaluator.Outcome{
			Status:        model.StatusUnknown,
			UnknownReason: reason,
			Summary:       summary,
			Expected:      expected,
			Observed:      summarizeStrings(ambiguous, 12),
			Evidence:      evidence,
		}
	}
	return evaluator.Outcome{
		Status:   model.StatusPass,
		Summary:  "모든 확인된 영속 로그 파일의 소유자, 권한 및 ACL이 기준을 충족합니다.",
		Expected: expected,
		Observed: fmt.Sprintf("regular log files=%d", len(inventory.files)),
		Evidence: evidence,
	}
}

func inspectLogMount(ctx context.Context, environment evaluator.Environment) (logMountInfo, model.Evidence, error) {
	spec := executor.Spec{
		Name:      "findmnt",
		Arguments: []string{"-rn", "-T", "/var/log", "-o", "TARGET,FSTYPE,OPTIONS"},
		Timeout:   10 * time.Second,
		MaxOutput: 64 << 10,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return logMountInfo{}, model.Evidence{}, err
	}
	evidence := support.CommandEvidence(spec, result)
	if result.ExitCode != 0 || result.Truncated {
		return logMountInfo{}, evidence, fmt.Errorf("findmnt exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	lines := make([]string, 0, 1)
	for _, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
		if line := strings.TrimSpace(raw); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) != 1 {
		return logMountInfo{}, evidence, fmt.Errorf("findmnt returned %d records", len(lines))
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 3 {
		return logMountInfo{}, evidence, fmt.Errorf("findmnt output is incomplete")
	}
	return logMountInfo{target: fields[0], fstype: fields[1], options: strings.Join(fields[2:], " ")}, evidence, nil
}

func inventoryLogFiles(ctx context.Context, files system.Reader) (logInventory, error) {
	root, err := files.Stat("/var/log")
	if err != nil {
		return logInventory{}, err
	}
	if root.FileType != "directory" {
		return logInventory{}, fmt.Errorf("/var/log is not a directory")
	}
	result := logInventory{}
	directories := []string{"/var/log"}
	seenFiles := make(map[string]struct{})
	for len(directories) > 0 {
		if err := ctx.Err(); err != nil {
			return logInventory{}, err
		}
		directory := directories[0]
		directories = directories[1:]
		entries, err := files.ReadDir(directory)
		if err != nil {
			return logInventory{}, err
		}
		for _, entry := range entries {
			filePath := path.Join(directory, entry.Name())
			if strings.ContainsAny(entry.Name(), " \r\n\t\\") {
				result.incomplete = true
				continue
			}
			metadata, err := files.Lstat(filePath)
			if err != nil {
				return logInventory{}, err
			}
			switch metadata.FileType {
			case "directory":
				if root.Device != 0 && metadata.Device != 0 && metadata.Device != root.Device {
					result.crossDeviceMounts++
					result.incomplete = true
					continue
				}
				directories = append(directories, filePath)
			case "regular":
				verified, statErr := files.Stat(filePath)
				if statErr != nil {
					return logInventory{}, statErr
				}
				if verified.FileType != "regular" || metadata.Device != verified.Device || metadata.Inode != verified.Inode {
					result.incomplete = true
					continue
				}
				addLogFile(&result, seenFiles, verified)
			case "symlink":
				result.symlinkFiles++
				result.evidence = append(result.evidence, support.FileMetadataEvidence(metadata))
				verified, statErr := files.Stat(filePath)
				if statErr != nil {
					result.incomplete = true
					continue
				}
				if verified.FileType == "regular" && (root.Device == 0 || verified.Device == 0 || verified.Device == root.Device) {
					addLogFile(&result, seenFiles, verified)
				}
			}
			if len(result.files) >= maxLogFiles {
				result.incomplete = true
				sort.Slice(result.files, func(i, j int) bool { return result.files[i].Path < result.files[j].Path })
				return result, nil
			}
		}
	}
	sort.Slice(result.files, func(i, j int) bool { return result.files[i].Path < result.files[j].Path })
	return result, nil
}

func addLogFile(inventory *logInventory, seen map[string]struct{}, metadata system.FileMetadata) {
	key := metadata.Path
	if metadata.Device != 0 || metadata.Inode != 0 {
		key = fmt.Sprintf("%d:%d", metadata.Device, metadata.Inode)
	}
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	inventory.files = append(inventory.files, metadata)
	inventory.evidence = append(inventory.evidence, support.FileMetadataEvidence(metadata))
}

func inspectLogACLs(
	ctx context.Context,
	environment evaluator.Environment,
	paths []string,
) (map[string]aclAssessment, []model.Evidence, error) {
	assessments := make(map[string]aclAssessment, len(paths))
	evidence := make([]model.Evidence, 0, (len(paths)+aclBatchSize-1)/aclBatchSize)
	for start := 0; start < len(paths); start += aclBatchSize {
		end := start + aclBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		arguments := append([]string{"-pn", "--"}, paths[start:end]...)
		spec := executor.Spec{Name: "getfacl", Arguments: arguments, Timeout: 30 * time.Second, MaxOutput: 8 << 20}
		result, err := environment.Commands.Run(ctx, spec)
		if err != nil {
			return nil, nil, err
		}
		evidence = append(evidence, support.CommandEvidence(spec, result))
		if result.ExitCode != 0 || result.Truncated {
			return nil, evidence, fmt.Errorf("getfacl exit=%d truncated=%t", result.ExitCode, result.Truncated)
		}
		parsed, err := parseACLDocuments(string(result.Stdout))
		if err != nil {
			return nil, evidence, err
		}
		for _, filePath := range paths[start:end] {
			assessment, exists := parsed[filePath]
			if !exists {
				return nil, evidence, fmt.Errorf("getfacl output is missing a requested path")
			}
			assessments[filePath] = assessment
		}
	}
	return assessments, evidence, nil
}

func parseACLDocuments(content string) (map[string]aclAssessment, error) {
	documents := make(map[string][]string)
	currentPath := ""
	for _, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "# file: ") {
			currentPath = strings.TrimSpace(strings.TrimPrefix(line, "# file: "))
			if currentPath == "" {
				return nil, fmt.Errorf("getfacl output contains an empty file header")
			}
			if _, exists := documents[currentPath]; exists {
				return nil, fmt.Errorf("getfacl output contains a duplicate file header")
			}
			documents[currentPath] = nil
			continue
		}
		if currentPath == "" || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		documents[currentPath] = append(documents[currentPath], line)
	}
	result := make(map[string]aclAssessment, len(documents))
	for filePath, lines := range documents {
		assessment, err := assessACLDocument(lines)
		if err != nil {
			return nil, err
		}
		result[filePath] = assessment
	}
	return result, nil
}

func assessACLDocument(lines []string) (aclAssessment, error) {
	type entry struct {
		tag       string
		qualifier string
		perms     uint8
		effective *uint8
	}
	entries := make([]entry, 0, len(lines))
	mask := uint8(0o7)
	assessment := aclAssessment{}
	for _, raw := range lines {
		mainPart, comment, _ := strings.Cut(raw, "#")
		mainPart = strings.TrimSpace(mainPart)
		if strings.HasPrefix(mainPart, "default:") {
			assessment.ambiguousReasons = append(assessment.ambiguousReasons, "regular 파일에 default ACL이 보고됨")
			continue
		}
		fields := strings.Split(mainPart, ":")
		if len(fields) != 3 {
			return aclAssessment{}, fmt.Errorf("getfacl output contains an invalid ACL entry")
		}
		permissions, err := parseACLPermission(fields[2])
		if err != nil {
			return aclAssessment{}, err
		}
		item := entry{tag: fields[0], qualifier: fields[1], perms: permissions}
		comment = strings.TrimSpace(comment)
		if strings.HasPrefix(comment, "effective:") {
			effective, err := parseACLPermission(strings.TrimSpace(strings.TrimPrefix(comment, "effective:")))
			if err != nil {
				return aclAssessment{}, err
			}
			item.effective = &effective
		}
		if item.tag == "mask" && item.qualifier == "" {
			mask = item.perms
		}
		entries = append(entries, item)
	}
	for _, item := range entries {
		if item.tag == "mask" && item.qualifier == "" {
			continue
		}
		actual := item.perms
		if item.effective != nil {
			actual = *item.effective
		} else if item.tag == "group" || item.qualifier != "" {
			actual &= mask
		}
		allowed := uint8(0o4)
		switch {
		case item.tag == "user" && item.qualifier == "":
			allowed = 0o6
		case item.tag == "group", item.tag == "user" && item.qualifier != "":
			allowed = 0o4
		case item.tag == "other" && item.qualifier == "":
			allowed = 0o4
		default:
			assessment.ambiguousReasons = append(assessment.ambiguousReasons, "지원하지 않는 ACL 항목")
			continue
		}
		extra := actual &^ allowed
		if extra == 0 {
			continue
		}
		reason := fmt.Sprintf("ACL %s:%s 권한이 기준을 초과함", item.tag, item.qualifier)
		if extra&0o1 != 0 || (item.tag == "other" && extra&0o2 != 0) {
			assessment.clearReasons = append(assessment.clearReasons, reason)
		} else {
			assessment.ambiguousReasons = append(assessment.ambiguousReasons, reason+" (서비스 또는 패키지 요구 확인 필요)")
		}
	}
	return assessment, nil
}

func parseACLPermission(value string) (uint8, error) {
	value = strings.TrimSpace(value)
	if len(value) != 3 {
		return 0, fmt.Errorf("getfacl output contains an invalid permission")
	}
	var result uint8
	for index, expected := range []byte{'r', 'w', 'x'} {
		if value[index] == '-' {
			continue
		}
		if value[index] != expected {
			return 0, fmt.Errorf("getfacl output contains an invalid permission")
		}
		result |= 1 << (2 - index)
	}
	return result, nil
}

func assessLogFile(metadata system.FileMetadata, acl aclAssessment) ([]string, []string) {
	clear := make([]string, 0)
	ambiguous := make([]string, 0)
	prefix := metadata.Path + ": "
	if metadata.UID < 0 {
		ambiguous = append(ambiguous, prefix+"소유자 UID를 확인할 수 없음")
	} else if metadata.UID != 0 {
		ambiguous = append(ambiguous, fmt.Sprintf("%s비-root 소유자 uid=%d (서비스 또는 패키지 요구 확인 필요)", prefix, metadata.UID))
	}
	mode := metadata.Mode.Perm()
	if metadata.Mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		clear = append(clear, prefix+"특수 권한 비트가 설정됨")
	}
	if mode&0o111 != 0 {
		clear = append(clear, fmt.Sprintf("%s실행 비트가 설정됨 mode=%04o", prefix, mode))
	}
	if mode&0o002 != 0 {
		clear = append(clear, fmt.Sprintf("%sother 쓰기 권한이 설정됨 mode=%04o", prefix, mode))
	}
	if mode&0o020 != 0 {
		ambiguous = append(ambiguous, fmt.Sprintf("%sgroup 쓰기 권한 mode=%04o (서비스 또는 패키지 요구 확인 필요)", prefix, mode))
	}
	for _, reason := range acl.clearReasons {
		clear = append(clear, prefix+reason)
	}
	for _, reason := range acl.ambiguousReasons {
		ambiguous = append(ambiguous, prefix+reason)
	}
	return clear, ambiguous
}

func limitedStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return append([]string(nil), values...)
	}
	result := append([]string(nil), values[:limit]...)
	result = append(result, fmt.Sprintf("... %d개 추가", len(values)-limit))
	return result
}

func summarizeStrings(values []string, limit int) string {
	if len(values) == 0 {
		return "해당 항목 없음"
	}
	return strings.Join(limitedStrings(values, limit), "; ")
}

func logFilePermissionError(code string, err error) evaluator.Outcome {
	return evaluator.Outcome{
		Status:       model.StatusError,
		Summary:      "로그 파일의 소유자, 권한 또는 ACL을 수집하거나 해석하지 못했습니다.",
		ErrorCode:    code,
		ErrorMessage: err.Error(),
	}
}
