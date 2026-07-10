package filecheck

import (
	"context"
	"encoding/json"
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
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type homeMount struct {
	Target string
	FSType string
}

type homeMountTable struct {
	mounts []homeMount
}

type homeMountKind string

const (
	homeMountLocal     homeMountKind = "local"
	homeMountRemote    homeMountKind = "remote"
	homeMountAmbiguous homeMountKind = "ambiguous"
)

type inspectedPath struct {
	Exists   bool
	Unknown  string
	Metadata system.FileMetadata
	Evidence []model.Evidence
}

type pathFinding struct {
	Account string
	Path    string
	Reason  string
}

type loginShellPolicy struct {
	Shells    map[string]struct{}
	Available bool
}

func collectHomeMounts(ctx context.Context, environment evaluator.Environment) (homeMountTable, model.Evidence, error) {
	spec := executor.Spec{
		Name:      "findmnt",
		Arguments: []string{"--json", "--list", "--output", "TARGET,FSTYPE"},
		Timeout:   20 * time.Second,
		MaxOutput: 4 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return homeMountTable{}, model.Evidence{}, fmt.Errorf("run findmnt: %w", err)
	}
	if result.ExitCode != 0 || result.Truncated {
		return homeMountTable{}, model.Evidence{}, fmt.Errorf("run findmnt: exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	var output findmntOutput
	if err := json.Unmarshal(result.Stdout, &output); err != nil {
		return homeMountTable{}, model.Evidence{}, fmt.Errorf("parse findmnt: %w", err)
	}
	mounts := make([]homeMount, 0, len(output.Filesystems))
	var visit func([]findmntEntry) error
	visit = func(entries []findmntEntry) error {
		for _, entry := range entries {
			if err := validateAbsoluteSystemPath(entry.Target); err != nil {
				return fmt.Errorf("invalid mount target %q: %w", entry.Target, err)
			}
			mounts = append(mounts, homeMount{Target: entry.Target, FSType: strings.ToLower(strings.TrimSpace(entry.FSType))})
			if err := visit(entry.Children); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(output.Filesystems); err != nil {
		return homeMountTable{}, model.Evidence{}, err
	}
	if len(mounts) == 0 {
		return homeMountTable{}, model.Evidence{}, fmt.Errorf("findmnt returned no mounts")
	}
	sort.Slice(mounts, func(i, j int) bool {
		if len(mounts[i].Target) == len(mounts[j].Target) {
			return mounts[i].Target < mounts[j].Target
		}
		return len(mounts[i].Target) > len(mounts[j].Target)
	})
	return homeMountTable{mounts: mounts}, support.CommandEvidence(spec, result), nil
}

func (t homeMountTable) classify(systemPath string) (homeMountKind, homeMount, bool) {
	var selected *homeMount
	selectedKind := homeMountAmbiguous
	for _, mount := range t.mounts {
		if !pathContains(mount.Target, systemPath) {
			continue
		}
		kind := homeMountLocal
		switch {
		case isRemoteFilesystem(mount.FSType):
			kind = homeMountRemote
		case !isKnownLocalFilesystem(mount.FSType):
			kind = homeMountAmbiguous
		}
		if selected == nil {
			copy := mount
			selected = &copy
			selectedKind = kind
			continue
		}
		if len(mount.Target) < len(selected.Target) {
			break
		}
		if mount.Target != selected.Target || mount.FSType != selected.FSType || kind != selectedKind {
			return homeMountAmbiguous, *selected, true
		}
	}
	if selected == nil {
		return homeMountAmbiguous, homeMount{}, false
	}
	return selectedKind, *selected, true
}

func isRemoteFilesystem(filesystemType string) bool {
	switch filesystemType {
	case "9p", "afs", "beegfs", "ceph", "cifs", "coda", "davfs", "gfs", "gfs2", "glusterfs", "gpfs", "lustre", "ncpfs", "nfs", "nfs4", "ocfs2", "panfs", "smb3", "virtiofs", "vboxsf", "vmhgfs":
		return true
	default:
		return strings.HasPrefix(filesystemType, "fuse.sshfs")
	}
}

func isKnownLocalFilesystem(filesystemType string) bool {
	switch filesystemType {
	case "bcachefs", "btrfs", "devtmpfs", "erofs", "exfat", "ext2", "ext3", "ext4", "f2fs", "jfs", "msdos", "nilfs2", "ntfs", "ntfs3", "ramfs", "reiserfs", "rootfs", "squashfs", "tmpfs", "vfat", "xfs", "zfs":
		return true
	default:
		return false
	}
}

func pathContains(parent, child string) bool {
	if parent == "/" {
		return strings.HasPrefix(child, "/")
	}
	return child == parent || strings.HasPrefix(child, parent+"/")
}

func validateAbsoluteSystemPath(value string) error {
	if value == "" {
		return fmt.Errorf("path is empty")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return fmt.Errorf("path contains a NUL byte")
	}
	if !path.IsAbs(value) {
		return fmt.Errorf("path is not absolute")
	}
	if cleaned := path.Clean(value); cleaned != value {
		return fmt.Errorf("path is not canonical: %q", cleaned)
	}
	return nil
}

func fixedChildPath(parent, name string) (string, error) {
	if err := validateAbsoluteSystemPath(parent); err != nil {
		return "", err
	}
	if name == "" || strings.Contains(name, "/") || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("invalid fixed child name %q", name)
	}
	candidate := path.Join(parent, name)
	if err := validateAbsoluteSystemPath(candidate); err != nil {
		return "", err
	}
	if !pathContains(parent, candidate) {
		return "", fmt.Errorf("child path escaped its parent")
	}
	return candidate, nil
}

func inspectPathWithoutSymlinks(files system.Reader, systemPath string) (inspectedPath, error) {
	if err := validateAbsoluteSystemPath(systemPath); err != nil {
		return inspectedPath{}, err
	}
	prefixes := systemPathPrefixes(systemPath)
	var metadata system.FileMetadata
	for index, prefix := range prefixes {
		current, err := files.Lstat(prefix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return inspectedPath{Exists: false}, nil
			}
			return inspectedPath{}, err
		}
		metadata = current
		evidence := []model.Evidence{support.FileMetadataEvidence(metadata)}
		if metadata.FileType == "symlink" {
			return inspectedPath{
				Exists:   true,
				Unknown:  fmt.Sprintf("경로 구성요소 %s가 심볼릭 링크이므로 대상을 추측하지 않습니다.", prefix),
				Metadata: metadata,
				Evidence: evidence,
			}, nil
		}
		if index < len(prefixes)-1 && metadata.FileType != "directory" {
			return inspectedPath{
				Exists:   true,
				Unknown:  fmt.Sprintf("상위 경로 %s가 디렉터리가 아닙니다.", prefix),
				Metadata: metadata,
				Evidence: evidence,
			}, nil
		}
	}
	evidence := []model.Evidence{support.FileMetadataEvidence(metadata)}
	resolved, err := files.Stat(systemPath)
	if err != nil {
		return inspectedPath{}, err
	}
	if metadata.Device != resolved.Device || metadata.Inode != resolved.Inode || metadata.FileType != resolved.FileType {
		return inspectedPath{
			Exists:   true,
			Unknown:  "lstat과 stat 사이에 경로 대상이 변경되었습니다.",
			Metadata: resolved,
			Evidence: append(evidence, support.FileMetadataEvidence(resolved)),
		}, nil
	}
	return inspectedPath{Exists: true, Metadata: resolved, Evidence: evidence}, nil
}

func systemPathPrefixes(systemPath string) []string {
	if systemPath == "/" {
		return []string{"/"}
	}
	components := strings.Split(strings.TrimPrefix(systemPath, "/"), "/")
	prefixes := make([]string, 0, len(components))
	current := "/"
	for _, component := range components {
		current = path.Join(current, component)
		prefixes = append(prefixes, current)
	}
	return prefixes
}

func inspectNonOwnerACL(ctx context.Context, environment evaluator.Environment, metadata system.FileMetadata, forbidden os.FileMode) ([]string, model.Evidence, error) {
	if metadata.UID < 0 {
		return nil, model.Evidence{}, fmt.Errorf("owner UID is unavailable for %s", metadata.Path)
	}
	spec := executor.Spec{
		Name:      "getfacl",
		Arguments: []string{"-c", "-p", "-n", "--absolute-names", "--", metadata.Path},
		Timeout:   15 * time.Second,
		MaxOutput: 1 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return nil, model.Evidence{}, err
	}
	if result.ExitCode != 0 || result.Truncated {
		return nil, model.Evidence{}, fmt.Errorf("getfacl exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	violations, err := nonOwnerACLViolations(string(result.Stdout), metadata.UID, forbidden)
	if err != nil {
		return nil, model.Evidence{}, err
	}
	return violations, support.CommandEvidence(spec, result), nil
}

func nonOwnerACLViolations(content string, ownerUID int, forbidden os.FileMode) ([]string, error) {
	type aclEntry struct {
		tag       string
		qualifier string
		perms     os.FileMode
		effective *os.FileMode
	}
	entries := make([]aclEntry, 0, 8)
	mask := os.FileMode(0o7)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "default:") {
			continue
		}
		mainPart, comment, _ := strings.Cut(line, "#")
		fields := strings.Split(strings.TrimSpace(mainPart), ":")
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d has an invalid ACL entry", lineNumber+1)
		}
		permissions, err := parseACLPermissions(strings.TrimSpace(fields[2]))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		entry := aclEntry{tag: strings.TrimSpace(fields[0]), qualifier: strings.TrimSpace(fields[1]), perms: permissions}
		if effectiveText := strings.TrimSpace(comment); strings.HasPrefix(effectiveText, "effective:") {
			effective, parseErr := parseACLPermissions(strings.TrimSpace(strings.TrimPrefix(effectiveText, "effective:")))
			if parseErr != nil {
				return nil, fmt.Errorf("line %d effective permissions: %w", lineNumber+1, parseErr)
			}
			entry.effective = &effective
		}
		if entry.tag == "mask" && entry.qualifier == "" {
			mask = entry.perms
		}
		entries = append(entries, entry)
	}
	violations := make([]string, 0)
	for _, entry := range entries {
		actual := entry.perms
		if entry.effective != nil {
			actual = *entry.effective
		} else if (entry.tag == "user" && entry.qualifier != "") || entry.tag == "group" {
			actual &= mask
		}
		switch entry.tag {
		case "user":
			if entry.qualifier == "" {
				continue
			}
			uid, err := strconv.Atoi(entry.qualifier)
			if err != nil || uid < 0 {
				return nil, fmt.Errorf("ACL user qualifier %q is not numeric", entry.qualifier)
			}
			if uid == 0 || uid == ownerUID {
				continue
			}
		case "group", "other":
		case "mask":
			continue
		default:
			return nil, fmt.Errorf("unsupported ACL tag %q", entry.tag)
		}
		if prohibited := actual & forbidden; prohibited != 0 {
			label := entry.tag
			if entry.qualifier != "" {
				label += ":" + entry.qualifier
			}
			violations = append(violations, fmt.Sprintf("ACL %s에 금지된 권한 %03o", label, prohibited))
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func groupAccountsByHome(accounts []support.PasswdEntry) map[string][]support.PasswdEntry {
	grouped := make(map[string][]support.PasswdEntry)
	for _, account := range accounts {
		grouped[account.Home] = append(grouped[account.Home], account)
	}
	for home := range grouped {
		sort.Slice(grouped[home], func(i, j int) bool { return grouped[home][i].Name < grouped[home][j].Name })
	}
	return grouped
}

func sortedHomes(grouped map[string][]support.PasswdEntry) []string {
	homes := make([]string, 0, len(grouped))
	for home := range grouped {
		homes = append(homes, home)
	}
	sort.Strings(homes)
	return homes
}

func accountNames(accounts []support.PasswdEntry) string {
	names := make([]string, 0, len(accounts))
	for _, account := range accounts {
		names = append(names, account.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func collectLoginShellPolicy(ctx context.Context, files system.Reader) (loginShellPolicy, []model.Evidence, error) {
	inspected, err := inspectPathWithoutSymlinks(files, "/etc/shells")
	if err != nil {
		return loginShellPolicy{}, nil, err
	}
	if !inspected.Exists || inspected.Unknown != "" || inspected.Metadata.FileType != "regular" {
		return loginShellPolicy{Shells: map[string]struct{}{}}, inspected.Evidence, nil
	}
	data, metadata, err := files.ReadFile(ctx, "/etc/shells", 1<<20)
	if err != nil {
		return loginShellPolicy{}, nil, err
	}
	if metadata.Device != inspected.Metadata.Device || metadata.Inode != inspected.Metadata.Inode || metadata.FileType != inspected.Metadata.FileType {
		return loginShellPolicy{Shells: map[string]struct{}{}}, inspected.Evidence, nil
	}
	shells := make(map[string]struct{})
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line, _, _ := strings.Cut(raw, "#")
		shell := strings.TrimSpace(line)
		if shell == "" {
			continue
		}
		if err := validateAbsoluteSystemPath(shell); err != nil {
			return loginShellPolicy{}, nil, fmt.Errorf("parse /etc/shells line %d: %w", lineNumber+1, err)
		}
		shells[shell] = struct{}{}
	}
	if len(shells) == 0 {
		return loginShellPolicy{}, nil, fmt.Errorf("/etc/shells contains no shell paths")
	}
	evidence := append([]model.Evidence(nil), inspected.Evidence...)
	evidence = append(evidence, support.FactEvidence("/etc/shells", map[string]any{
		"shell_count":      len(shells),
		"content_redacted": true,
	}))
	return loginShellPolicy{Shells: shells, Available: true}, evidence, nil
}

func loginCapability(account support.PasswdEntry, policy loginShellPolicy) (bool, bool) {
	shell := strings.TrimSpace(account.Shell)
	if shell == "" {
		return true, true
	}
	if err := validateAbsoluteSystemPath(shell); err != nil {
		return false, false
	}
	switch path.Base(path.Clean(shell)) {
	case "false", "nologin":
		return false, true
	}
	if !policy.Available {
		return false, false
	}
	if _, exists := policy.Shells[shell]; exists {
		return true, true
	}
	return false, false
}

func findingEvidence(source string, checked int, violations, unknowns []pathFinding) model.Evidence {
	return support.FactEvidence(source, map[string]any{
		"checked_count":   checked,
		"violations":      findingFacts(violations, 128),
		"violation_count": len(violations),
		"unknowns":        findingFacts(unknowns, 128),
		"unknown_count":   len(unknowns),
	})
}

func findingFacts(findings []pathFinding, limit int) []map[string]any {
	ordered := append([]pathFinding(nil), findings...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		if ordered[i].Account != ordered[j].Account {
			return ordered[i].Account < ordered[j].Account
		}
		return ordered[i].Reason < ordered[j].Reason
	})
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	facts := make([]map[string]any, 0, len(ordered))
	for _, finding := range ordered {
		facts = append(facts, map[string]any{
			"account": finding.Account,
			"path":    finding.Path,
			"reason":  finding.Reason,
		})
	}
	return facts
}

func findingsObserved(violations, unknowns []pathFinding) string {
	parts := make([]string, 0, 2)
	if len(violations) > 0 {
		parts = append(parts, fmt.Sprintf("기준 위반 %d건: %s", len(violations), compactFindings(violations, 6)))
	}
	if len(unknowns) > 0 {
		parts = append(parts, fmt.Sprintf("확정 불가 %d건: %s", len(unknowns), compactFindings(unknowns, 6)))
	}
	return strings.Join(parts, "; ")
}

func compactFindings(findings []pathFinding, limit int) string {
	ordered := append([]pathFinding(nil), findings...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Path != ordered[j].Path {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Account < ordered[j].Account
	})
	values := make([]string, 0, minInt(len(ordered), limit)+1)
	for index, finding := range ordered {
		if index >= limit {
			values = append(values, fmt.Sprintf("외 %d건", len(ordered)-limit))
			break
		}
		label := finding.Path
		if finding.Account != "" {
			label = finding.Account + ":" + label
		}
		values = append(values, label+"("+finding.Reason+")")
	}
	return strings.Join(values, ", ")
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
