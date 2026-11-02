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
	"unicode/utf8"

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
	mounts   []homeMount
	byTarget map[string][]homeMount
	cache    map[string]homeMountSelection
}

type homeMountSelection struct {
	kind  homeMountKind
	mount homeMount
	found bool
}

type homeMountKind string

const (
	homeMountLocal     homeMountKind = "local"
	homeMountRemote    homeMountKind = "remote"
	homeMountAmbiguous homeMountKind = "ambiguous"
)

const (
	maximumHomeMountEntries      = 4_096
	maximumHomeMountCacheEntries = 8_192
)

type homeMountInventoryLimitError struct {
	Limit int
}

func (err *homeMountInventoryLimitError) Error() string {
	return fmt.Sprintf("mount inventory exceeds %d entries", err.Limit)
}

func isHomeMountInventoryLimit(err error) bool {
	var limitError *homeMountInventoryLimitError
	return errors.As(err, &limitError)
}

func homeMountInventoryLimitEvidence(err error) model.Evidence {
	var limitError *homeMountInventoryLimitError
	limit := maximumHomeMountEntries
	if errors.As(err, &limitError) {
		limit = limitError.Limit
	}
	return support.FactEvidence("home-mount-inventory-limit", map[string]any{
		"entry_limit":    limit,
		"limit_exceeded": true,
	})
}

type inspectedPath struct {
	Exists       bool
	Unknown      string
	ResolvedPath string
	// TerminalSymlink records that the requested path's final component was a
	// symbolic link. Callers can distinguish a missing target from a path that
	// simply does not exist.
	TerminalSymlink bool
	Metadata        system.FileMetadata
	Evidence        []model.Evidence
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
			if len(mounts) >= maximumHomeMountEntries {
				return &homeMountInventoryLimitError{Limit: maximumHomeMountEntries}
			}
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
		return homeMountTable{}, support.CommandEvidence(spec, result), err
	}
	if len(mounts) == 0 {
		return homeMountTable{}, model.Evidence{}, fmt.Errorf("findmnt returned no mounts")
	}
	sort.Slice(mounts, func(i, j int) bool {
		if len(mounts[i].Target) == len(mounts[j].Target) {
			if mounts[i].Target == mounts[j].Target {
				return mounts[i].FSType < mounts[j].FSType
			}
			return mounts[i].Target < mounts[j].Target
		}
		return len(mounts[i].Target) > len(mounts[j].Target)
	})
	byTarget := make(map[string][]homeMount, len(mounts))
	for _, mount := range mounts {
		byTarget[mount.Target] = append(byTarget[mount.Target], mount)
	}
	return homeMountTable{
		mounts:   mounts,
		byTarget: byTarget,
		cache:    make(map[string]homeMountSelection),
	}, support.CommandEvidence(spec, result), nil
}

func (t homeMountTable) classify(systemPath string) (homeMountKind, homeMount, bool) {
	if validateAbsoluteSystemPath(systemPath) != nil {
		return homeMountAmbiguous, homeMount{}, false
	}
	if selection, exists := t.cache[systemPath]; exists {
		return selection.kind, selection.mount, selection.found
	}
	ancestors := make([]string, 0, systemPathComponentCount(systemPath)+1)
	current := systemPath
	selection := homeMountSelection{}
	for {
		if cached, exists := t.cache[current]; exists {
			selection = cached
			break
		}
		ancestors = append(ancestors, current)
		if current == "/" {
			break
		}
		parent := parentSystemPath(current)
		if parent == current {
			break
		}
		current = parent
	}
	for index := len(ancestors) - 1; index >= 0; index-- {
		current = ancestors[index]
		if exact := t.byTarget[current]; len(exact) > 0 {
			selection = classifyExactHomeMounts(exact)
		}
		t.storeCachedMountSelection(current, selection)
	}
	if !selection.found {
		return homeMountAmbiguous, homeMount{}, false
	}
	return selection.kind, selection.mount, true
}

func (t homeMountTable) storeCachedMountSelection(systemPath string, selection homeMountSelection) {
	if t.cache == nil {
		return
	}
	if len(t.cache) >= maximumHomeMountCacheEntries {
		clear(t.cache)
	}
	t.cache[systemPath] = selection
}

func parentSystemPath(systemPath string) string {
	if systemPath == "/" {
		return "/"
	}
	lastSeparator := strings.LastIndexByte(systemPath, '/')
	if lastSeparator <= 0 {
		return "/"
	}
	return systemPath[:lastSeparator]
}

func classifyExactHomeMounts(mounts []homeMount) homeMountSelection {
	selected := mounts[0]
	selectedKind := classifyHomeMountType(selected.FSType)
	for _, mount := range mounts[1:] {
		kind := classifyHomeMountType(mount.FSType)
		if mount.Target != selected.Target ||
			mount.FSType != selected.FSType ||
			kind != selectedKind {
			return homeMountSelection{
				kind:  homeMountAmbiguous,
				mount: selected,
				found: true,
			}
		}
	}
	return homeMountSelection{kind: selectedKind, mount: selected, found: true}
}

func classifyHomeMountType(filesystemType string) homeMountKind {
	switch {
	case isRemoteFilesystem(filesystemType):
		return homeMountRemote
	case isKnownLocalFilesystem(filesystemType):
		return homeMountLocal
	default:
		return homeMountAmbiguous
	}
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
	if len(value) > maximumAbsoluteSystemPathBytes {
		return fmt.Errorf("path exceeds the Linux absolute pathname limit")
	}
	if systemPathComponentCount(value) > maximumAbsoluteSystemPathComponents {
		return fmt.Errorf("path has too many components")
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

const (
	// Linux accepts at most PATH_MAX-1 pathname bytes in one pathname-based
	// system call. Bounding the component count also bounds prefix snapshots.
	maximumAbsoluteSystemPathBytes      = 4095
	maximumAbsoluteSystemPathComponents = 2047
)

func systemPathComponentCount(value string) int {
	count := 0
	inComponent := false
	for index := 0; index < len(value); index++ {
		if value[index] == '/' {
			inComponent = false
			continue
		}
		if !inComponent {
			count++
			inComponent = true
		}
	}
	return count
}

func fixedChildPath(parent, name string) (string, error) {
	if err := validateAbsoluteSystemPath(parent); err != nil {
		return "", err
	}
	if name == "" || strings.Contains(name, "/") || strings.IndexByte(name, 0) >= 0 {
		return "", fmt.Errorf("invalid fixed child name %q", name)
	}
	return fixedRelativeSystemPath(parent, name)
}

func fixedRelativeSystemPath(parent, relative string) (string, error) {
	if err := validateAbsoluteSystemPath(parent); err != nil {
		return "", err
	}
	if relative == "" ||
		path.IsAbs(relative) ||
		strings.IndexByte(relative, 0) >= 0 ||
		path.Clean(relative) != relative {
		return "", fmt.Errorf("invalid fixed relative path %q", relative)
	}
	for _, component := range strings.Split(relative, "/") {
		if component == "" || component == "." || component == ".." {
			return "", fmt.Errorf("invalid fixed relative path component")
		}
	}
	candidate := path.Join(parent, relative)
	if err := validateAbsoluteSystemPath(candidate); err != nil {
		return "", err
	}
	if !pathContains(parent, candidate) {
		return "", fmt.Errorf("child path escaped its parent")
	}
	return candidate, nil
}

func inspectPathWithoutSymlinks(files system.Reader, systemPath string) (inspectedPath, error) {
	return inspectPathWithoutSymlinksWithPolicy(files, systemPath, nil, nil)
}

func inspectPathWithoutSymlinksWithPolicy(
	files system.Reader,
	systemPath string,
	policy pathInspectionPolicy,
	budget *pathInspectionBudget,
) (inspectedPath, error) {
	if err := validateAbsoluteSystemPath(systemPath); err != nil {
		return inspectedPath{}, err
	}
	prefixes := systemPathPrefixes(systemPath)
	tracker := &pathInspectionTracker{shared: budget}
	evidence := make([]model.Evidence, 0, 3)
	var metadata system.FileMetadata
	for index, prefix := range prefixes {
		if !tracker.consume() {
			return pathInspectionLimitResult(systemPath, systemPath, nil, false, evidence, tracker), nil
		}
		if policy != nil {
			reason, policyEvidence := policy(prefix)
			if reason != "" {
				if strings.TrimSpace(policyEvidence.Source) != "" {
					evidence = append(evidence, policyEvidence)
				}
				evidence = append(evidence, pathResolutionEvidence(systemPath, systemPath, nil, false))
				return inspectedPath{
					Exists:       true,
					Unknown:      reason,
					ResolvedPath: systemPath,
					Evidence:     evidence,
				}, nil
			}
		}
		current, err := files.Lstat(prefix)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				stable, confirmErr := confirmMissingPath(
					files,
					systemPath,
					systemPath,
					nil,
					&evidence,
					tracker,
				)
				if confirmErr != nil {
					if errors.Is(confirmErr, errPathInspectionLimitExceeded) {
						return pathInspectionLimitResult(systemPath, systemPath, nil, false, evidence, tracker), nil
					}
					return inspectedPath{}, confirmErr
				}
				evidence = append(evidence, pathResolutionEvidence(systemPath, systemPath, nil, stable))
				if !stable {
					return inspectedPath{
						Exists:       true,
						Unknown:      "홈 경로가 점검 중 변경되었습니다.",
						ResolvedPath: systemPath,
						Evidence:     evidence,
					}, nil
				}
				return inspectedPath{
					Exists:       false,
					ResolvedPath: systemPath,
					Evidence:     evidence,
				}, nil
			}
			return inspectedPath{}, err
		}
		metadata = current
		if index == len(prefixes)-1 ||
			metadata.FileType == "symlink" ||
			(index < len(prefixes)-1 && metadata.FileType != "directory") {
			evidence = append(evidence, support.FileMetadataEvidence(metadata))
		}
		if metadata.FileType == "symlink" {
			evidence = append(evidence, pathResolutionEvidence(systemPath, systemPath, nil, false))
			return inspectedPath{
				Exists:          true,
				Unknown:         fmt.Sprintf("경로 구성요소 %s가 심볼릭 링크이므로 대상을 추측하지 않습니다.", prefix),
				ResolvedPath:    systemPath,
				TerminalSymlink: index == len(prefixes)-1,
				Metadata:        metadata,
				Evidence:        evidence,
			}, nil
		}
		if index < len(prefixes)-1 && metadata.FileType != "directory" {
			evidence = append(evidence, pathResolutionEvidence(systemPath, systemPath, nil, false))
			return inspectedPath{
				Exists:       true,
				Unknown:      fmt.Sprintf("상위 경로 %s가 디렉터리가 아닙니다.", prefix),
				ResolvedPath: systemPath,
				Metadata:     metadata,
				Evidence:     evidence,
			}, nil
		}
	}
	if !tracker.consume() {
		return pathInspectionLimitResult(systemPath, systemPath, nil, false, evidence, tracker), nil
	}
	resolved, err := files.Stat(systemPath)
	if err != nil {
		if isUserEnvironmentPathUnstable(err) {
			evidence = append(evidence, pathResolutionEvidence(systemPath, systemPath, nil, false))
			return inspectedPath{
				Exists:       true,
				Unknown:      "lstat과 stat 사이에 경로 대상이 변경되었습니다.",
				ResolvedPath: systemPath,
				Metadata:     metadata,
				Evidence:     evidence,
			}, nil
		}
		return inspectedPath{}, err
	}
	if metadata.Device != resolved.Device || metadata.Inode != resolved.Inode || metadata.FileType != resolved.FileType {
		evidence = append(
			evidence,
			support.FileMetadataEvidence(resolved),
			pathResolutionEvidence(systemPath, systemPath, nil, false),
		)
		return inspectedPath{
			Exists:       true,
			Unknown:      "lstat과 stat 사이에 경로 대상이 변경되었습니다.",
			ResolvedPath: systemPath,
			Metadata:     resolved,
			Evidence:     evidence,
		}, nil
	}
	evidence = append(evidence, pathResolutionEvidence(systemPath, systemPath, nil, true))
	return inspectedPath{
		Exists:       true,
		ResolvedPath: systemPath,
		Metadata:     resolved,
		Evidence:     evidence,
	}, nil
}

const (
	maximumInspectedPathSymlinks         = 40
	maximumPathOperationsPerInspection   = 8_192
	maximumUserEnvironmentPathOperations = 262_144
	maximumHomeExistencePathOperations   = 131_072
)

type pathLinkSnapshot struct {
	metadata system.FileMetadata
}

type pathInspectionBudget struct {
	limit     int
	remaining int
	exhausted bool
	reason    string
}

func newPathInspectionBudget(limit int) *pathInspectionBudget {
	if limit < 0 {
		limit = 0
	}
	return &pathInspectionBudget{limit: limit, remaining: limit}
}

func (budget *pathInspectionBudget) consume() bool {
	if budget == nil {
		return true
	}
	if budget.remaining <= 0 {
		budget.exhausted = true
		budget.reason = "shared"
		return false
	}
	budget.remaining--
	return true
}

func (budget *pathInspectionBudget) isExhausted() bool {
	return budget != nil && budget.exhausted
}

type pathInspectionTracker struct {
	shared     *pathInspectionBudget
	operations int
}

func (tracker *pathInspectionTracker) consume() bool {
	if tracker.operations >= maximumPathOperationsPerInspection {
		if tracker.shared != nil {
			tracker.shared.exhausted = true
			tracker.shared.reason = "per_path"
		}
		return false
	}
	if !tracker.shared.consume() {
		return false
	}
	tracker.operations++
	return true
}

type pathInspectionPolicy func(string) (string, model.Evidence)

var errPathInspectionLimitExceeded = errors.New("path inspection work limit exceeded")

func pathInspectionLimitResult(
	systemPath string,
	resolvedPath string,
	links []pathLinkSnapshot,
	terminalSymlink bool,
	evidence []model.Evidence,
	tracker *pathInspectionTracker,
) inspectedPath {
	perPathLimitReached := tracker != nil && tracker.operations >= maximumPathOperationsPerInspection
	perPathOperations := 0
	if tracker != nil {
		perPathOperations = tracker.operations
	}
	sharedLimitReached := tracker != nil &&
		tracker.shared != nil &&
		tracker.shared.reason == "shared"
	evidence = append(
		evidence,
		pathResolutionEvidence(systemPath, resolvedPath, links, false),
		support.FactEvidence("home-path-inspection-limit", map[string]any{
			"requested_path":         systemPath,
			"resolved_path":          resolvedPath,
			"per_path_limit":         maximumPathOperationsPerInspection,
			"per_path_operations":    perPathOperations,
			"per_path_limit_reached": perPathLimitReached,
			"shared_limit_reached":   sharedLimitReached,
		}),
	)
	return inspectedPath{
		Exists:          true,
		Unknown:         "경로 검사 작업량이 안전한 상한을 초과했습니다.",
		ResolvedPath:    resolvedPath,
		TerminalSymlink: terminalSymlink,
		Evidence:        evidence,
	}
}

func localMountPathInspectionPolicy(mounts homeMountTable) pathInspectionPolicy {
	return func(systemPath string) (string, model.Evidence) {
		kind, mount, found := mounts.classify(systemPath)
		facts := map[string]any{
			"path": systemPath,
		}
		if !found {
			facts["classified"] = false
			return "경로 구성요소의 포함 마운트를 확인할 수 없습니다.",
				support.FactEvidence("home-path-mount-boundary", facts)
		}
		facts["classified"] = true
		facts["kind"] = string(kind)
		facts["mount_target"] = mount.Target
		facts["filesystem_type"] = mount.FSType
		if kind != homeMountLocal {
			return fmt.Sprintf(
					"경로 구성요소가 %s 마운트에 있어 안전하게 점검할 수 없습니다(%s:%s).",
					kind,
					mount.Target,
					mount.FSType,
				),
				support.FactEvidence("home-path-mount-boundary", facts)
		}
		return "", model.Evidence{}
	}
}

// inspectPathFollowingSymlinks resolves a system path inside the Reader's rooted
// namespace. It records every symbolic-link identity, limits traversal, and
// revalidates both the chain and final target before returning a verdict.
func inspectPathFollowingSymlinks(files system.Reader, systemPath string) (inspectedPath, error) {
	return inspectPathFollowingSymlinksWithPolicy(files, systemPath, nil, nil)
}

func inspectPathFollowingSymlinksWithPolicy(
	files system.Reader,
	systemPath string,
	policy pathInspectionPolicy,
	budget *pathInspectionBudget,
) (inspectedPath, error) {
	if err := validateAbsoluteSystemPath(systemPath); err != nil {
		return inspectedPath{}, err
	}
	tracker := &pathInspectionTracker{shared: budget}
	resolvedPath := systemPath
	evidence := make([]model.Evidence, 0)
	links := make([]pathLinkSnapshot, 0)
	var finalMetadata system.FileMetadata
	terminalSymlink := false

	for {
		restart := false
		prefixes := systemPathPrefixes(resolvedPath)
		for index, prefix := range prefixes {
			if !tracker.consume() {
				return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
			}
			if policy != nil {
				reason, policyEvidence := policy(prefix)
				if reason != "" {
					if strings.TrimSpace(policyEvidence.Source) != "" {
						evidence = append(evidence, policyEvidence)
					}
					evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, false))
					return inspectedPath{
						Exists:          true,
						Unknown:         reason,
						ResolvedPath:    resolvedPath,
						TerminalSymlink: terminalSymlink,
						Evidence:        evidence,
					}, nil
				}
			}
			current, err := files.Lstat(prefix)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					stable, confirmErr := confirmMissingPath(files, systemPath, resolvedPath, links, &evidence, tracker)
					if confirmErr != nil {
						if errors.Is(confirmErr, errPathInspectionLimitExceeded) {
							return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
						}
						return inspectedPath{}, confirmErr
					}
					evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, stable))
					if !stable {
						return inspectedPath{
							Exists:          true,
							Unknown:         "홈 경로 또는 심볼릭 링크 체인이 점검 중 변경되었습니다.",
							ResolvedPath:    resolvedPath,
							TerminalSymlink: terminalSymlink,
							Evidence:        evidence,
						}, nil
					}
					return inspectedPath{
						Exists:          false,
						ResolvedPath:    resolvedPath,
						TerminalSymlink: terminalSymlink,
						Evidence:        evidence,
					}, nil
				}
				return inspectedPath{}, err
			}
			if current.FileType == "symlink" ||
				index == len(prefixes)-1 ||
				(index < len(prefixes)-1 && current.FileType != "directory") {
				evidence = append(evidence, support.FileMetadataEvidence(current))
			}
			if current.FileType == "symlink" {
				if strings.TrimPrefix(resolvedPath, prefix) == "" {
					terminalSymlink = true
				}
				if !safeConfiguredHomePathText(current.LinkTarget) {
					return inspectedPath{
						Exists:          true,
						Unknown:         fmt.Sprintf("심볼릭 링크 %s의 대상에 안전하게 처리할 수 없는 문자가 포함되어 있습니다.", prefix),
						ResolvedPath:    resolvedPath,
						TerminalSymlink: terminalSymlink,
						Evidence: append(evidence, support.FactEvidence(
							"home-path-resolution-unsupported-target",
							map[string]any{
								"link_path":          prefix,
								"target_sha256":      pathDigest(current.LinkTarget),
								"target_not_exposed": true,
							},
						)),
					}, nil
				}
				if len(links) >= maximumInspectedPathSymlinks {
					evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, false))
					return inspectedPath{
						Exists:          true,
						Unknown:         fmt.Sprintf("심볼릭 링크 체인이 %d개를 초과하여 대상을 확정할 수 없습니다.", maximumInspectedPathSymlinks),
						ResolvedPath:    resolvedPath,
						TerminalSymlink: terminalSymlink,
						Metadata:        current,
						Evidence:        evidence,
					}, nil
				}
				if strings.TrimSpace(current.LinkTarget) == "" {
					evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, false))
					return inspectedPath{
						Exists:          true,
						Unknown:         fmt.Sprintf("심볼릭 링크 %s의 대상을 확인할 수 없습니다.", prefix),
						ResolvedPath:    resolvedPath,
						TerminalSymlink: terminalSymlink,
						Metadata:        current,
						Evidence:        evidence,
					}, nil
				}
				links = append(links, pathLinkSnapshot{metadata: current})
				next, resolveErr := replaceSystemPathLink(resolvedPath, prefix, current.LinkTarget)
				if resolveErr != nil {
					evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, false))
					return inspectedPath{
						Exists:          true,
						Unknown:         fmt.Sprintf("심볼릭 링크 %s의 대상을 안전하게 해석할 수 없습니다.", prefix),
						ResolvedPath:    resolvedPath,
						TerminalSymlink: terminalSymlink,
						Metadata:        current,
						Evidence:        evidence,
					}, nil
				}
				resolvedPath = next
				restart = true
				break
			}
			if index < len(prefixes)-1 && current.FileType != "directory" {
				stable, revalidateErr := revalidatePathLinks(files, links, &evidence, tracker)
				if revalidateErr != nil {
					if errors.Is(revalidateErr, errPathInspectionLimitExceeded) {
						return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
					}
					return inspectedPath{}, revalidateErr
				}
				if !tracker.consume() {
					return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
				}
				after, afterErr := files.Lstat(prefix)
				if afterErr != nil {
					if errors.Is(afterErr, os.ErrNotExist) {
						stable = false
					} else {
						return inspectedPath{}, afterErr
					}
				} else {
					evidence = append(evidence, support.FileMetadataEvidence(after))
					stable = stable && samePathIdentity(current, after)
				}
				evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, stable))
				if !stable {
					return inspectedPath{
						Exists:          true,
						Unknown:         "홈 경로 또는 심볼릭 링크 체인이 점검 중 변경되었습니다.",
						ResolvedPath:    resolvedPath,
						TerminalSymlink: terminalSymlink,
						Evidence:        evidence,
					}, nil
				}
				return inspectedPath{
					Exists:          true,
					ResolvedPath:    resolvedPath,
					TerminalSymlink: terminalSymlink,
					Metadata:        current,
					Evidence:        evidence,
				}, nil
			}
			finalMetadata = current
		}
		if restart {
			continue
		}
		break
	}

	if !tracker.consume() {
		return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
	}
	firstTarget, err := files.Stat(systemPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, false))
			return inspectedPath{
				Exists:          true,
				Unknown:         "홈 경로 대상이 점검 중 변경되었습니다.",
				ResolvedPath:    resolvedPath,
				TerminalSymlink: terminalSymlink,
				Evidence:        evidence,
			}, nil
		}
		return inspectedPath{}, err
	}
	if !samePathIdentity(finalMetadata, firstTarget) {
		evidence = append(evidence, support.FileMetadataEvidence(firstTarget))
		evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, false))
		return inspectedPath{
			Exists:          true,
			Unknown:         "심볼릭 링크 해석 결과와 홈 경로 대상이 일치하지 않습니다.",
			ResolvedPath:    resolvedPath,
			TerminalSymlink: terminalSymlink,
			Evidence:        evidence,
		}, nil
	}
	stable, err := revalidatePathLinks(files, links, &evidence, tracker)
	if err != nil {
		if errors.Is(err, errPathInspectionLimitExceeded) {
			return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
		}
		return inspectedPath{}, err
	}
	if !tracker.consume() {
		return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
	}
	finalAfter, err := files.Lstat(resolvedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			stable = false
		} else {
			return inspectedPath{}, err
		}
	} else {
		evidence = append(evidence, support.FileMetadataEvidence(finalAfter))
		stable = stable && samePathIdentity(finalMetadata, finalAfter)
	}
	if !tracker.consume() {
		return pathInspectionLimitResult(systemPath, resolvedPath, links, terminalSymlink, evidence, tracker), nil
	}
	secondTarget, err := files.Stat(systemPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			stable = false
		} else {
			return inspectedPath{}, err
		}
	} else {
		evidence = append(evidence, support.FileMetadataEvidence(secondTarget))
		stable = stable && samePathIdentity(firstTarget, secondTarget)
	}
	evidence = append(evidence, pathResolutionEvidence(systemPath, resolvedPath, links, stable))
	if !stable {
		return inspectedPath{
			Exists:          true,
			Unknown:         "홈 경로 또는 심볼릭 링크 체인이 점검 중 변경되었습니다.",
			ResolvedPath:    resolvedPath,
			TerminalSymlink: terminalSymlink,
			Evidence:        evidence,
		}, nil
	}
	return inspectedPath{
		Exists:          true,
		ResolvedPath:    resolvedPath,
		TerminalSymlink: terminalSymlink,
		Metadata:        secondTarget,
		Evidence:        evidence,
	}, nil
}

func replaceSystemPathLink(systemPath, linkPath, target string) (string, error) {
	if !safeConfiguredHomePathText(target) {
		return "", fmt.Errorf("symbolic link target contains an unsafe display or control character")
	}
	remainder := strings.TrimPrefix(systemPath, linkPath)
	if remainder != "" && !strings.HasPrefix(remainder, "/") {
		return "", fmt.Errorf("symbolic link is not a complete path component")
	}
	var base string
	if path.IsAbs(target) {
		base = target
	} else {
		base = path.Join(path.Dir(linkPath), target)
	}
	replaced := path.Join(base, strings.TrimPrefix(remainder, "/"))
	if !path.IsAbs(replaced) {
		replaced = "/" + replaced
	}
	replaced = path.Clean(replaced)
	if err := validateAbsoluteSystemPath(replaced); err != nil {
		return "", err
	}
	return replaced, nil
}

func confirmMissingPath(
	files system.Reader,
	systemPath string,
	resolvedPath string,
	links []pathLinkSnapshot,
	evidence *[]model.Evidence,
	tracker *pathInspectionTracker,
) (bool, error) {
	if !tracker.consume() {
		return false, errPathInspectionLimitExceeded
	}
	if _, err := files.Stat(systemPath); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	stable, err := revalidatePathLinks(files, links, evidence, tracker)
	if err != nil {
		return false, err
	}
	if !tracker.consume() {
		return false, errPathInspectionLimitExceeded
	}
	if _, err := files.Lstat(resolvedPath); err == nil {
		stable = false
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if !tracker.consume() {
		return false, errPathInspectionLimitExceeded
	}
	if _, err := files.Stat(systemPath); err == nil {
		stable = false
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return stable, nil
}

func revalidatePathLinks(
	files system.Reader,
	links []pathLinkSnapshot,
	evidence *[]model.Evidence,
	tracker *pathInspectionTracker,
) (bool, error) {
	stable := true
	for _, snapshot := range links {
		if !tracker.consume() {
			return false, errPathInspectionLimitExceeded
		}
		current, err := files.Lstat(snapshot.metadata.Path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				stable = false
				continue
			}
			return false, err
		}
		*evidence = append(*evidence, support.FileMetadataEvidence(current))
		if !samePathIdentity(snapshot.metadata, current) {
			stable = false
		}
	}
	return stable, nil
}

func samePathIdentity(before, after system.FileMetadata) bool {
	if before.FileType != after.FileType {
		return false
	}
	if before.FileType == "symlink" && before.LinkTarget != after.LinkTarget {
		return false
	}
	hasIdentity := before.Device != 0 || before.Inode != 0 || after.Device != 0 || after.Inode != 0
	if hasIdentity {
		return before.Device == after.Device && before.Inode == after.Inode
	}
	return before.Mode == after.Mode &&
		before.Size == after.Size &&
		before.UID == after.UID &&
		before.GID == after.GID &&
		before.ModTime.Equal(after.ModTime)
}

func samePathSecuritySnapshot(before, after system.FileMetadata) bool {
	return samePathIdentity(before, after) &&
		before.Mode == after.Mode &&
		before.UID == after.UID &&
		before.GID == after.GID
}

func pathResolutionEvidence(
	systemPath string,
	resolvedPath string,
	links []pathLinkSnapshot,
	stable bool,
) model.Evidence {
	chainRecords := make([]string, 0, len(links))
	for _, link := range links {
		chainRecords = append(chainRecords, fmt.Sprintf(
			"%s\x00%s\x00%d\x00%d",
			link.metadata.Path,
			link.metadata.LinkTarget,
			link.metadata.Device,
			link.metadata.Inode,
		))
	}
	return support.FactEvidence("home-path-resolution", map[string]any{
		"requested_path":       systemPath,
		"resolved_path":        resolvedPath,
		"stable":               stable,
		"symlink_count":        len(links),
		"symlink_chain_sha256": bytesDigest([]byte(strings.Join(chainRecords, "\x00\x00"))),
	})
}

func inspectedPathResolutionDigest(inspected inspectedPath) (string, bool) {
	for index := len(inspected.Evidence) - 1; index >= 0; index-- {
		item := inspected.Evidence[index]
		if item.Source != "home-path-resolution" || item.Fact == nil {
			continue
		}
		encoded, err := json.Marshal(item.Fact)
		if err != nil {
			return "", false
		}
		return pathDigest(string(encoded)), true
	}
	return "", false
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
	violations, evidence, _, err := inspectNonOwnerACLSnapshot(ctx, environment, metadata, forbidden, false)
	return violations, evidence, err
}

func inspectNonOwnerACLSnapshot(
	ctx context.Context,
	environment evaluator.Environment,
	metadata system.FileMetadata,
	forbidden os.FileMode,
	followFinalSymlink bool,
) ([]string, model.Evidence, string, error) {
	if metadata.UID < 0 {
		return nil, model.Evidence{}, "", fmt.Errorf("owner UID is unavailable for %s", metadata.Path)
	}
	inspection, err := support.InspectPOSIXACL(
		ctx,
		environment.Files,
		environment.Commands,
		metadata.Path,
		followFinalSymlink,
		false,
		&metadata,
	)
	if err != nil {
		return nil, inspection.Evidence, "", err
	}
	violations, err := nonOwnerACLViolations(inspection.Content, metadata.UID, forbidden)
	if err != nil {
		return nil, model.Evidence{}, "", err
	}
	return violations, inspection.Evidence, pathDigest(inspection.Content), nil
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

const maximumAccountFindingLabelBytes = 512

func accountNames(accounts []support.PasswdEntry) string {
	names := make([]string, 0, len(accounts))
	for _, account := range accounts {
		names = append(names, account.Name)
	}
	sort.Strings(names)
	joined := strings.Join(names, ",")
	if len(joined) <= maximumAccountFindingLabelBytes {
		return joined
	}
	suffix := fmt.Sprintf(
		"… (계정 %d개, sha256=%s)",
		len(names),
		pathSetDigest(names),
	)
	previewLimit := maximumAccountFindingLabelBytes - len(suffix)
	if previewLimit < 0 {
		previewLimit = 0
	}
	return truncateUTF8Bytes(joined, previewLimit) + suffix
}

func truncateUTF8Bytes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	end := limit
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end]
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
			names := strings.Split(finding.Account, ",")
			if len(names) > 1 {
				label = fmt.Sprintf("계정 %d개(%s):%s", len(names), strings.Join(names, ", "), label)
			} else {
				label = finding.Account + ":" + label
			}
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
