package filecheck

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	filesystemSearchTimeout = 5 * time.Minute
	filesystemSearchOutput  = 8 << 20
	maxDetailedFileFindings = 4096
	maxEvidenceFileFindings = 256
)

type filesystemSnapshotOutput struct {
	Filesystems []filesystemSnapshotEntry `json:"filesystems"`
}

type filesystemSnapshotEntry struct {
	Target   string                    `json:"target"`
	Source   string                    `json:"source"`
	FSType   string                    `json:"fstype"`
	Options  string                    `json:"options"`
	Children []filesystemSnapshotEntry `json:"children"`
}

type scanMount struct {
	Target   string
	Source   string
	FSType   string
	Options  string
	ReadOnly bool
	NoSUID   bool
	Device   uint64
}

type filesystemSnapshot struct {
	All              []scanMount
	Eligible         []scanMount
	ExcludedCounts   map[string]int
	UnsupportedCount int
	Digest           string
	Evidence         model.Evidence
}

type namespaceBoundary struct {
	Known    bool
	HostWide bool
	Evidence model.Evidence
}

type pathSearchResult struct {
	Paths      []string
	Incomplete bool
	Evidence   model.Evidence
}

func collectFilesystemSnapshot(ctx context.Context, environment evaluator.Environment) (filesystemSnapshot, error) {
	spec := executor.Spec{
		Name:      "findmnt",
		Arguments: []string{"--json", "--list", "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"},
		Timeout:   20 * time.Second,
		MaxOutput: 4 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return filesystemSnapshot{}, fmt.Errorf("run findmnt: %w", err)
	}
	commandEvidence := privateCommandSummary("filesystem-mount-snapshot-command", spec, result)
	if result.ExitCode != 0 || result.Truncated || len(result.Stderr) > 0 {
		return filesystemSnapshot{}, fmt.Errorf("findmnt exit=%d truncated=%t diagnostics=%t", result.ExitCode, result.Truncated, len(result.Stderr) > 0)
	}
	var output filesystemSnapshotOutput
	if err := json.Unmarshal(result.Stdout, &output); err != nil {
		return filesystemSnapshot{}, fmt.Errorf("parse findmnt JSON: %w", err)
	}

	all := make([]scanMount, 0, len(output.Filesystems))
	var flatten func([]filesystemSnapshotEntry) error
	flatten = func(entries []filesystemSnapshotEntry) error {
		for _, entry := range entries {
			if err := validateAbsoluteSystemPath(entry.Target); err != nil {
				return fmt.Errorf("invalid mount target sha256=%s", pathDigest(entry.Target))
			}
			filesystemType := strings.ToLower(strings.TrimSpace(entry.FSType))
			if filesystemType == "" {
				return fmt.Errorf("mount %s has no filesystem type", pathDigest(entry.Target))
			}
			options, readOnly, err := canonicalMountOptions(entry.Options)
			if err != nil {
				return fmt.Errorf("mount %s options: %w", pathDigest(entry.Target), err)
			}
			all = append(all, scanMount{
				Target:   entry.Target,
				Source:   entry.Source,
				FSType:   filesystemType,
				Options:  options,
				ReadOnly: readOnly,
				NoSUID:   mountOptionPresent(options, "nosuid"),
			})
			if err := flatten(entry.Children); err != nil {
				return err
			}
		}
		return nil
	}
	if err := flatten(output.Filesystems); err != nil {
		return filesystemSnapshot{}, err
	}
	if len(all) == 0 {
		return filesystemSnapshot{}, fmt.Errorf("findmnt returned no mounts")
	}
	sort.Slice(all, func(i, j int) bool {
		left := mountFingerprint(all[i])
		right := mountFingerprint(all[j])
		return left < right
	})

	eligible := make([]scanMount, 0)
	excluded := make(map[string]int)
	unsupported := 0
	targetCounts := make(map[string]int)
	for index := range all {
		mount := all[index]
		targetCounts[mount.Target]++
		switch classifyScanFilesystem(mount.FSType) {
		case "persistent-posix":
			metadata, statErr := environment.Files.Stat(mount.Target)
			if statErr != nil {
				return filesystemSnapshot{}, privatePathError("stat_mount", mount.Target, statErr)
			}
			if metadata.Device == 0 {
				unsupported++
				continue
			}
			all[index].Device = metadata.Device
			eligible = append(eligible, all[index])
		case "remote", "transient":
			excluded[classifyScanFilesystem(mount.FSType)]++
		default:
			unsupported++
		}
	}
	for _, count := range targetCounts {
		if count > 1 {
			unsupported += count
		}
	}

	digest := mountSnapshotDigest(all)
	evidence := support.FactEvidence("filesystem-mount-snapshot", map[string]any{
		"command":                  commandEvidence.Fact,
		"eligible_count":           len(eligible),
		"eligible_mounts":          mountEvidenceFacts(eligible, 128),
		"excluded_counts":          excluded,
		"snapshot_sha256":          digest,
		"total_mount_count":        len(all),
		"unsupported_or_ambiguous": unsupported,
	})
	return filesystemSnapshot{
		All:              all,
		Eligible:         eligible,
		ExcludedCounts:   excluded,
		UnsupportedCount: unsupported,
		Digest:           digest,
		Evidence:         evidence,
	}, nil
}

func canonicalMountOptions(value string) (string, bool, error) {
	items := strings.Split(strings.TrimSpace(value), ",")
	seen := make(map[string]struct{}, len(items))
	canonical := make([]string, 0, len(items))
	readOnly := false
	readWrite := false
	for _, raw := range items {
		option := strings.TrimSpace(raw)
		if option == "" || strings.ContainsAny(option, "\x00\r\n") {
			return "", false, fmt.Errorf("invalid option token")
		}
		if _, exists := seen[option]; exists {
			continue
		}
		seen[option] = struct{}{}
		canonical = append(canonical, option)
		if option == "ro" {
			readOnly = true
		}
		if option == "rw" {
			readWrite = true
		}
	}
	if readOnly && readWrite {
		return "", false, fmt.Errorf("both ro and rw are present")
	}
	sort.Strings(canonical)
	return strings.Join(canonical, ","), readOnly, nil
}

func classifyScanFilesystem(filesystemType string) string {
	switch filesystemType {
	case "bcachefs", "btrfs", "ext2", "ext3", "ext4", "f2fs", "jfs", "nilfs2", "reiserfs", "xfs", "zfs":
		return "persistent-posix"
	case "9p", "afs", "beegfs", "ceph", "cifs", "coda", "davfs", "gfs", "gfs2", "glusterfs", "gpfs", "lustre", "ncpfs", "nfs", "nfs4", "ocfs2", "panfs", "smb3", "virtiofs", "vboxsf", "vmhgfs":
		return "remote"
	case "autofs", "aufs", "binfmt_misc", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs", "efivarfs", "fusectl", "hugetlbfs", "mqueue", "nsfs", "overlay", "proc", "pstore", "ramfs", "rpc_pipefs", "securityfs", "selinuxfs", "squashfs", "sysfs", "tmpfs", "tracefs":
		return "transient"
	default:
		if strings.HasPrefix(filesystemType, "fuse.") {
			return "remote"
		}
		return "unsupported"
	}
}

func mountOptionPresent(options, expected string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == expected {
			return true
		}
	}
	return false
}

func inspectMountNamespace(files system.Reader) (namespaceBoundary, error) {
	const (
		selfPath = "/proc/self/ns/mnt"
		initPath = "/proc/1/ns/mnt"
	)
	self, selfErr := files.Lstat(selfPath)
	init, initErr := files.Lstat(initPath)
	if selfErr != nil || initErr != nil {
		if (selfErr != nil && !errors.Is(selfErr, os.ErrNotExist)) || (initErr != nil && !errors.Is(initErr, os.ErrNotExist)) {
			return namespaceBoundary{}, fmt.Errorf("inspect mount namespace: self=%v init=%v", selfErr, initErr)
		}
		return namespaceBoundary{
			Known: false,
			Evidence: support.FactEvidence("mount-namespace-boundary", map[string]any{
				"init_exists": initErr == nil,
				"self_exists": selfErr == nil,
			}),
		}, nil
	}
	known := self.FileType == "symlink" && init.FileType == "symlink" && self.LinkTarget != "" && init.LinkTarget != ""
	hostWide := known && self.LinkTarget == init.LinkTarget
	return namespaceBoundary{
		Known:    known,
		HostWide: hostWide,
		Evidence: support.FactEvidence("mount-namespace-boundary", map[string]any{
			"host_namespace_visible": hostWide,
			"init_namespace_sha256":  pathDigest(init.LinkTarget),
			"namespace_known":        known,
			"self_namespace_sha256":  pathDigest(self.LinkTarget),
		}),
	}, nil
}

func runPathSearch(ctx context.Context, environment evaluator.Environment, root string, expression ...string) (pathSearchResult, error) {
	if err := validateAbsoluteSystemPath(root); err != nil {
		return pathSearchResult{}, fmt.Errorf("invalid search root sha256=%s", pathDigest(root))
	}
	arguments := make([]string, 0, len(expression)+3)
	arguments = append(arguments, root, "-xdev")
	arguments = append(arguments, expression...)
	arguments = append(arguments, "-print0")
	spec := executor.Spec{
		Name:      "find",
		Arguments: arguments,
		Timeout:   filesystemSearchTimeout,
		MaxOutput: filesystemSearchOutput,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return pathSearchResult{}, fmt.Errorf("run find: %w", err)
	}
	evidence := privateCommandSummary("filesystem-search-command", spec, result)
	if result.ExitCode != 0 {
		return pathSearchResult{}, fmt.Errorf("find exit=%d", result.ExitCode)
	}
	paths, partial, err := parseNULTerminatedPaths(result.Stdout, result.Truncated)
	if err != nil {
		return pathSearchResult{}, err
	}
	for _, candidate := range paths {
		if err := validateAbsoluteSystemPath(candidate); err != nil {
			return pathSearchResult{}, fmt.Errorf("find returned an unsafe path sha256=%s", pathDigest(candidate))
		}
		if !pathContains(root, candidate) {
			return pathSearchResult{}, fmt.Errorf("find returned a path outside its root")
		}
	}
	paths = uniqueSortedPaths(paths)
	evidence.Fact["candidate_count"] = len(paths)
	evidence.Fact["candidate_set_sha256"] = pathSetDigest(paths)
	incomplete := result.Truncated || partial || len(result.Stderr) > 0
	evidence.Fact["complete"] = !incomplete
	return pathSearchResult{Paths: paths, Incomplete: incomplete, Evidence: evidence}, nil
}

func parseNULTerminatedPaths(data []byte, truncated bool) ([]string, bool, error) {
	if len(data) == 0 {
		return nil, false, nil
	}
	partial := data[len(data)-1] != 0
	if partial && !truncated {
		return nil, false, fmt.Errorf("find output is not NUL terminated")
	}
	parts := strings.Split(string(data), "\x00")
	if partial {
		parts = parts[:len(parts)-1]
	} else if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	paths := make([]string, 0, len(parts))
	for _, item := range parts {
		if item == "" {
			return nil, partial, fmt.Errorf("find output contains an empty path")
		}
		paths = append(paths, item)
	}
	return paths, partial, nil
}

func validateSnapshotStability(before, after filesystemSnapshot) bool {
	return before.Digest == after.Digest
}

func mountForPath(mounts []scanMount, candidate string) (scanMount, bool) {
	var selected *scanMount
	for index := range mounts {
		mount := mounts[index]
		if !pathContains(mount.Target, candidate) {
			continue
		}
		if selected == nil || len(mount.Target) > len(selected.Target) {
			copy := mount
			selected = &copy
			continue
		}
		if len(mount.Target) == len(selected.Target) && mountFingerprint(mount) != mountFingerprint(*selected) {
			return scanMount{}, false
		}
	}
	if selected == nil {
		return scanMount{}, false
	}
	return *selected, true
}

func approvedPathParameter(parameters map[string]any, key, requiredRoot string) (map[string]struct{}, bool, error) {
	values, exists, err := support.StringSliceParameter(parameters, key)
	if err != nil {
		return nil, exists, err
	}
	if !exists {
		return nil, false, nil
	}
	result := make(map[string]struct{}, len(values))
	for index, value := range values {
		if value != strings.TrimSpace(value) {
			return nil, true, fmt.Errorf("parameter %s item %d has surrounding whitespace", key, index)
		}
		if err := validateAbsoluteSystemPath(value); err != nil {
			return nil, true, fmt.Errorf("parameter %s item %d is not a canonical absolute path", key, index)
		}
		if requiredRoot != "" && (value == requiredRoot || !pathContains(requiredRoot, value)) {
			return nil, true, fmt.Errorf("parameter %s item %d is outside %s", key, index, requiredRoot)
		}
		if _, duplicate := result[value]; duplicate {
			return nil, true, fmt.Errorf("parameter %s contains a duplicate path", key)
		}
		result[value] = struct{}{}
	}
	return result, true, nil
}

func privateCommandSummary(source string, spec executor.Spec, result executor.Result) model.Evidence {
	return support.FactEvidence(source, map[string]any{
		"argument_count": len(spec.Arguments),
		"duration_ms":    result.Duration.Milliseconds(),
		"executable":     spec.Name,
		"exit_code":      result.ExitCode,
		"stderr_bytes":   len(result.Stderr),
		"stderr_sha256":  bytesDigest(result.Stderr),
		"stdout_bytes":   len(result.Stdout),
		"stdout_sha256":  bytesDigest(result.Stdout),
		"timed_out":      result.TimedOut,
		"truncated":      result.Truncated,
	})
}

func pathDigest(value string) string {
	return bytesDigest([]byte(value))
}

func pathSetDigest(paths []string) string {
	ordered := uniqueSortedPaths(paths)
	hash := sha256.New()
	for _, item := range ordered {
		_, _ = hash.Write([]byte(item))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func bytesDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func privatePathError(operation, candidate string, err error) error {
	kind := fmt.Sprintf("%T", err)
	switch {
	case errors.Is(err, os.ErrPermission):
		kind = "permission_denied"
	case errors.Is(err, os.ErrNotExist):
		kind = "not_found"
	case errors.Is(err, context.Canceled):
		kind = "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		kind = "deadline_exceeded"
	}
	return fmt.Errorf("%s path_sha256=%s error=%s", operation, pathDigest(candidate), kind)
}

func confirmMetadataStable(files system.Reader, candidate string, before system.FileMetadata) (bool, error) {
	after, err := files.Lstat(candidate)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, privatePathError("lstat", candidate, err)
	}
	return before.Device == after.Device &&
		before.Inode == after.Inode &&
		before.FileType == after.FileType &&
		before.Mode == after.Mode &&
		before.Size == after.Size &&
		before.UID == after.UID &&
		before.GID == after.GID &&
		before.ModTime.Equal(after.ModTime), nil
}

func uniqueSortedPaths(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func mountSnapshotDigest(mounts []scanMount) string {
	values := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		values = append(values, mountFingerprint(mount))
	}
	sort.Strings(values)
	return pathSetDigest(values)
}

func mountFingerprint(mount scanMount) string {
	return strings.Join([]string{mount.Target, mount.Source, mount.FSType, mount.Options, fmt.Sprintf("%d", mount.Device)}, "\x00")
}

func mountEvidenceFacts(mounts []scanMount, limit int) []map[string]any {
	if len(mounts) > limit {
		mounts = mounts[:limit]
	}
	facts := make([]map[string]any, 0, len(mounts))
	for _, mount := range mounts {
		facts = append(facts, map[string]any{
			"device_sha256":   pathDigest(fmt.Sprintf("%d", mount.Device)),
			"filesystem_type": mount.FSType,
			"no_suid":         mount.NoSUID,
			"read_only":       mount.ReadOnly,
			"source_sha256":   pathDigest(mount.Source),
			"target_sha256":   pathDigest(mount.Target),
		})
	}
	return facts
}
