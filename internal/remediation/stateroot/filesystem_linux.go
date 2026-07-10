//go:build linux

package stateroot

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

const (
	extFilesystemMagic  uint64 = 0xef53
	xfsFilesystemMagic  uint64 = 0x58465342
	procFilesystemMagic uint64 = 0x9fa0
	sysFilesystemMagic  uint64 = 0x62656572

	maxMountInfoLine      = 1024 * 1024
	maxSysfsAttributeSize = 128
	maxBlockGraphDepth    = 32
	maxBlockGraphNodes    = 256
	maxBlockDeviceSlaves  = 128
)

type mountRecord struct {
	root        string
	mountPoint  string
	fsType      string
	source      string
	deviceMajor uint64
	deviceMinor uint64
}

// validateStateFilesystem accepts only the local, block-backed filesystems
// whose rename and fsync semantics OpenCIIP is prepared to rely on. A denylist
// would make every unknown network, userspace, stacked, or future filesystem
// implicitly trusted, so unknown filesystem types are deliberately rejected.
func validateStateFilesystem(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return invalid(fmt.Sprintf("open %s for filesystem validation: %v", path, err))
	}
	defer syscall.Close(fd)

	var statistics syscall.Statfs_t
	if err := syscall.Fstatfs(fd, &statistics); err != nil {
		return invalid(fmt.Sprintf("inspect filesystem for %s: %v", path, err))
	}
	var opened syscall.Stat_t
	if err := syscall.Fstat(fd, &opened); err != nil {
		return invalid(fmt.Sprintf("inspect opened state directory %s: %v", path, err))
	}
	openedDeviceMajor := linuxDeviceMajor(uint64(opened.Dev))
	openedDeviceMinor := linuxDeviceMinor(uint64(opened.Dev))
	magic := uint64(statistics.Type)
	if !supportedFilesystemMagic(magic) {
		return invalid(fmt.Sprintf("%s is on an unsupported remote, volatile, overlay, or special filesystem (statfs type %#x)", path, magic))
	}

	records, err := readMountInfo()
	if err != nil {
		return invalid(fmt.Sprintf("inspect mount namespace for %s: %v", path, err))
	}
	if err := rejectContainerMountNamespace(records); err != nil {
		return invalid(err.Error())
	}
	record, err := mountForPath(records, path)
	if err != nil {
		return invalid(fmt.Sprintf("resolve mount for %s: %v", path, err))
	}
	expectedMagic, ok := supportedMountTypes[record.fsType]
	if !ok || expectedMagic != magic {
		return invalid(fmt.Sprintf("mount type %q for %s does not match a supported local filesystem", record.fsType, path))
	}
	if record.deviceMajor != openedDeviceMajor || record.deviceMinor != openedDeviceMinor {
		return invalid(fmt.Sprintf("mount identity for %s changed while its filesystem was validated", path))
	}
	if record.root != "/" {
		return invalid(fmt.Sprintf("%s is on a bind, subdirectory, or namespaced mount; remediation state requires a direct filesystem mount", path))
	}
	if duplicateUnderlyingMount(records, record) {
		return invalid(fmt.Sprintf("%s is on a duplicate or bind mount; remediation state requires a unique direct filesystem mount", path))
	}
	if err := validateBlockDeviceSource(record.source, record.deviceMajor, record.deviceMinor); err != nil {
		return invalid(fmt.Sprintf("mount source for %s is not a supported persistent local block device: %v", path, err))
	}
	return nil
}

var supportedMountTypes = map[string]uint64{
	"ext4": extFilesystemMagic,
	"xfs":  xfsFilesystemMagic,
}

func supportedFilesystemMagic(magic uint64) bool {
	return magic == extFilesystemMagic || magic == xfsFilesystemMagic
}

func readMountInfo() ([]mountRecord, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var records []mountRecord
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxMountInfoLine)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if len(fields) < 10 || separator < 6 || separator+3 >= len(fields) {
			return nil, errors.New("malformed /proc/self/mountinfo record")
		}
		root, err := unescapeMountInfoField(fields[3])
		if err != nil {
			return nil, fmt.Errorf("decode mount root: %w", err)
		}
		mountPoint, err := unescapeMountInfoField(fields[4])
		if err != nil {
			return nil, fmt.Errorf("decode mount point: %w", err)
		}
		source, err := unescapeMountInfoField(fields[separator+2])
		if err != nil {
			return nil, fmt.Errorf("decode mount source: %w", err)
		}
		if !filepath.IsAbs(root) || !filepath.IsAbs(mountPoint) {
			return nil, errors.New("mountinfo contains a non-absolute root or mount point")
		}
		deviceMajor, deviceMinor, err := parseDeviceNumber(fields[2])
		if err != nil {
			return nil, fmt.Errorf("decode mount device: %w", err)
		}
		records = append(records, mountRecord{
			root:        filepath.Clean(root),
			mountPoint:  filepath.Clean(mountPoint),
			fsType:      fields[separator+1],
			source:      source,
			deviceMajor: deviceMajor,
			deviceMinor: deviceMinor,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("/proc/self/mountinfo is empty")
	}
	return records, nil
}

func mountForPath(records []mountRecord, path string) (mountRecord, error) {
	cleanPath := filepath.Clean(path)
	var selected mountRecord
	selectedLength := -1
	ambiguous := false
	for _, record := range records {
		if !pathWithinMount(cleanPath, record.mountPoint) {
			continue
		}
		length := len(record.mountPoint)
		switch {
		case length > selectedLength:
			selected = record
			selectedLength = length
			ambiguous = false
		case length == selectedLength:
			ambiguous = true
		}
	}
	if selectedLength < 0 {
		return mountRecord{}, errors.New("no covering mount was found")
	}
	if ambiguous {
		return mountRecord{}, errors.New("multiple stacked mounts cover the path")
	}
	return selected, nil
}

func pathWithinMount(path, mountPoint string) bool {
	if mountPoint == string(filepath.Separator) {
		return filepath.IsAbs(path)
	}
	return path == mountPoint || strings.HasPrefix(path, mountPoint+string(filepath.Separator))
}

func duplicateUnderlyingMount(records []mountRecord, selected mountRecord) bool {
	if selected.mountPoint == "/" {
		return false
	}
	for _, record := range records {
		if record.mountPoint == selected.mountPoint {
			continue
		}
		if record.deviceMajor == selected.deviceMajor &&
			record.deviceMinor == selected.deviceMinor &&
			record.root == selected.root &&
			record.fsType == selected.fsType {
			return true
		}
	}
	return false
}

func rejectContainerMountNamespace(records []mountRecord) error {
	if err := validateHostMountNamespace(); err != nil {
		return err
	}
	if err := validateHostRootIdentity(); err != nil {
		return err
	}
	root, err := mountForPath(records, "/")
	if err != nil {
		return fmt.Errorf("cannot establish a host mount namespace: %w", err)
	}
	rootMagic, supported := supportedMountTypes[root.fsType]
	if !supported || !supportedFilesystemMagic(rootMagic) || root.root != "/" {
		return fmt.Errorf("container, overlay, chroot, or special root mount %q is not supported for remediation", root.fsType)
	}
	if err := validateBlockDeviceSource(root.source, root.deviceMajor, root.deviceMinor); err != nil {
		return fmt.Errorf("host root mount is not backed by a supported persistent local block device: %w", err)
	}

	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Lstat(marker); err == nil {
			return fmt.Errorf("container marker %s is present; remediation is disabled in containers", marker)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("cannot inspect container marker %s: %w", marker, err)
		}
	}
	if value, err := os.ReadFile("/run/systemd/container"); err == nil {
		if strings.TrimSpace(string(value)) != "" {
			return errors.New("systemd reports a container environment; remediation is disabled in containers")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot inspect /run/systemd/container: %w", err)
	}

	cgroup, err := os.ReadFile("/proc/1/cgroup")
	if err != nil {
		return fmt.Errorf("cannot inspect PID 1 cgroups: %w", err)
	}
	lowerCgroup := strings.ToLower(string(cgroup))
	for _, marker := range []string{"docker", "kubepods", "containerd", "libpod", "lxc", "machine.slice"} {
		if strings.Contains(lowerCgroup, marker) {
			return fmt.Errorf("PID 1 cgroup contains container marker %q; remediation is disabled in containers", marker)
		}
	}
	if err := validateHostPIDNamespace(); err != nil {
		return err
	}
	pidOneName, err := os.ReadFile("/proc/1/comm")
	if err != nil {
		return fmt.Errorf("cannot inspect PID 1 executable name: %w", err)
	}
	if strings.TrimSpace(string(pidOneName)) != "systemd" {
		return fmt.Errorf("PID 1 is %q rather than systemd; container or non-host execution is not supported", strings.TrimSpace(string(pidOneName)))
	}
	return nil
}

func validateHostRootIdentity() error {
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	currentRootFD, err := syscall.Open("/", flags, 0)
	if err != nil {
		return fmt.Errorf("cannot safely open the current root: %w", err)
	}
	defer syscall.Close(currentRootFD)

	procFD, err := syscall.Open("/proc", flags, 0)
	if err != nil {
		return fmt.Errorf("cannot safely open procfs: %w", err)
	}
	defer syscall.Close(procFD)
	var procStatistics syscall.Statfs_t
	if err := syscall.Fstatfs(procFD, &procStatistics); err != nil {
		return fmt.Errorf("cannot inspect procfs: %w", err)
	}
	if uint64(procStatistics.Type) != procFilesystemMagic {
		return errors.New("/proc is not a verified procfs mount")
	}

	pidOneFD, err := syscall.Openat(procFD, "1", flags, 0)
	if err != nil {
		return fmt.Errorf("cannot safely open the PID 1 proc directory: %w", err)
	}
	defer syscall.Close(pidOneFD)
	// procfs root is a kernel magic link. Appending a final real directory
	// component lets O_NOFOLLOW protect the final lookup while still opening
	// the root that PID 1 actually sees.
	pidOneRootFD, err := syscall.Openat(pidOneFD, "root/.", flags, 0)
	if err != nil {
		return fmt.Errorf("cannot safely open PID 1's root: %w", err)
	}
	defer syscall.Close(pidOneRootFD)

	var currentRoot syscall.Stat_t
	if err := syscall.Fstat(currentRootFD, &currentRoot); err != nil {
		return fmt.Errorf("cannot inspect the current root: %w", err)
	}
	var pidOneRoot syscall.Stat_t
	if err := syscall.Fstat(pidOneRootFD, &pidOneRoot); err != nil {
		return fmt.Errorf("cannot inspect PID 1's root: %w", err)
	}
	if currentRoot.Mode&syscall.S_IFMT != syscall.S_IFDIR || pidOneRoot.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return errors.New("the current root or PID 1 root is not a directory")
	}
	if currentRoot.Dev != pidOneRoot.Dev || currentRoot.Ino != pidOneRoot.Ino {
		return errors.New("the current root does not match PID 1's host root; remediation is disabled in chroot environments")
	}
	return nil
}

func validateHostMountNamespace() error {
	currentNamespace, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		return fmt.Errorf("cannot inspect the current mount namespace: %w", err)
	}
	hostNamespace, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		return fmt.Errorf("cannot inspect PID 1 mount namespace: %w", err)
	}
	if currentNamespace == "" || currentNamespace != hostNamespace {
		return errors.New("the process is not in PID 1's host mount namespace; remediation is disabled in isolated namespaces")
	}
	return nil
}

func validateHostPIDNamespace() error {
	status, err := os.ReadFile("/proc/1/status")
	if err != nil {
		return fmt.Errorf("cannot inspect PID 1 namespace: %w", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "NSpid:" {
			if len(fields) != 2 || fields[1] != "1" {
				return errors.New("PID 1 is in a nested PID namespace; remediation is disabled in containers")
			}
			return nil
		}
	}
	return errors.New("PID 1 namespace identity is unavailable")
}

func validateBlockDeviceSource(source string, expectedMajor, expectedMinor uint64) error {
	if !filepath.IsAbs(source) || !pathWithinMount(filepath.Clean(source), "/dev") {
		return fmt.Errorf("mount source %q is not below /dev", source)
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", source, err)
	}
	resolved = filepath.Clean(resolved)
	if !pathWithinMount(resolved, "/dev") {
		return fmt.Errorf("mount source %s resolves outside /dev", source)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", resolved, err)
	}
	if info.Mode()&os.ModeDevice == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("%s is not a block device", resolved)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("device identity for %s is unavailable", resolved)
	}
	major := linuxDeviceMajor(uint64(stat.Rdev))
	minor := linuxDeviceMinor(uint64(stat.Rdev))
	if major != expectedMajor || minor != expectedMinor {
		return fmt.Errorf("%s device identity %d:%d does not match mount identity %d:%d", resolved, major, minor, expectedMajor, expectedMinor)
	}
	if err := validatePersistentBlockGraph(blockDeviceIdentity{major: major, minor: minor}); err != nil {
		return fmt.Errorf("validate backing devices for %s: %w", resolved, err)
	}
	return nil
}

type blockDeviceIdentity struct {
	major uint64
	minor uint64
}

func (identity blockDeviceIdentity) key() string {
	return fmt.Sprintf("%d:%d", identity.major, identity.minor)
}

type blockVisitState uint8

const (
	blockVisitActive blockVisitState = iota + 1
	blockVisitComplete
)

type blockDeviceNode struct {
	identity blockDeviceIdentity
	path     string
	name     string
	stat     syscall.Stat_t
	fd       int
	slaves   []blockDeviceIdentity
}

type blockGraphValidator struct {
	devicesRoot string
	states      map[string]blockVisitState
	nodes       int
}

func validatePersistentBlockGraph(identity blockDeviceIdentity) error {
	devicesRoot, err := validateSysfsRoots()
	if err != nil {
		return err
	}
	validator := &blockGraphValidator{
		devicesRoot: devicesRoot,
		states:      make(map[string]blockVisitState),
	}
	return validator.validate(identity, 0)
}

func validateSysfsRoots() (string, error) {
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	for _, path := range []string{"/sys", "/sys/dev", "/sys/dev/block", "/sys/devices"} {
		fd, err := syscall.Open(path, flags, 0)
		if err != nil {
			return "", fmt.Errorf("safely open sysfs directory %s: %w", path, err)
		}
		var stat syscall.Stat_t
		statErr := syscall.Fstat(fd, &stat)
		if statErr == nil && stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			statErr = fmt.Errorf("not a directory")
		}
		if path == "/sys" && statErr == nil {
			var statistics syscall.Statfs_t
			if err := syscall.Fstatfs(fd, &statistics); err != nil {
				statErr = err
			} else if uint64(statistics.Type) != sysFilesystemMagic {
				statErr = fmt.Errorf("filesystem magic %#x is not sysfs", uint64(statistics.Type))
			}
		}
		closeErr := syscall.Close(fd)
		if statErr != nil {
			return "", fmt.Errorf("inspect sysfs directory %s: %w", path, statErr)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close sysfs directory %s: %w", path, closeErr)
		}
	}
	resolved, err := filepath.EvalSymlinks("/sys/devices")
	if err != nil {
		return "", fmt.Errorf("resolve /sys/devices: %w", err)
	}
	resolved = filepath.Clean(resolved)
	if resolved != "/sys/devices" {
		return "", fmt.Errorf("/sys/devices resolves outside its canonical location: %s", resolved)
	}
	return resolved, nil
}

func (validator *blockGraphValidator) validate(identity blockDeviceIdentity, depth int) error {
	if depth > maxBlockGraphDepth {
		return fmt.Errorf("block-device graph exceeds depth %d at %s", maxBlockGraphDepth, identity.key())
	}
	key := identity.key()
	switch validator.states[key] {
	case blockVisitActive:
		return fmt.Errorf("block-device graph contains a cycle at %s", key)
	case blockVisitComplete:
		return nil
	}
	if validator.nodes >= maxBlockGraphNodes {
		return fmt.Errorf("block-device graph exceeds %d nodes", maxBlockGraphNodes)
	}
	validator.nodes++
	validator.states[key] = blockVisitActive

	node, err := validator.openNode(identity)
	if err != nil {
		return err
	}
	defer syscall.Close(node.fd)

	if rejectedBlockDeviceName(node.name) {
		return fmt.Errorf("block device %s (%s) is volatile or remote", key, node.name)
	}
	if obviousRemoteBlockPath(node.path) {
		return fmt.Errorf("block device %s uses an obvious remote transport: %s", key, node.path)
	}

	stacked := isDeviceMapperName(node.name) || isMDName(node.name)
	if stacked {
		if len(node.slaves) == 0 {
			return fmt.Errorf("stacked block device %s (%s) has no backing slaves", key, node.name)
		}
		for _, slave := range node.slaves {
			if err := validator.validate(slave, depth+1); err != nil {
				return fmt.Errorf("backing device %s of %s: %w", slave.key(), key, err)
			}
		}
	} else {
		if len(node.slaves) != 0 {
			return fmt.Errorf("unknown stacked block device %s (%s) has backing slaves", key, node.name)
		}
		if pathWithinMount(node.path, filepath.Join(validator.devicesRoot, "virtual")) {
			return fmt.Errorf("unknown virtual block-device leaf %s (%s) is not persistent", key, node.name)
		}
		if !allowedPersistentBlockLeaf(node.name) {
			return fmt.Errorf("block-device leaf %s (%s) is not in the persistent local allowlist", key, node.name)
		}
	}

	currentSlaves, err := validator.readSlaveIdentities(node.fd, node.path)
	if err != nil {
		return fmt.Errorf("reinspect backing devices for %s: %w", key, err)
	}
	if !sameBlockDeviceIdentities(node.slaves, currentSlaves) {
		return fmt.Errorf("backing-device graph for %s changed while it was validated", key)
	}
	if err := validator.revalidateNode(node); err != nil {
		return err
	}
	validator.states[key] = blockVisitComplete
	return nil
}

func (validator *blockGraphValidator) openNode(identity blockDeviceIdentity) (*blockDeviceNode, error) {
	resolved, fd, stat, err := validator.openBlockDeviceDirectory(identity)
	if err != nil {
		return nil, err
	}
	slaves, err := validator.readSlaveIdentities(fd, resolved)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("read backing devices for %s: %w", identity.key(), err)
	}
	return &blockDeviceNode{
		identity: identity,
		path:     resolved,
		name:     filepath.Base(resolved),
		stat:     stat,
		fd:       fd,
		slaves:   slaves,
	}, nil
}

func (validator *blockGraphValidator) openBlockDeviceDirectory(identity blockDeviceIdentity) (string, int, syscall.Stat_t, error) {
	linkPath := filepath.Join("/sys/dev/block", identity.key())
	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		return "", -1, syscall.Stat_t{}, fmt.Errorf("resolve sysfs block device %s: %w", identity.key(), err)
	}
	resolved = filepath.Clean(resolved)
	if !pathWithinMount(resolved, validator.devicesRoot) {
		return "", -1, syscall.Stat_t{}, fmt.Errorf("sysfs block device %s resolves outside /sys/devices", identity.key())
	}
	fd, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", -1, syscall.Stat_t{}, fmt.Errorf("safely open sysfs block device %s: %w", identity.key(), err)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		syscall.Close(fd)
		return "", -1, syscall.Stat_t{}, fmt.Errorf("inspect sysfs block device %s: %w", identity.key(), err)
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		syscall.Close(fd)
		return "", -1, syscall.Stat_t{}, fmt.Errorf("sysfs block device %s is not a directory", identity.key())
	}
	actual, err := readStableBlockIdentity(fd)
	if err != nil {
		syscall.Close(fd)
		return "", -1, syscall.Stat_t{}, fmt.Errorf("read sysfs identity for %s: %w", identity.key(), err)
	}
	if actual != identity {
		syscall.Close(fd)
		return "", -1, syscall.Stat_t{}, fmt.Errorf("sysfs identity %s does not match expected block device %s", actual.key(), identity.key())
	}
	return resolved, fd, stat, nil
}

func (validator *blockGraphValidator) revalidateNode(node *blockDeviceNode) error {
	resolved, fd, stat, err := validator.openBlockDeviceDirectory(node.identity)
	if err != nil {
		return fmt.Errorf("revalidate block device %s: %w", node.identity.key(), err)
	}
	defer syscall.Close(fd)
	if resolved != node.path || stat.Dev != node.stat.Dev || stat.Ino != node.stat.Ino || stat.Mode != node.stat.Mode {
		return fmt.Errorf("sysfs block device %s changed while its backing graph was validated", node.identity.key())
	}
	return nil
}

func (validator *blockGraphValidator) readSlaveIdentities(deviceFD int, devicePath string) ([]blockDeviceIdentity, error) {
	flags := syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	slavesFD, err := syscall.Openat(deviceFD, "slaves", flags, 0)
	if err != nil {
		// Physical partitions do not expose a slaves directory on every
		// supported Rocky kernel. They are still accepted only after the caller
		// proves that the node is a non-virtual allowlisted leaf; dm and MD nodes
		// with this result are rejected for having no backing devices.
		if errors.Is(err, syscall.ENOENT) {
			return []blockDeviceIdentity{}, nil
		}
		return nil, fmt.Errorf("safely open slaves directory: %w", err)
	}
	file := os.NewFile(uintptr(slavesFD), filepath.Join(devicePath, "slaves"))
	if file == nil {
		syscall.Close(slavesFD)
		return nil, errors.New("create slaves directory handle")
	}
	entries, readErr := file.ReadDir(maxBlockDeviceSlaves + 1)
	closeErr := file.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > maxBlockDeviceSlaves {
		return nil, fmt.Errorf("slaves directory exceeds %d entries", maxBlockDeviceSlaves)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	identities := make([]blockDeviceIdentity, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.IndexByte(name, 0) >= 0 {
			return nil, fmt.Errorf("invalid sysfs slave name %q", name)
		}
		linkPath := filepath.Join(devicePath, "slaves", name)
		info, err := os.Lstat(linkPath)
		if err != nil {
			return nil, fmt.Errorf("inspect sysfs slave %s: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return nil, fmt.Errorf("sysfs slave %s is not a symbolic link", name)
		}
		resolved, err := filepath.EvalSymlinks(linkPath)
		if err != nil {
			return nil, fmt.Errorf("resolve sysfs slave %s: %w", name, err)
		}
		resolved = filepath.Clean(resolved)
		if !pathWithinMount(resolved, validator.devicesRoot) {
			return nil, fmt.Errorf("sysfs slave %s resolves outside /sys/devices", name)
		}
		targetFD, err := syscall.Open(resolved, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, fmt.Errorf("safely open sysfs slave %s: %w", name, err)
		}
		identity, identityErr := readStableBlockIdentity(targetFD)
		closeErr := syscall.Close(targetFD)
		if identityErr != nil {
			return nil, fmt.Errorf("read identity for sysfs slave %s: %w", name, identityErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close sysfs slave %s: %w", name, closeErr)
		}
		if _, duplicate := seen[identity.key()]; duplicate {
			return nil, fmt.Errorf("duplicate sysfs slave identity %s", identity.key())
		}
		seen[identity.key()] = struct{}{}
		identities = append(identities, identity)
	}
	sort.Slice(identities, func(i, j int) bool {
		if identities[i].major == identities[j].major {
			return identities[i].minor < identities[j].minor
		}
		return identities[i].major < identities[j].major
	})
	return identities, nil
}

func readStableBlockIdentity(directoryFD int) (blockDeviceIdentity, error) {
	data, err := readStableSysfsAttribute(directoryFD, "dev", maxSysfsAttributeSize)
	if err != nil {
		return blockDeviceIdentity{}, err
	}
	major, minor, err := parseDeviceNumber(strings.TrimSpace(string(data)))
	if err != nil {
		return blockDeviceIdentity{}, err
	}
	return blockDeviceIdentity{major: major, minor: minor}, nil
}

func readStableSysfsAttribute(directoryFD int, name string, maximum int64) ([]byte, error) {
	first, firstStat, err := readSysfsAttributeOnce(directoryFD, name, maximum)
	if err != nil {
		return nil, err
	}
	second, secondStat, err := readSysfsAttributeOnce(directoryFD, name, maximum)
	if err != nil {
		return nil, err
	}
	if firstStat.Dev != secondStat.Dev || firstStat.Ino != secondStat.Ino || firstStat.Mode != secondStat.Mode || firstStat.Nlink != secondStat.Nlink || !bytes.Equal(first, second) {
		return nil, fmt.Errorf("sysfs attribute %s changed while it was read", name)
	}
	return first, nil
}

func readSysfsAttributeOnce(directoryFD int, name string, maximum int64) ([]byte, syscall.Stat_t, error) {
	if name == "" || filepath.Base(name) != name || strings.IndexByte(name, 0) >= 0 || maximum <= 0 {
		return nil, syscall.Stat_t{}, errors.New("invalid sysfs attribute request")
	}
	fd, err := syscall.Openat(directoryFD, name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		syscall.Close(fd)
		return nil, syscall.Stat_t{}, errors.New("create sysfs attribute handle")
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, syscall.Stat_t{}, err
	}
	if stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		file.Close()
		return nil, syscall.Stat_t{}, errors.New("sysfs attribute is not a regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, syscall.Stat_t{}, readErr
	}
	if closeErr != nil {
		return nil, syscall.Stat_t{}, closeErr
	}
	if int64(len(data)) > maximum {
		return nil, syscall.Stat_t{}, fmt.Errorf("sysfs attribute exceeds %d bytes", maximum)
	}
	return data, stat, nil
}

func sameBlockDeviceIdentities(left, right []blockDeviceIdentity) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func rejectedBlockDeviceName(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"loop", "zram", "ram", "nbd", "rbd", "drbd", "aoe", "etherd"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func obviousRemoteBlockPath(path string) bool {
	components := strings.Split(strings.ToLower(filepath.ToSlash(filepath.Clean(path))), "/")
	for _, component := range components {
		switch {
		case component == "iscsi" || strings.HasPrefix(component, "iscsi_"),
			strings.HasPrefix(component, "rport-"),
			strings.HasPrefix(component, "fc_remote"),
			strings.Contains(component, "nvme-fabrics"),
			component == "infiniband",
			strings.HasPrefix(component, "aoe"),
			strings.HasPrefix(component, "etherd"),
			isNumericSuffix(component, "session"):
			return true
		}
	}
	return false
}

func isDeviceMapperName(name string) bool {
	return isNumericSuffix(strings.ToLower(name), "dm-")
}

func isMDName(name string) bool {
	return isNumericSuffix(strings.ToLower(name), "md")
}

func isNumericSuffix(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func allowedPersistentBlockLeaf(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "nvme") ||
		strings.HasPrefix(lower, "sd") ||
		strings.HasPrefix(lower, "vd") ||
		strings.HasPrefix(lower, "xvd") ||
		strings.HasPrefix(lower, "mmcblk")
}

func linuxDeviceMajor(device uint64) uint64 {
	return (device>>8)&0xfff | (device>>32)&0xfffff000
}

func linuxDeviceMinor(device uint64) uint64 {
	return device&0xff | (device>>12)&0xffffff00
}

func parseDeviceNumber(value string) (uint64, uint64, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, 0, fmt.Errorf("invalid major:minor value %q", value)
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid device major %q", parts[0])
	}
	minor, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid device minor %q", parts[1])
	}
	return major, minor, nil
}

func unescapeMountInfoField(value string) (string, error) {
	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])
			continue
		}
		if index+3 >= len(value) {
			return "", errors.New("truncated mountinfo escape")
		}
		digits := value[index+1 : index+4]
		decoded, err := strconv.ParseUint(digits, 8, 8)
		if err != nil {
			return "", fmt.Errorf("invalid mountinfo escape \\%s", digits)
		}
		result.WriteByte(byte(decoded))
		index += 3
	}
	return result.String(), nil
}
