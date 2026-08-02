//go:build linux

package stateroot

import (
	"reflect"
	"strings"
	"testing"
)

func TestSupportedFilesystemMagicUsesAnExplicitAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		magic uint64
		want  bool
	}{
		{name: "ext", magic: extFilesystemMagic, want: true},
		{name: "xfs", magic: xfsFilesystemMagic, want: true},
		{name: "proc", magic: procFilesystemMagic, want: false},
		{name: "sysfs", magic: sysFilesystemMagic, want: false},
		{name: "tmpfs", magic: 0x01021994, want: false},
		{name: "overlay", magic: 0x794c7630, want: false},
		{name: "nfs", magic: 0x6969, want: false},
		{name: "unknown", magic: 0, want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := supportedFilesystemMagic(test.magic); got != test.want {
				t.Fatalf("supportedFilesystemMagic(%#x) = %t, want %t", test.magic, got, test.want)
			}
		})
	}
	if got := supportedMountTypes; !reflect.DeepEqual(got, map[string]uint64{
		"ext4": extFilesystemMagic,
		"xfs":  xfsFilesystemMagic,
	}) {
		t.Fatalf("supportedMountTypes = %#v, want only ext4 and xfs", got)
	}
}

func TestMountForPathSelectsTheLongestUniqueBoundaryMatch(t *testing.T) {
	t.Parallel()

	records := []mountRecord{
		{root: "/", mountPoint: "/", fsType: "ext4", source: "/dev/vda1", deviceMajor: 253, deviceMinor: 1},
		{root: "/", mountPoint: "/var", fsType: "xfs", source: "/dev/vdb1", deviceMajor: 253, deviceMinor: 17},
		{root: "/", mountPoint: "/var/lib", fsType: "ext4", source: "/dev/vdc1", deviceMajor: 253, deviceMinor: 33},
	}
	got, err := mountForPath(records, "/var/lib/openciip")
	if err != nil {
		t.Fatalf("mountForPath() error = %v", err)
	}
	if got.mountPoint != "/var/lib" {
		t.Fatalf("mountForPath() selected %q, want /var/lib", got.mountPoint)
	}

	got, err = mountForPath(records, "/variable")
	if err != nil {
		t.Fatalf("mountForPath(boundary) error = %v", err)
	}
	if got.mountPoint != "/" {
		t.Fatalf("mountForPath(/variable) selected %q, want root boundary", got.mountPoint)
	}
}

func TestMountForPathRejectsMissingAndStackedMounts(t *testing.T) {
	t.Parallel()

	if _, err := mountForPath(nil, "/state"); err == nil {
		t.Fatal("mountForPath() accepted an empty mount table")
	}
	stacked := []mountRecord{
		{root: "/", mountPoint: "/state", fsType: "ext4", source: "/dev/vda1", deviceMajor: 253, deviceMinor: 1},
		{root: "/", mountPoint: "/state", fsType: "xfs", source: "/dev/vdb1", deviceMajor: 253, deviceMinor: 17},
	}
	if _, err := mountForPath(stacked, "/state/openciip"); err == nil {
		t.Fatal("mountForPath() accepted multiple stacked mounts at the same boundary")
	}
}

func TestParseMountInfoAcceptsUnrelatedCanonicalNSFSOpaqueRoots(t *testing.T) {
	t.Parallel()

	for _, namespace := range []string{"cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"} {
		namespace := namespace
		t.Run(namespace, func(t *testing.T) {
			t.Parallel()

			mountPoint := "/run/openciip-test/ns/" + namespace
			mountInfo := "" +
				"413 333 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n" +
				"434 413 0:4 " + namespace + ":[4026532302] " + mountPoint + " rw - nsfs nsfs rw\n"
			records, err := parseMountInfo(strings.NewReader(mountInfo))
			if err != nil {
				t.Fatalf("parseMountInfo() error = %v", err)
			}
			if len(records) != 2 {
				t.Fatalf("parseMountInfo() returned %d records, want 2", len(records))
			}
			if records[1].root != namespace+":[4026532302]" ||
				records[1].mountPoint != mountPoint ||
				records[1].fsType != "nsfs" {
				t.Fatalf("parseMountInfo() nsfs record = %#v", records[1])
			}

			selected, err := mountForPath(records, "/var/lib/openciip")
			if err != nil {
				t.Fatalf("mountForPath(/var/lib/openciip) error = %v", err)
			}
			if selected.mountPoint != "/" || selected.root != "/" {
				t.Fatalf("mountForPath(/var/lib/openciip) selected %#v, want host root", selected)
			}
		})
	}
}

func TestMountForPathRejectsSelectedNSFSOpaqueRoot(t *testing.T) {
	t.Parallel()

	const mountInfo = "" +
		"413 333 8:2 / / rw,relatime - ext4 /dev/sda2 rw\n" +
		"434 413 0:4 net:[4026532302] /var/lib/openciip rw - nsfs nsfs rw\n"
	records, err := parseMountInfo(strings.NewReader(mountInfo))
	if err != nil {
		t.Fatalf("parseMountInfo() error = %v", err)
	}
	for _, path := range []string{"/var/lib/openciip", "/var/lib/openciip/remediation"} {
		if _, err := mountForPath(records, path); err == nil ||
			!strings.Contains(err.Error(), "non-path root") {
			t.Fatalf("mountForPath(%s) error = %v, want fail-closed non-path-root rejection", path, err)
		}
	}
}

func TestParseMountInfoRejectsInvalidOpaqueRootsAndMountPoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		record string
	}{
		{
			name:   "non-path root on block filesystem",
			record: "434 413 8:2 subdirectory /state rw - ext4 /dev/sda2 rw",
		},
		{
			name:   "unknown namespace type",
			record: "434 413 0:4 mystery:[4026532302] /state rw - nsfs nsfs rw",
		},
		{
			name:   "proc pid for children alias",
			record: "434 413 0:4 pid_for_children:[4026532302] /state rw - nsfs nsfs rw",
		},
		{
			name:   "proc time for children alias",
			record: "434 413 0:4 time_for_children:[4026532302] /state rw - nsfs nsfs rw",
		},
		{
			name:   "non-nsfs filesystem type",
			record: "434 413 0:4 mnt:[4026532302] /state rw - ext4 nsfs rw",
		},
		{
			name:   "non-nsfs source",
			record: "434 413 0:4 mnt:[4026532302] /state rw - nsfs none rw",
		},
		{
			name:   "missing namespace inode",
			record: "434 413 0:4 mnt:[] /state rw - nsfs nsfs rw",
		},
		{
			name:   "zero namespace inode",
			record: "434 413 0:4 mnt:[0] /state rw - nsfs nsfs rw",
		},
		{
			name:   "leading zero namespace inode",
			record: "434 413 0:4 mnt:[04026532302] /state rw - nsfs nsfs rw",
		},
		{
			name:   "non-decimal namespace inode",
			record: "434 413 0:4 mnt:[not-an-inode] /state rw - nsfs nsfs rw",
		},
		{
			name:   "signed namespace inode",
			record: "434 413 0:4 mnt:[+4026532302] /state rw - nsfs nsfs rw",
		},
		{
			name:   "trailing namespace data",
			record: "434 413 0:4 mnt:[4026532302]suffix /state rw - nsfs nsfs rw",
		},
		{
			name:   "overflowing namespace inode",
			record: "434 413 0:4 mnt:[18446744073709551616] /state rw - nsfs nsfs rw",
		},
		{
			name:   "non-absolute mount point",
			record: "434 413 0:4 mnt:[4026532302] state rw - nsfs nsfs rw",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseMountInfo(strings.NewReader(test.record + "\n")); err == nil {
				t.Fatalf("parseMountInfo(%q) unexpectedly succeeded", test.record)
			}
		})
	}
}

func TestDuplicateUnderlyingMountDetectsAliases(t *testing.T) {
	t.Parallel()

	selected := mountRecord{
		root:        "/",
		mountPoint:  "/var/lib/openciip",
		fsType:      "ext4",
		source:      "/dev/vda1",
		deviceMajor: 253,
		deviceMinor: 1,
	}
	alias := selected
	alias.mountPoint = "/mnt/alias"
	if !duplicateUnderlyingMount([]mountRecord{selected, alias}, selected) {
		t.Fatal("duplicateUnderlyingMount() missed a second mount of the same root and device")
	}
	otherRoot := alias
	otherRoot.root = "/subdirectory"
	if duplicateUnderlyingMount([]mountRecord{selected, otherRoot}, selected) {
		t.Fatal("duplicateUnderlyingMount() treated a different filesystem root as the same direct mount")
	}
	root := selected
	root.mountPoint = "/"
	if duplicateUnderlyingMount([]mountRecord{root, alias}, root) {
		t.Fatal("duplicateUnderlyingMount() rejected the host root through the non-root duplicate check")
	}
}

func TestBlockDeviceClassificationFailsClosed(t *testing.T) {
	t.Parallel()

	for _, name := range []string{
		"loop0",
		"zram0",
		"ram0",
		"nbd0",
		"rbd0",
		"drbd0",
		"aoe0",
		"etherd0",
	} {
		if !rejectedBlockDeviceName(name) {
			t.Errorf("rejectedBlockDeviceName(%q) = false, want true", name)
		}
	}
	for _, path := range []string{
		"/devices/platform/host0/session1/target",
		"/devices/pci/rport-1/block/sda",
		"/devices/virtual/nvme-fabrics/ctl",
		"/devices/platform/iscsi_host/host3",
	} {
		if !obviousRemoteBlockPath(path) {
			t.Errorf("obviousRemoteBlockPath(%q) = false, want true", path)
		}
	}
	for _, name := range []string{"nvme0n1", "sda", "vda", "xvda", "mmcblk0"} {
		if !allowedPersistentBlockLeaf(name) {
			t.Errorf("allowedPersistentBlockLeaf(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"hda", "dm-0", "md0", "mystery0", ""} {
		if allowedPersistentBlockLeaf(name) {
			t.Errorf("allowedPersistentBlockLeaf(%q) = true, want false", name)
		}
	}
}

func TestMountInfoParsingRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	major, minor, err := parseDeviceNumber("259:17")
	if err != nil || major != 259 || minor != 17 {
		t.Fatalf("parseDeviceNumber(259:17) = (%d, %d, %v)", major, minor, err)
	}
	for _, value := range []string{"", "1", "1:", ":1", "1:2:3", "-1:2", "x:2"} {
		if _, _, err := parseDeviceNumber(value); err == nil {
			t.Errorf("parseDeviceNumber(%q) unexpectedly succeeded", value)
		}
	}

	got, err := unescapeMountInfoField(`/var/lib/OpenCIIP\040state\011root`)
	if err != nil || got != "/var/lib/OpenCIIP state\troot" {
		t.Fatalf("unescapeMountInfoField() = %q, %v", got, err)
	}
	for _, value := range []string{`\`, `\04`, `\xyz`, `path\400`} {
		if _, err := unescapeMountInfoField(value); err == nil {
			t.Errorf("unescapeMountInfoField(%q) unexpectedly succeeded", value)
		}
	}
}
