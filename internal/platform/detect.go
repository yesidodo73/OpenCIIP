package platform

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

const smallSystemFileLimit int64 = 64 << 10

type Detector struct {
	files system.Reader
}

func NewDetector(files system.Reader) *Detector {
	return &Detector{files: files}
}

func (d *Detector) Detect(ctx context.Context) (model.PlatformInfo, []string, error) {
	warnings := make([]string, 0, 4)
	info := model.PlatformInfo{
		OS:                 runtime.GOOS,
		Architecture:       runtime.GOARCH,
		Privilege:          currentPrivilege(),
		ScanSupport:        model.ScanSupportUnsupported,
		RemediationSupport: model.RemediationSupportUnsupported,
	}
	if hostname, err := os.Hostname(); err == nil {
		info.Hostname = hostname
	} else {
		info.Hostname = "unknown"
		warnings = append(warnings, "호스트 이름을 확인하지 못했습니다.")
	}
	if runtime.GOOS != "linux" {
		return info, warnings, nil
	}

	data, _, err := d.files.ReadFile(ctx, "/etc/os-release", smallSystemFileLimit)
	if err != nil {
		return model.PlatformInfo{}, nil, fmt.Errorf("read /etc/os-release: %w", err)
	}
	values, err := parseOSRelease(data)
	if err != nil {
		return model.PlatformInfo{}, nil, fmt.Errorf("parse /etc/os-release: %w", err)
	}

	info.ID = strings.ToLower(values["ID"])
	info.Name = firstNonEmpty(values["PRETTY_NAME"], values["NAME"], info.ID)
	info.VersionID = values["VERSION_ID"]
	info.VersionID = d.refineCentOSVersionID(ctx, info.ID, info.VersionID)
	info.Family = detectFamily(info.ID, values["ID_LIKE"])

	if kernel, readErr := d.readTrimmed(ctx, "/proc/sys/kernel/osrelease"); readErr == nil {
		info.KernelRelease = kernel
	} else {
		warnings = append(warnings, "커널 릴리스 정보를 읽지 못했습니다.")
	}
	info.InitSystem, warnings = d.detectInit(ctx, warnings)
	info.PackageManager = d.detectPackageManager()

	return info, warnings, nil
}

func (d *Detector) refineCentOSVersionID(ctx context.Context, id, versionID string) string {
	if id != "centos" || !isDecimal(versionID) {
		return versionID
	}
	release, err := d.readTrimmed(ctx, "/etc/centos-release")
	if err != nil {
		return versionID
	}
	refined, ok := parseCentOSLinuxRelease(release)
	if !ok || strings.SplitN(refined, ".", 2)[0] != versionID {
		return versionID
	}
	return refined
}

func parseCentOSLinuxRelease(release string) (string, bool) {
	const prefix = "CentOS Linux release "
	version, ok := strings.CutPrefix(release, prefix)
	if !ok || strings.ContainsAny(version, " \t\r\n") {
		return "", false
	}
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "", false
	}
	for _, part := range parts {
		if !isDecimal(part) {
			return "", false
		}
	}
	return version, true
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func (d *Detector) detectInit(ctx context.Context, warnings []string) (string, []string) {
	if exists, err := d.files.Exists("/run/systemd/system"); err == nil && exists {
		return "systemd", warnings
	} else if err != nil {
		warnings = append(warnings, "init 시스템 경로를 확인하지 못했습니다.")
	}
	process, err := d.readTrimmed(ctx, "/proc/1/comm")
	if err != nil {
		return "unknown", append(warnings, "PID 1 프로세스를 확인하지 못했습니다.")
	}
	switch process {
	case "systemd":
		return "systemd", warnings
	case "init":
		return "sysvinit", warnings
	default:
		if process == "" {
			return "unknown", warnings
		}
		return process, warnings
	}
}

func (d *Detector) detectPackageManager() string {
	candidates := []struct {
		name string
		path string
	}{
		{name: "dnf", path: "/usr/bin/dnf"},
		{name: "rpm", path: "/usr/bin/rpm"},
		{name: "yum", path: "/usr/bin/yum"},
		{name: "apt", path: "/usr/bin/apt-get"},
		{name: "zypper", path: "/usr/bin/zypper"},
		{name: "apk", path: "/sbin/apk"},
	}
	for _, candidate := range candidates {
		if exists, err := d.files.Exists(candidate.path); err == nil && exists {
			return candidate.name
		}
	}
	return "unknown"
}

func (d *Detector) readTrimmed(ctx context.Context, path string) (string, error) {
	data, _, err := d.files.ReadFile(ctx, path, smallSystemFileLimit)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func detectFamily(id, idLike string) string {
	candidates := append([]string{id}, strings.Fields(strings.ToLower(idLike))...)
	for _, candidate := range candidates {
		switch candidate {
		case "rocky", "rhel", "centos", "almalinux", "fedora":
			return "rhel"
		case "debian", "ubuntu":
			return "debian"
		case "suse", "opensuse", "sles":
			return "suse"
		case "alpine":
			return "alpine"
		}
	}
	return "unknown"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "unknown"
}

func parseOSRelease(data []byte) (map[string]string, error) {
	result := make(map[string]string)
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for index, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, raw, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("line %d does not contain '='", index+1)
		}
		key = strings.TrimSpace(key)
		if !validOSReleaseKey(key) {
			return nil, fmt.Errorf("line %d contains invalid key %q", index+1, key)
		}
		value, err := parseOSReleaseValue(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", index+1, err)
		}
		result[key] = value
	}
	if strings.TrimSpace(result["ID"]) == "" {
		return nil, fmt.Errorf("ID is missing")
	}
	return result, nil
}

func validOSReleaseKey(key string) bool {
	if key == "" {
		return false
	}
	for _, character := range key {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func parseOSReleaseValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	switch raw[0] {
	case '\'':
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return "", fmt.Errorf("unterminated single-quoted value")
		}
		return raw[1 : len(raw)-1], nil
	case '"':
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return "", fmt.Errorf("unterminated double-quoted value")
		}
		return unescapeDoubleQuoted(raw[1 : len(raw)-1])
	default:
		if strings.ContainsAny(raw, " \t\"'") {
			return "", fmt.Errorf("unquoted value contains whitespace or quotes")
		}
		return unescapeUnquoted(raw), nil
	}
}

func unescapeDoubleQuoted(value string) (string, error) {
	var builder strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			builder.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) {
			return "", fmt.Errorf("trailing escape")
		}
		index++
		switch value[index] {
		case '\\', '"', '$', '`':
			builder.WriteByte(value[index])
		default:
			builder.WriteByte('\\')
			builder.WriteByte(value[index])
		}
	}
	return builder.String(), nil
}

func unescapeUnquoted(value string) string {
	return strings.ReplaceAll(value, `\\`, `\`)
}
