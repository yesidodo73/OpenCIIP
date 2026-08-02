package support

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

const dpkgQueryFormat = "${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n"

type DPKGPackage struct {
	Name         string
	Version      string
	Architecture string
}

func InspectDPKGInventory(ctx context.Context, environment evaluator.Environment) ([]DPKGPackage, model.Evidence, error) {
	spec := executor.Spec{
		Name:      "dpkg-query",
		Arguments: []string{"--show", "--showformat=" + dpkgQueryFormat},
		Timeout:   2 * time.Minute,
		MaxOutput: 8 << 20,
	}
	result, err := environment.Commands.Run(ctx, spec)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("inspect dpkg package inventory: %w", err)
	}
	evidence := CommandSummaryEvidence("dpkg-package-inventory-summary", spec, result, map[string]any{
		"content_redacted": true,
	})
	if result.ExitCode != 0 || result.Truncated {
		return nil, evidence, fmt.Errorf("inspect dpkg package inventory: exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	if strings.TrimSpace(string(result.Stderr)) != "" {
		return nil, evidence, fmt.Errorf("inspect dpkg package inventory: command emitted diagnostics")
	}
	packages, err := ParseDPKGInventory(string(result.Stdout))
	if err != nil {
		return nil, evidence, fmt.Errorf("inspect dpkg package inventory: %w", err)
	}
	evidence.Fact["installed_package_count"] = len(packages)
	identities := make([]string, 0, len(packages))
	for _, item := range packages {
		identities = append(identities, item.Name+"\x00"+item.Version+"\x00"+item.Architecture)
	}
	evidence.Fact["installed_set_sha256"] = stringSetDigest(identities)
	return packages, evidence, nil
}

func ParseDPKGInventory(output string) ([]DPKGPackage, error) {
	records := make(map[string]DPKGPackage)
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if raw == "" {
			continue
		}
		fields := strings.Split(raw, "\t")
		if len(fields) != 4 {
			return nil, fmt.Errorf("line %d does not have four tab-separated fields", lineNumber+1)
		}
		name := strings.TrimSpace(fields[0])
		version := strings.TrimSpace(fields[1])
		architecture := strings.TrimSpace(fields[2])
		status := fields[3]
		if !validDPKGPackageName(name) || version == "" || strings.ContainsAny(version, "\x00\r\n\t") ||
			!validDPKGArchitecture(architecture) {
			return nil, fmt.Errorf("line %d has an invalid package identity", lineNumber+1)
		}
		if len(status) != 3 || !strings.ContainsRune("uihrp", rune(status[0])) ||
			!strings.ContainsRune("ncHUFWti", rune(status[1])) ||
			(status[2] != ' ' && status[2] != 'R') {
			return nil, fmt.Errorf("line %d has an invalid package status", lineNumber+1)
		}
		if status[1] != 'i' || status[2] != ' ' {
			continue
		}
		if _, duplicate := records[name]; duplicate {
			return nil, fmt.Errorf("line %d repeats installed package %s", lineNumber+1, name)
		}
		records[name] = DPKGPackage{Name: name, Version: version, Architecture: architecture}
	}
	packages := make([]DPKGPackage, 0, len(records))
	for _, item := range records {
		packages = append(packages, item)
	}
	sort.Slice(packages, func(left, right int) bool {
		return packages[left].Name < packages[right].Name
	})
	return packages, nil
}

func DPKGPackageInstalled(packages []DPKGPackage, names ...string) bool {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	for _, item := range packages {
		name := item.Name
		if index := strings.LastIndexByte(name, ':'); index > 0 {
			name = name[:index]
		}
		if _, exists := wanted[name]; exists {
			return true
		}
	}
	return false
}

func validDPKGPackageName(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	name, architecture, hasArchitecture := strings.Cut(value, ":")
	if name == "" || hasArchitecture && !validDPKGArchitecture(architecture) {
		return false
	}
	for _, character := range name {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '+' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func validDPKGArchitecture(value string) bool {
	if value == "" || strings.HasPrefix(value, "-") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '-' {
			return false
		}
	}
	return true
}
