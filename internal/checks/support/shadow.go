package support

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type ShadowEntry struct {
	Name      string
	State     string
	Algorithm string
	MinDays   *int
	MaxDays   *int
	Line      int
}

func ReadShadowSummary(ctx context.Context, files system.Reader) (map[string]ShadowEntry, model.Evidence, error) {
	data, _, err := files.ReadFile(ctx, "/etc/shadow", 4<<20)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("read /etc/shadow: %w", err)
	}
	entries := make(map[string]ShadowEntry)
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 9 {
			return nil, model.Evidence{}, fmt.Errorf("parse /etc/shadow line %d: expected 9 fields", index+1)
		}
		name := fields[0]
		if !validIdentityName(name) {
			return nil, model.Evidence{}, fmt.Errorf("parse /etc/shadow line %d: invalid account name", index+1)
		}
		if _, exists := entries[name]; exists {
			return nil, model.Evidence{}, fmt.Errorf("parse /etc/shadow line %d: duplicate account %s", index+1, name)
		}
		state, algorithm := classifyShadowPassword(fields[1])
		minDays, err := optionalShadowInt(fields[3])
		if err != nil {
			return nil, model.Evidence{}, fmt.Errorf("parse /etc/shadow line %d minimum days: %w", index+1, err)
		}
		maxDays, err := optionalShadowInt(fields[4])
		if err != nil {
			return nil, model.Evidence{}, fmt.Errorf("parse /etc/shadow line %d maximum days: %w", index+1, err)
		}
		entries[name] = ShadowEntry{Name: name, State: state, Algorithm: algorithm, MinDays: minDays, MaxDays: maxDays, Line: index + 1}
	}
	if len(entries) == 0 {
		return nil, model.Evidence{}, fmt.Errorf("parse /etc/shadow: no account entries")
	}
	facts := make([]map[string]any, 0, len(entries))
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := entries[name]
		facts = append(facts, map[string]any{
			"name":      entry.Name,
			"state":     entry.State,
			"algorithm": entry.Algorithm,
			"min_days":  entry.MinDays,
			"max_days":  entry.MaxDays,
			"line":      entry.Line,
		})
	}
	return entries, FactEvidence("/etc/shadow", map[string]any{
		"redaction": "비밀번호 해시와 잠금 문자열은 저장하지 않았습니다.",
		"accounts":  facts,
	}), nil
}

func optionalShadowInt(value string) (*int, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return nil, fmt.Errorf("invalid non-negative integer %q", value)
	}
	return &parsed, nil
}

func classifyShadowPassword(value string) (state, algorithm string) {
	if value == "" {
		return "empty", "none"
	}
	trimmed := strings.TrimLeft(value, "!")
	if trimmed != value {
		if trimmed == "" {
			return "locked", "none"
		}
		state = "locked"
	} else if strings.HasPrefix(value, "*") {
		return "locked", "none"
	} else {
		state = "active"
	}
	if strings.HasPrefix(trimmed, "$") {
		parts := strings.SplitN(strings.TrimPrefix(trimmed, "$"), "$", 2)
		if len(parts) == 2 && parts[0] != "" {
			return state, parts[0]
		}
	}
	return state, "legacy_or_unknown"
}
