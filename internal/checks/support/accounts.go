package support

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type PasswdEntry struct {
	Name     string
	Password string
	UID      uint32
	GID      uint32
	GECOS    string
	Home     string
	Shell    string
	Line     int
}

type GroupEntry struct {
	Name     string
	Password string
	GID      uint32
	Members  []string
	Line     int
}

func ReadPasswd(ctx context.Context, files system.Reader) ([]PasswdEntry, model.Evidence, error) {
	data, metadata, err := files.ReadFile(ctx, "/etc/passwd", 4<<20)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("read /etc/passwd: %w", err)
	}
	entries, err := parsePasswd(data, "/etc/passwd")
	if err != nil {
		return nil, model.Evidence{}, err
	}
	return entries, passwdEvidence("/etc/passwd", entries, map[string]any{"mode": metadata.Mode.Perm().String()}), nil
}

func ReadEffectivePasswd(ctx context.Context, commands executor.CommandRunner) ([]PasswdEntry, model.Evidence, error) {
	spec := executor.Spec{Name: "getent", Arguments: []string{"passwd"}, Timeout: 20 * time.Second, MaxOutput: 4 << 20}
	result, err := commands.Run(ctx, spec)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("run getent passwd: %w", err)
	}
	if result.ExitCode != 0 {
		return nil, model.Evidence{}, fmt.Errorf("run getent passwd: exit code %d", result.ExitCode)
	}
	if result.Truncated {
		return nil, model.Evidence{}, fmt.Errorf("run getent passwd: output exceeded the limit")
	}
	entries, err := parsePasswd(result.Stdout, "getent passwd")
	if err != nil {
		return nil, model.Evidence{}, err
	}
	return entries, passwdEvidence("getent passwd", entries, map[string]any{
		"executable":  result.Executable,
		"exit_code":   result.ExitCode,
		"duration_ms": result.Duration.Milliseconds(),
	}), nil
}

func parsePasswd(data []byte, source string) ([]PasswdEntry, error) {
	entries := make([]PasswdEntry, 0, 32)
	seenNames := make(map[string]int)
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 7 {
			return nil, fmt.Errorf("parse %s line %d: expected 7 fields", source, index+1)
		}
		uid, err := parseID(fields[2])
		if err != nil {
			return nil, fmt.Errorf("parse %s line %d uid: %w", source, index+1, err)
		}
		gid, err := parseID(fields[3])
		if err != nil {
			return nil, fmt.Errorf("parse %s line %d gid: %w", source, index+1, err)
		}
		if fields[0] == "" || strings.ContainsAny(fields[0], " \t/\\") {
			return nil, fmt.Errorf("parse %s line %d: invalid account name", source, index+1)
		}
		if previousLine, duplicate := seenNames[fields[0]]; duplicate {
			return nil, fmt.Errorf("parse %s line %d: duplicate account %s (first seen on line %d)", source, index+1, fields[0], previousLine)
		}
		seenNames[fields[0]] = index + 1
		entries = append(entries, PasswdEntry{
			Name:     fields[0],
			Password: fields[1],
			UID:      uid,
			GID:      gid,
			GECOS:    fields[4],
			Home:     fields[5],
			Shell:    fields[6],
			Line:     index + 1,
		})
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("parse %s: no account entries", source)
	}
	return entries, nil
}

func passwdEvidence(source string, entries []PasswdEntry, extra map[string]any) model.Evidence {
	canonical := make([]string, 0, len(entries))
	uidZeroCount := 0
	for _, entry := range entries {
		canonical = append(canonical, strings.Join([]string{
			entry.Name, strconv.FormatUint(uint64(entry.UID), 10), strconv.FormatUint(uint64(entry.GID), 10), entry.Home, entry.Shell,
		}, "\x00"))
		if entry.UID == 0 {
			uidZeroCount++
		}
	}
	sort.Strings(canonical)
	digest := sha256.New()
	for _, record := range canonical {
		_, _ = digest.Write([]byte(record))
		_, _ = digest.Write([]byte{0})
	}
	evidence := model.Evidence{
		Kind:       model.EvidenceFact,
		Source:     source,
		CapturedAt: nowUTC(),
		Redacted:   true,
		Fact: map[string]any{
			"account_count":            len(entries),
			"account_set_sha256":       hex.EncodeToString(digest.Sum(nil)),
			"uid_zero_entry_count":     uidZeroCount,
			"account_details_redacted": true,
		},
	}
	for key, value := range extra {
		evidence.Fact[key] = value
	}
	return evidence
}

func ReadGroup(ctx context.Context, files system.Reader) ([]GroupEntry, model.Evidence, error) {
	data, metadata, err := files.ReadFile(ctx, "/etc/group", 4<<20)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("read /etc/group: %w", err)
	}
	entries := make([]GroupEntry, 0, 32)
	for index, raw := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			return nil, model.Evidence{}, fmt.Errorf("parse /etc/group line %d: expected 4 fields", index+1)
		}
		gid, err := parseID(fields[2])
		if err != nil {
			return nil, model.Evidence{}, fmt.Errorf("parse /etc/group line %d gid: %w", index+1, err)
		}
		members := make([]string, 0)
		if strings.TrimSpace(fields[3]) != "" {
			for _, member := range strings.Split(fields[3], ",") {
				member = strings.TrimSpace(member)
				if member == "" {
					return nil, model.Evidence{}, fmt.Errorf("parse /etc/group line %d: empty member", index+1)
				}
				members = append(members, member)
			}
		}
		entries = append(entries, GroupEntry{
			Name:     fields[0],
			Password: fields[1],
			GID:      gid,
			Members:  members,
			Line:     index + 1,
		})
	}
	if len(entries) == 0 {
		return nil, model.Evidence{}, fmt.Errorf("parse /etc/group: no group entries")
	}
	canonical := make([]string, 0, len(entries))
	membershipCount := 0
	for _, entry := range entries {
		membershipCount += len(entry.Members)
		canonical = append(canonical, fmt.Sprintf("%s\x00%d\x00%s", entry.Name, entry.GID, strings.Join(entry.Members, "\x00")))
	}
	evidence := model.Evidence{
		Kind:       model.EvidenceFact,
		Source:     "/etc/group",
		CapturedAt: nowUTC(),
		Redacted:   true,
		Fact: map[string]any{
			"mode":                   metadata.Mode.Perm().String(),
			"group_count":            len(entries),
			"membership_count":       membershipCount,
			"group_set_sha256":       stringSetDigest(canonical),
			"group_details_redacted": true,
		},
	}
	return entries, evidence, nil
}

func parseID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric id %q", value)
	}
	return uint32(parsed), nil
}
