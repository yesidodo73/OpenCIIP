package support

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func ReadEffectiveGroups(ctx context.Context, commands executor.CommandRunner) ([]GroupEntry, model.Evidence, error) {
	spec := executor.Spec{Name: "getent", Arguments: []string{"group"}, Timeout: 20 * time.Second, MaxOutput: 4 << 20}
	result, err := commands.Run(ctx, spec)
	if err != nil {
		return nil, model.Evidence{}, fmt.Errorf("run getent group: %w", err)
	}
	if result.ExitCode != 0 || result.Truncated {
		return nil, model.Evidence{}, fmt.Errorf("run getent group: exit=%d truncated=%t", result.ExitCode, result.Truncated)
	}
	groups := make([]GroupEntry, 0, 32)
	seen := make(map[string]struct{})
	for lineNumber, raw := range strings.Split(strings.ReplaceAll(string(result.Stdout), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 4 {
			return nil, model.Evidence{}, fmt.Errorf("parse getent group line %d: expected 4 fields", lineNumber+1)
		}
		if !validIdentityName(fields[0]) {
			return nil, model.Evidence{}, fmt.Errorf("parse getent group line %d: invalid group name", lineNumber+1)
		}
		if _, exists := seen[fields[0]]; exists {
			return nil, model.Evidence{}, fmt.Errorf("parse getent group line %d: duplicate group %s", lineNumber+1, fields[0])
		}
		seen[fields[0]] = struct{}{}
		gid, parseErr := parseID(fields[2])
		if parseErr != nil {
			return nil, model.Evidence{}, fmt.Errorf("parse getent group line %d gid: %w", lineNumber+1, parseErr)
		}
		members := make([]string, 0)
		if fields[3] != "" {
			for _, rawMember := range strings.Split(fields[3], ",") {
				member := strings.TrimSpace(rawMember)
				if !validIdentityName(member) {
					return nil, model.Evidence{}, fmt.Errorf("parse getent group line %d: invalid member", lineNumber+1)
				}
				members = append(members, member)
			}
		}
		sort.Strings(members)
		groups = append(groups, GroupEntry{Name: fields[0], Password: fields[1], GID: gid, Members: members, Line: lineNumber + 1})
	}
	if len(groups) == 0 {
		return nil, model.Evidence{}, fmt.Errorf("parse getent group: no group entries")
	}
	sort.Slice(groups, func(left, right int) bool { return groups[left].Name < groups[right].Name })
	canonical := make([]string, 0, len(groups))
	membershipCount := 0
	for _, group := range groups {
		membershipCount += len(group.Members)
		canonical = append(canonical, fmt.Sprintf("%s\x00%d\x00%s", group.Name, group.GID, strings.Join(group.Members, "\x00")))
	}
	evidence := FactEvidence("getent group", map[string]any{
		"executable": result.Executable, "exit_code": result.ExitCode,
		"duration_ms": result.Duration.Milliseconds(), "group_count": len(groups),
		"membership_count": membershipCount, "group_set_sha256": stringSetDigest(canonical),
		"group_details_redacted": true,
	})
	return groups, evidence, nil
}
