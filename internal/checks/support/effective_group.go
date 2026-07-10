package support

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func ReadEffectiveGroup(ctx context.Context, commands executor.CommandRunner, name string) (GroupEntry, model.Evidence, bool, error) {
	if name == "" || strings.ContainsAny(name, " \t/\\:") {
		return GroupEntry{}, model.Evidence{}, false, fmt.Errorf("invalid group name %q", name)
	}
	spec := executor.Spec{Name: "getent", Arguments: []string{"group", name}, Timeout: 10 * time.Second, MaxOutput: 1 << 20}
	result, err := commands.Run(ctx, spec)
	if err != nil {
		return GroupEntry{}, model.Evidence{}, false, fmt.Errorf("run getent group %s: %w", name, err)
	}
	baseEvidence := FactEvidence("getent group "+name, map[string]any{
		"executable":  result.Executable,
		"exit_code":   result.ExitCode,
		"duration_ms": result.Duration.Milliseconds(),
	})
	if result.ExitCode == 2 {
		return GroupEntry{}, baseEvidence, false, nil
	}
	if result.ExitCode != 0 || result.Truncated {
		return GroupEntry{}, baseEvidence, false, fmt.Errorf("getent group %s exit=%d truncated=%t", name, result.ExitCode, result.Truncated)
	}
	line := strings.TrimSpace(string(result.Stdout))
	if strings.Contains(line, "\n") || strings.Contains(line, "\r") {
		return GroupEntry{}, baseEvidence, false, fmt.Errorf("getent group %s returned multiple lines", name)
	}
	fields := strings.Split(line, ":")
	if len(fields) != 4 || fields[0] != name {
		return GroupEntry{}, baseEvidence, false, fmt.Errorf("getent group %s returned an invalid entry", name)
	}
	gid, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return GroupEntry{}, baseEvidence, false, fmt.Errorf("getent group %s returned an invalid gid", name)
	}
	members := make([]string, 0)
	if fields[3] != "" {
		for _, member := range strings.Split(fields[3], ",") {
			member = strings.TrimSpace(member)
			if member == "" {
				return GroupEntry{}, baseEvidence, false, fmt.Errorf("getent group %s returned an empty member", name)
			}
			members = append(members, member)
		}
	}
	entry := GroupEntry{Name: name, Password: fields[1], GID: uint32(gid), Members: members}
	baseEvidence.Fact["group"] = map[string]any{
		"name": entry.Name, "gid": entry.GID, "member_count": len(entry.Members),
		"member_set_sha256": stringSetDigest(entry.Members), "member_details_redacted": true,
	}
	return entry, baseEvidence, true, nil
}
