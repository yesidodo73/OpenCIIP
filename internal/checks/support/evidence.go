package support

import (
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

func FactEvidence(source string, facts map[string]any) model.Evidence {
	return model.Evidence{
		Kind:       model.EvidenceFact,
		Source:     source,
		CapturedAt: nowUTC(),
		Redacted:   true,
		Fact:       facts,
	}
}

func FileMetadataEvidence(metadata system.FileMetadata) model.Evidence {
	return model.Evidence{
		Kind:       model.EvidenceFile,
		Source:     metadata.Path,
		CapturedAt: nowUTC(),
		Redacted:   true,
		File: &model.FileEvidence{
			Path:  metadata.Path,
			Mode:  metadata.Mode.String(),
			Owner: numericIdentity(metadata.UID),
			Group: numericIdentity(metadata.GID),
		},
	}
}

func CommandEvidence(spec executor.Spec, result executor.Result) model.Evidence {
	return model.Evidence{
		Kind:       model.EvidenceCommand,
		Source:     result.Executable,
		CapturedAt: nowUTC(),
		Redacted:   len(spec.SensitiveArgs) > 0,
		Command: &model.CommandEvidence{
			Executable: result.Executable,
			Arguments:  result.Arguments,
			ExitCode:   result.ExitCode,
			Stdout:     string(result.Stdout),
			Stderr:     string(result.Stderr),
			DurationMS: result.Duration.Milliseconds(),
			TimedOut:   result.TimedOut,
			Truncated:  result.Truncated,
		},
	}
}

func numericIdentity(value int) string {
	if value < 0 {
		return "unknown"
	}
	return fmtInt(value)
}

func fmtInt(value int) string {
	if value == 0 {
		return "0"
	}
	digits := [20]byte{}
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func nowUTC() time.Time {
	return time.Now().UTC()
}
