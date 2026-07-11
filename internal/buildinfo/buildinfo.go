package buildinfo

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

var (
	version = ""
	commit  = "unknown"
	date    = "unknown"
)

//go:embed VERSION
var embeddedVersion string

// Info describes the exact OpenCIIP build that produced a result.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	Modified  bool   `json:"modified"`
}

// Current returns build information set by release ldflags and Go module data.
func Current() Info {
	resolvedVersion := strings.TrimSpace(version)
	if resolvedVersion == "" {
		resolvedVersion = strings.TrimSpace(embeddedVersion)
	}
	if resolvedVersion == "" {
		resolvedVersion = "dev"
	}
	info := Info{
		Version:   resolvedVersion,
		Commit:    commit,
		BuildDate: date,
	}

	if build, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range build.Settings {
			switch setting.Key {
			case "vcs.revision":
				if info.Commit == "unknown" && setting.Value != "" {
					info.Commit = setting.Value
				}
			case "vcs.time":
				if info.BuildDate == "unknown" && setting.Value != "" {
					info.BuildDate = setting.Value
				}
			case "vcs.modified":
				info.Modified = setting.Value == "true"
			}
		}
	}
	if info.Modified && !strings.Contains(info.Version, "+dirty") {
		info.Version += "+dirty"
	}

	return info
}

func IsPrerelease(version string) bool {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	version, _, _ = strings.Cut(version, "+")
	return strings.Contains(version, "-")
}

// ExecutableSHA256 hashes one stably opened executable twice and rejects a
// changing file before returning its identity.
func ExecutableSHA256(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path, err := runningExecutablePath()
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open remediation executable: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		if err == nil {
			err = fmt.Errorf("executable is not a regular file")
		}
		return "", fmt.Errorf("inspect remediation executable: %w", err)
	}
	first, err := hashExecutable(ctx, file)
	if err != nil {
		return "", err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind remediation executable: %w", err)
	}
	second, err := hashExecutable(ctx, file)
	if err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("reinspect remediation executable: %w", err)
	}
	if first != second || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		return "", fmt.Errorf("remediation executable changed while it was hashed")
	}
	return first, nil
}

func hashExecutable(ctx context.Context, reader io.Reader) (string, error) {
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		count, err := reader.Read(buffer)
		if count > 0 {
			if _, writeErr := hash.Write(buffer[:count]); writeErr != nil {
				return "", fmt.Errorf("hash remediation executable: %w", writeErr)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read remediation executable: %w", err)
		}
		if count == 0 {
			return "", io.ErrNoProgress
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
