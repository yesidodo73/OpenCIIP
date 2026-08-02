package supportevidence

import (
	"bytes"
	"crypto/sha256"
	gobuildinfo "debug/buildinfo"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

const openCIIPCommandPath = "github.com/yesidodo73/OpenCIIP/cmd/openciip"
const openCIIPModulePath = "github.com/yesidodo73/OpenCIIP"

// GoBinaryBuildIdentity contains the non-executable Go build metadata required
// to bind a final verification manifest to the supplied OpenCIIP binary.
type GoBinaryBuildIdentity struct {
	GoVersion     string
	CommandPath   string
	ModulePath    string
	ModuleVersion string
	BuildMode     string
	Compiler      string
	Trimpath      string
	CGOEnabled    string
	GOOS          string
	GOARCH        string
	GOAMD64       string
	VCS           string
	VCSRevision   string
	VCSModified   string
}

// InspectArtifact hashes one regular, non-link file twice through the same
// handle and rejects path replacement while it is inspected.
func InspectArtifact(path string) (ArtifactIdentity, error) {
	file, before, err := openStableRegular(path)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	defer file.Close()

	identity, err := hashStableArtifact(file, before, path)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	return identity, nil
}

func readStableRegular(path string, maximum int64) ([]byte, error) {
	file, before, err := openStableRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	read := func() ([]byte, error) {
		value, err := io.ReadAll(io.LimitReader(file, maximum+1))
		if err != nil {
			return nil, fmt.Errorf("read artifact: %w", err)
		}
		if int64(len(value)) > maximum {
			return nil, fmt.Errorf("artifact exceeds the %d byte limit", maximum)
		}
		return value, nil
	}
	first, err := read()
	if err != nil {
		return nil, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind artifact: %w", err)
	}
	second, err := read()
	if err != nil {
		return nil, err
	}
	afterOpen, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("reinspect open artifact: %w", err)
	}
	afterPath, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("reinspect artifact path: %w", err)
	}
	if !bytes.Equal(first, second) || !sameFileSnapshot(before, afterOpen) ||
		!sameFileSnapshot(before, afterPath) || isReparsePoint(afterPath) {
		return nil, fmt.Errorf("artifact changed while it was inspected")
	}
	return first, nil
}

// InspectGoBinary reads Go build metadata and hashes the exact same open file.
// It does not execute the supplied binary.
func InspectGoBinary(path string) (ArtifactIdentity, GoBinaryBuildIdentity, error) {
	file, before, err := openStableRegular(path)
	if err != nil {
		return ArtifactIdentity{}, GoBinaryBuildIdentity{}, err
	}
	defer file.Close()

	info, err := gobuildinfo.Read(file)
	if err != nil {
		return ArtifactIdentity{}, GoBinaryBuildIdentity{}, fmt.Errorf("read final binary Go build metadata: %w", err)
	}
	identity, err := hashStableArtifact(file, before, path)
	if err != nil {
		return ArtifactIdentity{}, GoBinaryBuildIdentity{}, err
	}
	parsed, err := parseGoBinaryBuildIdentity(info)
	if err != nil {
		return ArtifactIdentity{}, GoBinaryBuildIdentity{}, err
	}
	return identity, parsed, nil
}

func parseGoBinaryBuildIdentity(info *debug.BuildInfo) (GoBinaryBuildIdentity, error) {
	if info == nil {
		return GoBinaryBuildIdentity{}, fmt.Errorf("final binary has no Go build metadata")
	}
	identity := GoBinaryBuildIdentity{
		GoVersion:     info.GoVersion,
		CommandPath:   info.Path,
		ModulePath:    info.Main.Path,
		ModuleVersion: info.Main.Version,
	}
	settings := map[string]*string{
		"-buildmode":   &identity.BuildMode,
		"-compiler":    &identity.Compiler,
		"-trimpath":    &identity.Trimpath,
		"CGO_ENABLED":  &identity.CGOEnabled,
		"GOOS":         &identity.GOOS,
		"GOARCH":       &identity.GOARCH,
		"GOAMD64":      &identity.GOAMD64,
		"vcs":          &identity.VCS,
		"vcs.revision": &identity.VCSRevision,
		"vcs.modified": &identity.VCSModified,
	}
	seen := make(map[string]struct{}, len(settings))
	for _, setting := range info.Settings {
		destination, required := settings[setting.Key]
		if !required {
			continue
		}
		if _, duplicate := seen[setting.Key]; duplicate {
			return GoBinaryBuildIdentity{}, fmt.Errorf("final binary has duplicate Go build setting %s", setting.Key)
		}
		seen[setting.Key] = struct{}{}
		*destination = setting.Value
	}
	return identity, nil
}

func (i GoBinaryBuildIdentity) Validate(platform Platform, source SourceIdentity) error {
	if !strings.HasPrefix(i.GoVersion, "go1.") {
		return fmt.Errorf("final binary has an unsupported Go toolchain identity %q", i.GoVersion)
	}
	if i.CommandPath != openCIIPCommandPath || i.ModulePath != openCIIPModulePath {
		return fmt.Errorf("final binary is not the OpenCIIP command from the canonical module")
	}
	if strings.Contains(i.ModuleVersion, "dirty") {
		return fmt.Errorf("final binary module version is modified")
	}
	if i.BuildMode != "exe" || i.Compiler != "gc" || i.Trimpath != "true" {
		return fmt.Errorf("final binary must use buildmode=exe, compiler=gc, and -trimpath")
	}
	if i.CGOEnabled != "0" || i.GOOS != "linux" || i.GOARCH != platform.Architecture {
		return fmt.Errorf("final binary target does not match linux/%s with CGO disabled", platform.Architecture)
	}
	if platform.Architecture == "amd64" && i.GOAMD64 != "v1" {
		return fmt.Errorf("final amd64 binary must use GOAMD64=v1")
	}
	if i.VCS != "git" || i.VCSRevision != source.ToolCommit || i.VCSModified != "false" {
		return fmt.Errorf("final binary must contain the exact clean Git revision from the manifest")
	}
	return nil
}

func openStableRegular(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect artifact path: %w", err)
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || isReparsePoint(before) {
		return nil, nil, fmt.Errorf("artifact must be a regular non-link file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open artifact: %w", err)
	}
	opened, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("inspect open artifact: %w", err)
	}
	if !sameFileSnapshot(before, opened) {
		file.Close()
		return nil, nil, fmt.Errorf("artifact path changed while it was opened")
	}
	return file, before, nil
}

func hashStableArtifact(file *os.File, before os.FileInfo, path string) (ArtifactIdentity, error) {
	first, err := hashOpenArtifact(file)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ArtifactIdentity{}, fmt.Errorf("rewind artifact: %w", err)
	}
	second, err := hashOpenArtifact(file)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	afterOpen, err := file.Stat()
	if err != nil {
		return ArtifactIdentity{}, fmt.Errorf("reinspect open artifact: %w", err)
	}
	afterPath, err := os.Lstat(path)
	if err != nil {
		return ArtifactIdentity{}, fmt.Errorf("reinspect artifact path: %w", err)
	}
	if first != second || !sameFileSnapshot(before, afterOpen) ||
		!sameFileSnapshot(before, afterPath) || isReparsePoint(afterPath) {
		return ArtifactIdentity{}, fmt.Errorf("artifact changed while it was inspected")
	}
	return ArtifactIdentity{SHA256: first, SizeBytes: before.Size()}, nil
}

func hashOpenArtifact(file *os.File) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind artifact: %w", err)
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("read artifact: %w", err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func sameFileSnapshot(left, right os.FileInfo) bool {
	return left != nil && right != nil &&
		left.Mode().IsRegular() && right.Mode().IsRegular() &&
		left.Mode()&os.ModeSymlink == 0 && right.Mode()&os.ModeSymlink == 0 &&
		os.SameFile(left, right) && left.Size() == right.Size() &&
		left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}
