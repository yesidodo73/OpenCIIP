package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultTimeout   = 15 * time.Second
	maximumTimeout   = 5 * time.Minute
	defaultOutputCap = 1 << 20
	maximumOutputCap = 8 << 20
	maximumArguments = 128
	maximumArgLength = 8 << 10
)

var (
	ErrCommandNotAllowed = errors.New("command is not allowed")
	ErrCommandNotFound   = errors.New("command was not found in trusted paths")
	ErrCommandTimeout    = errors.New("command timed out")
	commandNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)
)

type Spec struct {
	Name          string
	Arguments     []string
	Timeout       time.Duration
	MaxOutput     int
	SensitiveArgs map[int]struct{}
}

func (s Spec) EvidenceArguments() []string {
	arguments := append([]string(nil), s.Arguments...)
	for index := range s.SensitiveArgs {
		if index >= 0 && index < len(arguments) {
			arguments[index] = "[REDACTED]"
		}
	}
	return arguments
}

type Result struct {
	Executable string
	Arguments  []string
	ExitCode   int
	Stdout     []byte
	Stderr     []byte
	StartedAt  time.Time
	Duration   time.Duration
	TimedOut   bool
	Truncated  bool
}

type CommandRunner interface {
	Run(context.Context, Spec) (Result, error)
	Available(string) bool
}

type Runner struct {
	allowed     map[string]struct{}
	searchPaths []string
}

func New(allowed []string) (*Runner, error) {
	commands := make(map[string]struct{}, len(allowed))
	for _, command := range allowed {
		command = strings.TrimSpace(command)
		if !commandNamePattern.MatchString(command) {
			return nil, fmt.Errorf("invalid allowed command name %q", command)
		}
		commands[command] = struct{}{}
	}
	return &Runner{
		allowed: commands,
		searchPaths: []string{
			"/usr/sbin",
			"/usr/bin",
			"/sbin",
			"/bin",
		},
	}, nil
}

func (r *Runner) Available(name string) bool {
	if _, allowed := r.allowed[name]; !allowed {
		return false
	}
	_, err := r.resolve(name)
	return err == nil
}

func (r *Runner) Run(ctx context.Context, spec Spec) (Result, error) {
	if _, allowed := r.allowed[spec.Name]; !allowed {
		return Result{}, fmt.Errorf("%w: %s", ErrCommandNotAllowed, spec.Name)
	}
	if !commandNamePattern.MatchString(spec.Name) {
		return Result{}, fmt.Errorf("invalid command name %q", spec.Name)
	}
	if len(spec.Arguments) > maximumArguments {
		return Result{}, fmt.Errorf("command %s has too many arguments", spec.Name)
	}
	for _, argument := range spec.Arguments {
		if len(argument) > maximumArgLength {
			return Result{}, fmt.Errorf("command %s has an argument larger than %d bytes", spec.Name, maximumArgLength)
		}
		if strings.IndexByte(argument, 0) >= 0 {
			return Result{}, fmt.Errorf("command %s has an argument containing a NUL byte", spec.Name)
		}
	}
	executable, err := r.resolve(spec.Name)
	if err != nil {
		return Result{}, err
	}

	timeout := spec.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > maximumTimeout {
		return Result{}, fmt.Errorf("command timeout %s exceeds maximum %s", timeout, maximumTimeout)
	}
	outputCap := spec.MaxOutput
	if outputCap <= 0 {
		outputCap = defaultOutputCap
	}
	if outputCap > maximumOutputCap {
		return Result{}, fmt.Errorf("command output limit %d exceeds maximum %d", outputCap, maximumOutputCap)
	}

	runContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout := newLimitedBuffer(outputCap)
	stderr := newLimitedBuffer(outputCap)
	command := exec.CommandContext(runContext, executable, spec.Arguments...)
	command.Env = trustedEnvironment()
	command.Stdout = stdout
	command.Stderr = stderr
	command.WaitDelay = 2 * time.Second
	configureCommand(command)

	startedAt := time.Now().UTC()
	err = command.Run()
	result := Result{
		Executable: executable,
		Arguments:  spec.EvidenceArguments(),
		ExitCode:   0,
		Stdout:     stdout.Bytes(),
		Stderr:     stderr.Bytes(),
		StartedAt:  startedAt,
		Duration:   time.Since(startedAt),
		TimedOut:   errors.Is(runContext.Err(), context.DeadlineExceeded),
		Truncated:  stdout.Truncated() || stderr.Truncated(),
	}

	if runContext.Err() != nil {
		result.ExitCode = -1
		if result.TimedOut {
			return result, fmt.Errorf("%w: %s", ErrCommandTimeout, spec.Name)
		}
		return result, fmt.Errorf("run command %s: %w", spec.Name, runContext.Err())
	}
	if err == nil {
		return result, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		return result, nil
	}
	result.ExitCode = -1
	return result, fmt.Errorf("run command %s: %w", spec.Name, err)
}

func (r *Runner) resolve(name string) (string, error) {
	for _, directory := range r.searchPaths {
		candidate := filepath.Join(directory, name)
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		if !withinTrustedPath(resolved, r.searchPaths) {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !trustedExecutable(info) {
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%w: %s", ErrCommandNotFound, name)
}

func withinTrustedPath(path string, directories []string) bool {
	path = filepath.Clean(path)
	for _, directory := range directories {
		relative, err := filepath.Rel(filepath.Clean(directory), path)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			return true
		}
	}
	return false
}

func trustedEnvironment() []string {
	environment := []string{
		"HOME=/",
		"LANG=C",
		"LC_ALL=C",
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"SYSTEMD_COLORS=0",
		"SYSTEMD_PAGER=",
		"TERM=dumb",
	}
	sort.Strings(environment)
	return environment
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	originalLength := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.truncated = b.truncated || originalLength > 0
		return originalLength, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(data)
	return originalLength, nil
}

func (b *limitedBuffer) Bytes() []byte {
	return append([]byte(nil), b.buffer.Bytes()...)
}

func (b *limitedBuffer) Truncated() bool {
	return b.truncated
}
