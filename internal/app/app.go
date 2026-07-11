package app

import (
	"context"
	"fmt"
	"os"

	"github.com/yesidodo73/OpenCIIP/internal/checks"
	"github.com/yesidodo73/OpenCIIP/internal/engine"
	"github.com/yesidodo73/OpenCIIP/internal/evaluator"
	"github.com/yesidodo73/OpenCIIP/internal/executor"
	"github.com/yesidodo73/OpenCIIP/internal/model"
	"github.com/yesidodo73/OpenCIIP/internal/platform"
	"github.com/yesidodo73/OpenCIIP/internal/remediation/hostidentity"
	"github.com/yesidodo73/OpenCIIP/internal/rules"
	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type Application struct {
	engine   *engine.Engine
	host     *hostidentity.Collector
	files    *system.OSReader
	platform model.PlatformInfo
	warnings []string
}

func New(ctx context.Context, systemRoot string) (*Application, error) {
	files, err := system.NewOSReader(systemRoot)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = files.Close()
		}
	}()
	detector := platform.NewDetector(files)
	platformInfo, warnings, err := detector.Detect(ctx)
	if err != nil {
		return nil, fmt.Errorf("detect platform: %w", err)
	}
	commands, err := executor.New(scanCommandAllowlist())
	if err != nil {
		return nil, fmt.Errorf("create command runner: %w", err)
	}
	bundle, err := rules.LoadDefaults()
	if err != nil {
		return nil, fmt.Errorf("load default rules: %w", err)
	}
	platformInfo, err = bundle.ResolvePlatformSupport(platformInfo)
	if err != nil {
		return nil, fmt.Errorf("resolve platform support: %w", err)
	}
	if platformInfo.ScanSupport == model.ScanSupportUnsupported {
		return nil, fmt.Errorf("현재는 Linux 서버 점검만 지원합니다")
	}
	registry := evaluator.NewRegistry()
	if err := checks.RegisterAll(registry, bundle.EvaluatorIDs()); err != nil {
		return nil, err
	}
	checkEngine, err := engine.New(bundle, registry, evaluator.Environment{
		Files:    files,
		Commands: commands,
		Platform: platformInfo,
	})
	if err != nil {
		return nil, err
	}
	host, err := hostidentity.New(systemRoot)
	if err != nil {
		return nil, fmt.Errorf("prepare host identity collector: %w", err)
	}
	succeeded = true
	return &Application{engine: checkEngine, host: host, files: files, platform: platformInfo, warnings: warnings}, nil
}

func NewDefault(ctx context.Context) (*Application, error) {
	return New(ctx, string(os.PathSeparator))
}

func (a *Application) PlatformInfo() model.PlatformInfo {
	if a == nil {
		return model.PlatformInfo{}
	}
	return a.platform
}

func (a *Application) Close() error {
	if a == nil || a.files == nil {
		return nil
	}
	err := a.files.Close()
	a.files = nil
	return err
}

func (a *Application) Scan(ctx context.Context, options engine.Options) (model.ScanRun, error) {
	run, err := a.engine.Scan(ctx, options)
	if err != nil {
		return model.ScanRun{}, err
	}
	run.Metadata.Warnings = append(run.Metadata.Warnings, a.warnings...)
	if a.host == nil {
		run.Metadata.Warnings = append(run.Metadata.Warnings, "호스트 식별 수집기가 없어 이 보고서를 자동 조치 입력으로 사용할 수 없습니다.")
		return run, nil
	}
	identity, identityErr := a.host.Collect(ctx)
	if identityErr != nil {
		run.Metadata.Warnings = append(run.Metadata.Warnings, "호스트 식별 정보를 안전하게 수집하지 못해 이 보고서를 자동 조치 입력으로 사용할 수 없습니다.")
		return run, nil
	}
	run.Metadata.TargetIdentity = &identity
	return run, nil
}

func scanCommandAllowlist() []string {
	return []string{
		"authselect",
		"chage",
		"chronyc",
		"dnf",
		"exportfs",
		"find",
		"findmnt",
		"firewall-cmd",
		"fuser",
		"getent",
		"getfacl",
		"last",
		"lastlog",
		"matchpathcon",
		"named",
		"named-checkconf",
		"nft",
		"postconf",
		"ps",
		"pwck",
		"rpcinfo",
		"rpm",
		"rsyslogd",
		"sendmail",
		"sha256sum",
		"snmpd",
		"ss",
		"sshd",
		"systemd-analyze",
		"systemctl",
		"testparm",
		"timedatectl",
		"udevadm",
		"visudo",
	}
}
