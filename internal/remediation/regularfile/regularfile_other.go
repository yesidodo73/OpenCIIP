//go:build !linux

package regularfile

import (
	"context"
	"fmt"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func unsupported(operation string) error {
	return &Error{Code: CodeUnsupportedPlatform, Operation: operation, Err: fmt.Errorf("regular-file remediation is currently verified only on Linux")}
}

func newPlatform(string, string, config) (*Handler, error) {
	return nil, unsupported("initialize")
}

func (*Handler) normalizePlatform(context.Context, model.ResourceRef) (model.CanonicalResource, error) {
	return model.CanonicalResource{}, unsupported("normalize")
}

func (*Handler) capturePlatform(context.Context, model.CanonicalResource) (model.ResourceSnapshot, error) {
	return model.ResourceSnapshot{}, unsupported("capture")
}

func (*Handler) buildDesiredMetadataPlatform(context.Context, model.CanonicalResource, DesiredMetadata) (model.ResourceSnapshot, error) {
	return model.ResourceSnapshot{}, unsupported("build desired state")
}

func (*Handler) backupPlatform(context.Context, string, string, model.CanonicalResource, model.ResourceSnapshot) (model.BackupArtifact, error) {
	return model.BackupArtifact{}, unsupported("backup")
}

func (*Handler) verifyBackupPlatform(context.Context, model.BackupArtifact) error {
	return unsupported("verify backup")
}

func (*Handler) applyMetadataPlatform(context.Context, model.CanonicalResource, model.ResourceSnapshot, model.ResourceSnapshot) (model.ResourceSnapshot, error) {
	return model.ResourceSnapshot{}, unsupported("apply metadata")
}

func (*Handler) restorePlatform(context.Context, model.OperationRecord, model.BackupArtifact, bool) (model.ResourceSnapshot, error) {
	return model.ResourceSnapshot{}, unsupported("restore")
}
