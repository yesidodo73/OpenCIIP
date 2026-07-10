package regularfile

import (
	"testing"
	"time"

	"github.com/yesidodo73/OpenCIIP/internal/model"
)

func TestMetadataTransitionCandidate(t *testing.T) {
	before := metadataTransitionSnapshot()
	desired := cloneResourceSnapshot(before)
	desired.File.UID = 2000
	desired.File.GID = 3000
	desired.File.Mode = 0o600
	desiredWithDifferentInode := cloneResourceSnapshot(desired)
	desiredWithDifferentInode.File.Inode++

	tests := []struct {
		name     string
		desired  model.ResourceSnapshot
		observed model.ResourceSnapshot
		want     bool
	}{
		{
			name:     "exact before state",
			desired:  desired,
			observed: cloneResourceSnapshot(before),
			want:     true,
		},
		{
			name:     "exact desired state",
			desired:  desired,
			observed: cloneResourceSnapshot(desired),
			want:     true,
		},
		{
			name:    "mode changed after ownership remains before",
			desired: desired,
			observed: mutateResourceSnapshot(before, func(file *model.FileSnapshot) {
				file.Mode = desired.File.Mode
			}),
			want: true,
		},
		{
			name:    "ownership changed while mode remains before",
			desired: desired,
			observed: mutateResourceSnapshot(before, func(file *model.FileSnapshot) {
				file.UID = desired.File.UID
				file.GID = desired.File.GID
			}),
			want: true,
		},
		{
			name:    "desired UID mixed with before GID",
			desired: desired,
			observed: mutateResourceSnapshot(before, func(file *model.FileSnapshot) {
				file.UID = desired.File.UID
			}),
			want: false,
		},
		{
			name:    "before UID mixed with desired GID",
			desired: desired,
			observed: mutateResourceSnapshot(before, func(file *model.FileSnapshot) {
				file.GID = desired.File.GID
			}),
			want: false,
		},
		{
			name:    "mode outside before and desired",
			desired: desired,
			observed: mutateResourceSnapshot(before, func(file *model.FileSnapshot) {
				file.Mode = 0o640
			}),
			want: false,
		},
		{
			name:    "observed immutable content changed",
			desired: desired,
			observed: mutateResourceSnapshot(before, func(file *model.FileSnapshot) {
				file.SHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			}),
			want: false,
		},
		{
			name:     "desired immutable inode changed",
			desired:  desiredWithDifferentInode,
			observed: cloneResourceSnapshot(before),
			want:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := MetadataTransitionCandidate(before, test.desired, test.observed); got != test.want {
				t.Fatalf("MetadataTransitionCandidate() = %t, want %t", got, test.want)
			}
		})
	}
}

func metadataTransitionSnapshot() model.ResourceSnapshot {
	resource := model.CanonicalResource{
		Reference: model.ResourceRef{Kind: model.ResourceFile, ID: "/etc/example.conf"},
		Key:       "file:/etc/example.conf",
	}
	return model.ResourceSnapshot{
		Reference:   resource,
		Fingerprint: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		File: &model.FileSnapshot{
			Path:           "/etc/example.conf",
			Exists:         true,
			FileType:       "regular",
			Mode:           0o664,
			UID:            1000,
			GID:            1000,
			Size:           7,
			SHA256:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			Device:         11,
			Inode:          22,
			NLink:          1,
			ParentDevice:   11,
			ParentInode:    21,
			XAttrDigest:    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			ACLDigest:      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
			SELinuxContext: "system_u:object_r:etc_t:s0",
			MetadataDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			CapturedAt:     time.Unix(1, 0).UTC(),
		},
	}
}

func cloneResourceSnapshot(snapshot model.ResourceSnapshot) model.ResourceSnapshot {
	cloned := snapshot
	if snapshot.File != nil {
		file := *snapshot.File
		cloned.File = &file
	}
	return cloned
}

func mutateResourceSnapshot(snapshot model.ResourceSnapshot, mutate func(*model.FileSnapshot)) model.ResourceSnapshot {
	cloned := cloneResourceSnapshot(snapshot)
	mutate(cloned.File)
	return cloned
}
