package platform

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/yesidodo73/OpenCIIP/internal/system"
)

type detectorReader struct {
	files        map[string][]byte
	readErrors   map[string]error
	exists       map[string]bool
	existsErrors map[string]error
}

func (r *detectorReader) ReadFile(_ context.Context, path string, _ int64) ([]byte, system.FileMetadata, error) {
	if err := r.readErrors[path]; err != nil {
		return nil, system.FileMetadata{}, err
	}
	data, ok := r.files[path]
	if !ok {
		return nil, system.FileMetadata{}, os.ErrNotExist
	}
	return append([]byte(nil), data...), system.FileMetadata{Path: path}, nil
}

func (*detectorReader) Stat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("not implemented by detector test reader")
}

func (*detectorReader) Lstat(string) (system.FileMetadata, error) {
	return system.FileMetadata{}, errors.New("not implemented by detector test reader")
}

func (*detectorReader) ReadDir(string) ([]os.DirEntry, error) {
	return nil, errors.New("not implemented by detector test reader")
}

func (r *detectorReader) Exists(path string) (bool, error) {
	if err := r.existsErrors[path]; err != nil {
		return false, err
	}
	return r.exists[path], nil
}

func TestParseOSReleaseAcceptsSupportedQuotingAndEscapes(t *testing.T) {
	data := []byte("# generated fixture\r\n" +
		"ID=ROCKY\r\n" +
		"NAME='Rocky\\Linux'\r\n" +
		"PRETTY_NAME=\"Rocky \\\"Linux\\\" \\\\ Edition \\$HOME \\`tag\\` \\q\"\r\n" +
		"VERSION_ID=9.8\r\n" +
		"VERSION_CODENAME=blue\\\\moon\r\n" +
		"ID_LIKE=\"rhel fedora\"\r\n")

	values, err := parseOSRelease(data)
	if err != nil {
		t.Fatalf("parseOSRelease() error = %v", err)
	}

	want := map[string]string{
		"ID":               "ROCKY",
		"NAME":             `Rocky\Linux`,
		"PRETTY_NAME":      "Rocky \"Linux\" \\ Edition $HOME `tag` \\q",
		"VERSION_ID":       "9.8",
		"VERSION_CODENAME": `blue\moon`,
		"ID_LIKE":          "rhel fedora",
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("parseOSRelease() = %#v, want %#v", values, want)
	}
}

func TestParseOSReleaseRejectsMalformedOrMissingID(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "missing equals", data: "ID\n"},
		{name: "invalid lowercase key", data: "id=rocky\n"},
		{name: "missing id", data: "NAME=Rocky\n"},
		{name: "empty id", data: "ID=\"\"\n"},
		{name: "unterminated single quote", data: "ID='rocky\n"},
		{name: "unterminated double quote", data: "ID=\"rocky\n"},
		{name: "trailing double quote escape", data: "ID=\"rocky\\\"\n"},
		{name: "unquoted whitespace", data: "ID=rocky linux\n"},
		{name: "unquoted quote", data: "ID=rocky'linux\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseOSRelease([]byte(test.data)); err == nil {
				t.Fatal("parseOSRelease() error = nil, want rejection")
			}
		})
	}
}

func TestDetectFamilyUsesDistributionFactsOnly(t *testing.T) {
	tests := []struct {
		name   string
		id     string
		idLike string
		want   string
	}{
		{name: "rocky", id: "rocky", want: "rhel"},
		{name: "rhel compatible", id: "custom", idLike: "rhel fedora", want: "rhel"},
		{name: "ubuntu", id: "ubuntu", idLike: "debian", want: "debian"},
		{name: "sles compatible", id: "custom", idLike: "sles suse", want: "suse"},
		{name: "alpine", id: "alpine", want: "alpine"},
		{name: "unknown", id: "custom", idLike: "independent", want: "unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := detectFamily(test.id, test.idLike); got != test.want {
				t.Fatalf("detectFamily(%q, %q) = %q, want %q", test.id, test.idLike, got, test.want)
			}
		})
	}
}

func TestDetectorRefineCentOSVersionID(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		versionID string
		release   string
		want      string
	}{
		{
			name:      "CentOS Linux point release",
			id:        "centos",
			versionID: "8",
			release:   "CentOS Linux release 8.5.2111\n",
			want:      "8.5.2111",
		},
		{
			name:      "CentOS Stream is not treated as a point release",
			id:        "centos",
			versionID: "8",
			release:   "CentOS Stream release 8\n",
			want:      "8",
		},
		{
			name:      "major mismatch is rejected",
			id:        "centos",
			versionID: "8",
			release:   "CentOS Linux release 7.9.2009\n",
			want:      "8",
		},
		{
			name:      "malformed point release is rejected",
			id:        "centos",
			versionID: "8",
			release:   "CentOS Linux release 8.5\n",
			want:      "8",
		},
		{
			name:      "other distributions are unchanged",
			id:        "rocky",
			versionID: "9.8",
			release:   "CentOS Linux release 8.5.2111\n",
			want:      "9.8",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &detectorReader{files: map[string][]byte{
				"/etc/centos-release": []byte(test.release),
			}}
			got := NewDetector(reader).refineCentOSVersionID(
				context.Background(),
				test.id,
				test.versionID,
			)
			if got != test.want {
				t.Fatalf("refineCentOSVersionID() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDetectorRefineCentOSVersionIDKeepsMajorWhenReleaseFileIsUnavailable(t *testing.T) {
	reader := &detectorReader{readErrors: map[string]error{
		"/etc/centos-release": os.ErrNotExist,
	}}
	got := NewDetector(reader).refineCentOSVersionID(context.Background(), "centos", "8")
	if got != "8" {
		t.Fatalf("refineCentOSVersionID() = %q, want %q", got, "8")
	}
}

func TestDetectorDetectInitUsesPathThenPID1Fact(t *testing.T) {
	tests := []struct {
		name         string
		reader       *detectorReader
		want         string
		wantWarnings int
	}{
		{
			name:   "systemd runtime path",
			reader: &detectorReader{exists: map[string]bool{"/run/systemd/system": true}},
			want:   "systemd",
		},
		{
			name: "sysv init from pid one",
			reader: &detectorReader{
				files:  map[string][]byte{"/proc/1/comm": []byte("init\n")},
				exists: map[string]bool{"/run/systemd/system": false},
			},
			want: "sysvinit",
		},
		{
			name: "custom pid one with path inspection warning",
			reader: &detectorReader{
				files:        map[string][]byte{"/proc/1/comm": []byte("s6-svscan\n")},
				existsErrors: map[string]error{"/run/systemd/system": errors.New("permission denied")},
			},
			want:         "s6-svscan",
			wantWarnings: 1,
		},
		{
			name: "unknown when pid one cannot be read",
			reader: &detectorReader{
				readErrors: map[string]error{"/proc/1/comm": errors.New("unavailable")},
				exists:     map[string]bool{"/run/systemd/system": false},
			},
			want:         "unknown",
			wantWarnings: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector := NewDetector(test.reader)
			got, warnings := detector.detectInit(context.Background(), nil)
			if got != test.want {
				t.Fatalf("detectInit() = %q, want %q", got, test.want)
			}
			if len(warnings) != test.wantWarnings {
				t.Fatalf("detectInit() warnings = %#v, want %d warning(s)", warnings, test.wantWarnings)
			}
		})
	}
}

func TestDetectorDetectPackageManagerUsesExecutablePathPrecedence(t *testing.T) {
	tests := []struct {
		name   string
		reader *detectorReader
		want   string
	}{
		{
			name: "dnf before lower priority candidates",
			reader: &detectorReader{exists: map[string]bool{
				"/usr/bin/dnf":     true,
				"/usr/bin/rpm":     true,
				"/usr/bin/apt-get": true,
			}},
			want: "dnf",
		},
		{
			name:   "rpm fallback",
			reader: &detectorReader{exists: map[string]bool{"/usr/bin/rpm": true}},
			want:   "rpm",
		},
		{
			name: "continue after inspection error",
			reader: &detectorReader{
				exists:       map[string]bool{"/sbin/apk": true},
				existsErrors: map[string]error{"/usr/bin/dnf": errors.New("permission denied")},
			},
			want: "apk",
		},
		{
			name:   "unknown without a candidate",
			reader: &detectorReader{},
			want:   "unknown",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			detector := NewDetector(test.reader)
			if got := detector.detectPackageManager(); got != test.want {
				t.Fatalf("detectPackageManager() = %q, want %q", got, test.want)
			}
		})
	}
}
