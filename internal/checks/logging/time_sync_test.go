package logging

import (
	"slices"
	"testing"
)

func TestParseChronySourcesCSVPreservesOriginalRuntimeNames(t *testing.T) {
	data := []byte("^,-,2.rocky.pool.ntp.org,2,9,377,685,-0.1,-0.1,0.2\n" +
		"^,*,approved.example,2,7,377,12,0.0,0.0,0.1\n")
	sources, selected, err := parseChronySourcesCSV(data)
	if err != nil {
		t.Fatalf("parseChronySourcesCSV() error = %v", err)
	}
	if !slices.Equal(sources, []string{"2.rocky.pool.ntp.org", "approved.example"}) || !slices.Equal(selected, []string{"approved.example"}) {
		t.Fatalf("parseChronySourcesCSV() = %#v, %#v", sources, selected)
	}
}

func TestParseChronySourcesCSVRejectsMalformedRows(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("^,*\n"),
		[]byte("?,*,source.example\n"),
		[]byte("^,**,source.example\n"),
	} {
		if _, _, err := parseChronySourcesCSV(data); err == nil {
			t.Fatalf("parseChronySourcesCSV(%q) accepted malformed data", data)
		}
	}
}
