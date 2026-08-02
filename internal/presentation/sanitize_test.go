package presentation

import (
	"strings"
	"testing"
	"unicode"
)

func TestSanitizeNeutralizesTerminalAndDirectionalControls(t *testing.T) {
	t.Parallel()

	input := "앞\t열\r\n다음\x00\x07\x1b[31m\x7f\u0085\u009b31m\u2028줄\u2029문단\u202e숨김\u2066끝\u2069"
	output := Sanitize(input)
	for _, character := range output {
		if character == '\n' || character == '\t' {
			continue
		}
		if character < 0x20 || character == 0x7f ||
			(character >= 0x80 && character <= 0x9f) ||
			unicode.Is(unicode.Cf, character) ||
			unicode.Is(unicode.Zl, character) ||
			unicode.Is(unicode.Zp, character) {
			t.Fatalf("Sanitize() retained U+%04X in %q", character, output)
		}
	}
	for _, expected := range []string{
		"앞\t열\n다음",
		"<U+0000>",
		"<U+0007>",
		"<U+001B>[31m",
		"<U+007F>",
		"<U+0085>",
		"<U+009B>31m",
		"<U+2028>줄<U+2029>문단",
		"<U+202E>숨김",
		"<U+2066>끝<U+2069>",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("Sanitize() lacks %q: %q", expected, output)
		}
	}
}

func TestSanitizeLeavesOrdinaryUnicodeAndStructureUnchanged(t *testing.T) {
	t.Parallel()

	input := "Rocky Linux 9.8\n확인 결과:\t양호 ✅"
	if output := Sanitize(input); output != input {
		t.Fatalf("Sanitize() = %q, want %q", output, input)
	}
}
