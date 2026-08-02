package presentation

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sanitize neutralizes terminal control and directional formatting characters
// while preserving line feeds and tabs used by human-readable output.
func Sanitize(value string) string {
	var builder strings.Builder
	changed := false
	for index := 0; index < len(value); {
		if value[index] == '\r' && index+1 < len(value) && value[index+1] == '\n' {
			if !changed {
				builder.Grow(len(value))
				builder.WriteString(value[:index])
				changed = true
			}
			builder.WriteByte('\n')
			index += 2
			continue
		}

		character, size := utf8.DecodeRuneInString(value[index:])
		if allowedPresentationRune(character) && !(character == utf8.RuneError && size == 1) {
			if changed {
				builder.WriteString(value[index : index+size])
			}
		} else {
			if !changed {
				builder.Grow(len(value) + 16)
				builder.WriteString(value[:index])
				changed = true
			}
			writeEscapedRune(&builder, character)
		}
		index += size
	}
	if !changed {
		return value
	}
	return builder.String()
}

func allowedPresentationRune(character rune) bool {
	if character == '\n' || character == '\t' {
		return true
	}
	if character < 0x20 || character == 0x7f ||
		(character >= 0x80 && character <= 0x9f) {
		return false
	}
	return !unicode.Is(unicode.Cf, character) &&
		!unicode.Is(unicode.Zl, character) &&
		!unicode.Is(unicode.Zp, character)
}

func writeEscapedRune(builder *strings.Builder, character rune) {
	builder.WriteString("<U+")
	hexadecimal := strings.ToUpper(strconv.FormatInt(int64(character), 16))
	for padding := 4 - len(hexadecimal); padding > 0; padding-- {
		builder.WriteByte('0')
	}
	builder.WriteString(hexadecimal)
	builder.WriteByte('>')
}
