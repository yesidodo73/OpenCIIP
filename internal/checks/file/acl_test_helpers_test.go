package filecheck

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

func mustTestPOSIXACLXAttr(t *testing.T, content string) []byte {
	t.Helper()
	const undefinedID = uint32(0xffffffff)
	type entry struct {
		tag   uint16
		perms uint16
		id    uint32
	}
	entries := make([]entry, 0, 8)
	for lineNumber, raw := range strings.Split(strings.TrimSpace(content), "\n") {
		fields := strings.Split(strings.TrimSpace(raw), ":")
		if len(fields) != 3 {
			t.Fatalf("ACL line %d has %d fields: %q", lineNumber+1, len(fields), raw)
		}
		item := entry{id: undefinedID}
		switch fields[0] {
		case "user":
			if fields[1] == "" {
				item.tag = 0x01
			} else {
				item.tag = 0x02
			}
		case "group":
			if fields[1] == "" {
				item.tag = 0x04
			} else {
				item.tag = 0x08
			}
		case "mask":
			item.tag = 0x10
		case "other":
			item.tag = 0x20
		default:
			t.Fatalf("ACL line %d has unsupported tag %q", lineNumber+1, fields[0])
		}
		if fields[1] != "" {
			identifier, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				t.Fatalf("ACL line %d identifier: %v", lineNumber+1, err)
			}
			item.id = uint32(identifier)
		}
		for _, character := range fields[2] {
			switch character {
			case 'r':
				item.perms |= 0o4
			case 'w':
				item.perms |= 0o2
			case 'x':
				item.perms |= 0o1
			case '-':
			default:
				t.Fatalf("ACL line %d has invalid permission %q", lineNumber+1, character)
			}
		}
		entries = append(entries, item)
	}
	encoded := make([]byte, 4+8*len(entries))
	binary.LittleEndian.PutUint32(encoded[:4], 2)
	for index, item := range entries {
		offset := 4 + index*8
		binary.LittleEndian.PutUint16(encoded[offset:offset+2], item.tag)
		binary.LittleEndian.PutUint16(encoded[offset+2:offset+4], item.perms)
		binary.LittleEndian.PutUint32(encoded[offset+4:offset+8], item.id)
	}
	return encoded
}
