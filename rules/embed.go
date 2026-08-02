// Package ruledata contains the versioned rule catalog, profiles, and platform bindings.
package ruledata

import "embed"

// FS contains immutable default rules shipped with the OpenCIIP binary.
//
//go:embed 2026/unix/catalog.yaml profiles/2026-unix.yaml platforms/*.yaml
var FS embed.FS
