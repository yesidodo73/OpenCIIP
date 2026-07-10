package remediationdata

import "embed"

// FS contains built-in, guide-backed remediation recipes. These recipes
// describe changes only; they never constitute user approval.
//
//go:embed 2026/unix/*.yaml
var FS embed.FS
