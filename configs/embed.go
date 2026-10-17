// Package configs contains the default configuration embedded at build time.
package configs

import _ "embed"

// Defaults is the YAML configuration bundled with the executable.
//
//go:embed default.yaml
var Defaults string
