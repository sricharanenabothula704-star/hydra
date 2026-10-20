// Package version carries build-time version information for the hydra binary.
package version

// These are overridden at build time via -ldflags "-X ...".
var (
	Version = "0.3.0-dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a human-readable version line.
func String() string {
	return "hydra " + Version + " (" + Commit + ", " + Date + ")"
}
