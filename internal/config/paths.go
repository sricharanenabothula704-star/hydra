// Package config resolves the filesystem locations hydra depends on:
// the Hydra repo root (which holds scripts/scope_check.sh and the Python
// backend), the opencode config, and the scope allowlist.
package config

import (
	"os"
	"path/filepath"
)

// markers are paths that, present together, uniquely identify the root of a
// Hydra checkout. A single file (e.g. a stray scripts/scope_check.sh copied
// into a home directory) must NOT be enough to pass as the repo, or hydra
// could run the wrong gate against the wrong allowlist.
var markers = []string{
	"scripts/scope_check.sh",
	"opencode.jsonc.template",
	"__main__.py",
}

// RepoRoot locates the Hydra repository root.
//
// Resolution order:
//  1. $HYDRA_HOME, if it points at a real Hydra checkout.
//  2. Walking up from the current working directory.
//  3. Walking up from the directory of the running executable.
//
// It returns an error if no checkout can be found, because core safety
// enforcement (scope_check.sh) lives there and callers must fail closed.
func RepoRoot() (string, error) {
	if home := os.Getenv("HYDRA_HOME"); home != "" {
		if isRepo(home) {
			return home, nil
		}
	}
	if cwd, err := os.Getwd(); err == nil {
		if root, ok := walkUp(cwd); ok {
			return root, nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		if root, ok := walkUp(filepath.Dir(exe)); ok {
			return root, nil
		}
	}
	return "", &NotFoundError{}
}

// NotFoundError is returned when the Hydra repo root cannot be located.
type NotFoundError struct{}

func (*NotFoundError) Error() string {
	return "hydra repo root not found (set HYDRA_HOME to your hydra checkout; it must contain " + markers[0] + ", " + markers[1] + " and " + markers[2] + ")"
}

func isRepo(dir string) bool {
	for _, m := range markers {
		st, err := os.Stat(filepath.Join(dir, m))
		if err != nil || st.IsDir() {
			return false
		}
	}
	return true
}

func walkUp(start string) (string, bool) {
	dir := start
	for {
		if isRepo(dir) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// ScopeCheckScript returns the absolute path to the scope-gate shell script.
func ScopeCheckScript(repoRoot string) string {
	return filepath.Join(repoRoot, "scripts", "scope_check.sh")
}

// AllowlistPath returns the path to the scope allowlist that scope_check.sh reads.
// This mirrors the script's own default: ~/.config/opencode/SCOPE_ALLOWLIST.txt.
func AllowlistPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return filepath.Join(home, ".config", "opencode", "SCOPE_ALLOWLIST.txt")
}

// OpencodeConfigPath returns the project-level opencode config inside the repo.
// hydra writes provider entries here; opencode also honours ~/.config/opencode.
func OpencodeConfigPath(repoRoot string) string {
	return filepath.Join(repoRoot, "opencode.json")
}

// HydraConfigDir returns hydra's own per-user config directory.
func HydraConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", "hydra")
}
