// Package pybridge runs the Python Hydra backend (`python -m hydra …`) that
// still holds the engine logic (autopilot, pipelines, attack chains, the
// validation gate). The Go CLI is the single entrypoint; for these commands it
// shells to Python until that logic is ported.
package pybridge

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
)

// pythonCandidates are tried in order to find an interpreter.
var pythonCandidates = []string{"python", "python3", "py"}

// FindPython returns the first available Python interpreter.
func FindPython() (string, error) {
	for _, c := range pythonCandidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no python interpreter found on PATH (need python/python3/py for the hydra backend)")
}

// Run executes `python -m hydra <args>` with the working directory set to the
// parent of repoRoot (so the `hydra` package is importable). stdout/stderr are
// streamed to the provided writers. It returns the process exit code.
//
// NOTE: not run with -I, because the backend is the user's own package and must
// import from the repo; callers pass only trusted argument values.
func Run(ctx context.Context, repoRoot string, stdout, stderr io.Writer, args ...string) (int, error) {
	py, err := FindPython()
	if err != nil {
		return 127, err
	}
	full := append([]string{"-m", "hydra"}, args...)
	cmd := exec.CommandContext(ctx, py, full...)
	cmd.Dir = filepath.Dir(repoRoot) // parent, so `import hydra` resolves
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), nil
		}
		return 1, err
	}
	return 0, nil
}
