// Package gates bridges the Go front-end to Hydra's existing deterministic
// safety enforcement. The single source of truth for scope decisions is the
// repository's scripts/scope_check.sh. This package NEVER re-decides scope in
// Go; it only runs the real gate and reports its verdict.
//
// Fail-closed contract: every error path — missing repo, missing script,
// missing shell interpreter, timeout, or any non-zero/garbled result — is
// treated as DENY. There is no code path that turns an error into ALLOW.
package gates

import (
	"bytes"
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/sricharanenabothula704-star/hydra/internal/config"
)

// Decision is the verdict from the scope gate.
type Decision struct {
	Allowed bool   // true ONLY when the gate explicitly passed (exit 0)
	Reason  string // the gate's own PASS/DENY explanation, or the failure cause
	Target  string // the target that was checked
}

// Denied builds a fail-closed denial with the given reason.
func denied(target, reason string) Decision {
	return Decision{Allowed: false, Reason: reason, Target: target}
}

// defaultTimeout bounds how long the gate may run before we fail closed.
// Generous headroom so a slow host or a large allowlist never produces a
// false DENY; the gate itself should complete in well under a second.
const defaultTimeout = 30 * time.Second

// CheckScope runs scripts/scope_check.sh against target and returns its verdict.
// An empty target is denied. Any failure to run the gate is denied.
func CheckScope(target string) Decision {
	return checkScopeCtx(context.Background(), target)
}

func checkScopeCtx(parent context.Context, target string) Decision {
	target = strings.TrimSpace(target)
	if target == "" {
		return denied(target, "no target supplied")
	}

	root, err := config.RepoRoot()
	if err != nil {
		return denied(target, "cannot locate scope gate: "+err.Error())
	}
	script := config.ScopeCheckScript(root)

	bash, err := findBash()
	if err != nil {
		return denied(target, "cannot run scope gate: "+err.Error())
	}

	ctx, cancel := context.WithTimeout(parent, defaultTimeout)
	defer cancel()

	// Pass the script path and target as separate argv entries; never build a
	// shell string, so the target can never be interpreted as a command.
	cmd := exec.CommandContext(ctx, bash, script, target)
	cmd.Dir = root
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()

	reason := strings.TrimSpace(out.String())
	if reason == "" {
		reason = "scope gate produced no output"
	}

	if ctx.Err() == context.DeadlineExceeded {
		return denied(target, "scope gate timed out")
	}
	if runErr != nil {
		// Non-zero exit (the script's DENY path) or a spawn failure. Either
		// way we deny, surfacing the gate's own message.
		return denied(target, reason)
	}

	// Exit 0. Trust the gate: it passed.
	return Decision{Allowed: true, Reason: reason, Target: target}
}

// findBash locates a bash interpreter. scope_check.sh is a bash script; on
// Windows this resolves Git Bash / WSL bash from PATH.
func findBash() (string, error) {
	candidates := []string{"bash"}
	if runtime.GOOS == "windows" {
		candidates = append(candidates,
			`C:\Program Files\Git\bin\bash.exe`,
			`C:\Program Files\Git\usr\bin\bash.exe`,
		)
	}
	for _, c := range candidates {
		if p, err := exec.LookPath(c); err == nil {
			return p, nil
		}
		// Absolute candidate that LookPath rejected (no PATH entry) — probe directly.
		if strings.ContainsAny(c, `\/`) {
			if _, err := exec.Command(c, "-c", "exit 0").Output(); err == nil {
				return c, nil
			}
		}
	}
	return "", errNoBash
}

type noBashError struct{}

func (noBashError) Error() string {
	return "no bash interpreter found in PATH (required to run the scope gate)"
}

var errNoBash = noBashError{}
