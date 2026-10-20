package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sricharanenabothula704-star/hydra/internal/audit"
	"github.com/sricharanenabothula704-star/hydra/internal/config"
	"github.com/sricharanenabothula704-star/hydra/internal/gates"
	"github.com/sricharanenabothula704-star/hydra/internal/pybridge"
)

// extractTarget finds a --target/--url value in a raw arg list (flags unparsed).
func extractTarget(args []string) (string, bool) {
	for i, a := range args {
		if a == "--target" || a == "--url" {
			if i+1 < len(args) {
				return args[i+1], true
			}
		}
		if v, ok := strings.CutPrefix(a, "--target="); ok {
			return v, true
		}
		if v, ok := strings.CutPrefix(a, "--url="); ok {
			return v, true
		}
	}
	return "", false
}

// gate runs the scope gate for a target, audits the decision, and prints the
// banner. It returns false (and the caller must abort) on deny.
func gate(cmd *cobra.Command, action, target string) bool {
	d := gates.CheckScope(target)
	_ = audit.Scope(action, target, d.Allowed, d.Reason)
	out := cmd.OutOrStdout()
	if d.Allowed {
		fmt.Fprintf(out, "[SCOPE-ALLOW] %s\n", d.Target)
		_ = audit.Run(action, target)
		return true
	}
	fmt.Fprintf(out, "[SCOPE-DENY] %s\n%s\n", d.Target, firstLine(d.Reason))
	return false
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// runBackend bridges to `python -m hydra <args>` and maps a non-zero exit to an
// error so the CLI exit code is faithful.
func runBackend(cmd *cobra.Command, args ...string) error {
	root, err := config.RepoRoot()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Minute)
	defer cancel()
	code, err := pybridge.Run(ctx, root, cmd.OutOrStdout(), cmd.ErrOrStderr(), args...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("hydra %s exited with code %d", args[0], code)
	}
	return nil
}

// newHuntCmd: scope-gated hunt that drives the backend.
func newHuntCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "hunt <target> [backend args…]",
		Short:              "Scope-gated hunt (fails closed if target is out of scope)",
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !gate(cmd, "hunt", args[0]) {
				return errDenied
			}
			return runBackend(cmd, append([]string{"hunt"}, args...)...)
		},
	}
}

// newScanCmd: scope-gated scan.
func newScanCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "scan <url>",
		Short:              "Scope-gated security-misconfiguration scan",
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !gate(cmd, "scan", args[0]) {
				return errDenied
			}
			return runBackend(cmd, append([]string{"scan"}, args...)...)
		},
	}
}

// newBridgedCmd wraps a backend command. If gateTargets is set, any
// --target/--url value in the args is scope-checked first (fails closed).
func newBridgedCmd(name, short string, gateTargets bool) *cobra.Command {
	return &cobra.Command{
		Use:                name + " [args…]",
		Short:              short,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if gateTargets {
				if t, ok := extractTarget(args); ok {
					if !gate(cmd, name, t) {
						return errDenied
					}
				}
			}
			return runBackend(cmd, append([]string{name}, args...)...)
		},
	}
}

// backendCommands returns the parity commands that bridge to the Python engine.
func backendCommands() []*cobra.Command {
	return []*cobra.Command{
		newHuntCmd(),
		newScanCmd(),
		newBridgedCmd("validate", "Run the 7-question validation gate on a finding", false),
		newBridgedCmd("chains", "List or run attack chains (run --target is gated)", true),
		newBridgedCmd("pipeline", "List or run pipelines (run --target is gated)", true),
		newBridgedCmd("history", "Show session history", false),
		newBridgedCmd("stats", "Show engine stats (autopilot, validation, exploits)", false),
		newBridgedCmd("skills", "Route/search Hydra skills", false),
	}
}
