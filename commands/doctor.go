package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sricharanenabothula704-star/hydra/internal/config"
)

// newDoctorCmd runs a pre-flight check of hydra's environment. It never
// contacts a target. Each check prints OK / WARN / FAIL with a hint.
func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Pre-flight environment and safety-gate checks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ok := true

			// opencode binary present?
			if p, err := exec.LookPath("opencode"); err == nil {
				fmt.Fprintf(out, "[ OK ] opencode found: %s\n", p)
			} else {
				ok = false
				fmt.Fprintln(out, "[FAIL] opencode not found on PATH (install opencode first)")
			}

			// repo root / scope gate present?
			root, err := config.RepoRoot()
			if err != nil {
				ok = false
				fmt.Fprintf(out, "[FAIL] %v\n", err)
			} else {
				fmt.Fprintf(out, "[ OK ] hydra repo: %s\n", root)
				script := config.ScopeCheckScript(root)
				if st, serr := os.Stat(script); serr == nil && !st.IsDir() {
					fmt.Fprintf(out, "[ OK ] scope gate: %s\n", script)
				} else {
					ok = false
					fmt.Fprintf(out, "[FAIL] scope gate missing: %s\n", script)
				}
			}

			// bash available for the gate?
			if _, berr := exec.LookPath("bash"); berr == nil {
				fmt.Fprintln(out, "[ OK ] bash available for scope gate")
			} else {
				fmt.Fprintln(out, "[WARN] bash not on PATH; scope gate needs Git Bash/WSL on Windows")
			}

			// allowlist present and non-empty?
			al := config.AllowlistPath()
			if st, aerr := os.Stat(al); aerr == nil && st.Size() > 0 {
				fmt.Fprintf(out, "[ OK ] scope allowlist: %s\n", al)
			} else {
				fmt.Fprintf(out, "[WARN] scope allowlist empty/missing: %s\n", al)
				fmt.Fprintln(out, "       Add your authorized program domains, one per line, before hunting.")
			}

			// Python backend reachable (for commands still bridged to it)?
			if root != "" {
				if _, perr := os.Stat(filepath.Join(root, "__main__.py")); perr == nil {
					fmt.Fprintln(out, "[ OK ] Python backend present (hydra package)")
				} else {
					fmt.Fprintln(out, "[WARN] Python backend (__main__.py) not found in repo root")
				}
			}

			fmt.Fprintln(out)
			if ok {
				fmt.Fprintln(out, "doctor: ready")
				return nil
			}
			fmt.Fprintln(out, "doctor: issues found (see FAIL lines above)")
			return errDoctor
		},
	}
}

type doctorError struct{}

func (doctorError) Error() string { return "doctor found blocking issues" }

var errDoctor = doctorError{}
