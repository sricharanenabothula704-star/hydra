// Package commands defines the hydra CLI surface. With no subcommand, hydra
// launches its interactive TUI; subcommands provide scriptable parity with the
// legacy `python -m hydra` entrypoint.
package commands

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/sricharanenabothula704-star/hydra/internal/config"
	"github.com/sricharanenabothula704-star/hydra/internal/tui"
	"github.com/sricharanenabothula704-star/hydra/internal/version"
)

// NewRootCmd builds the root command tree.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "hydra",
		Short: "HYDRA — AI bug-bounty system (authorized testing only)",
		Long: "HYDRA drives opencode for authorized security testing.\n" +
			"Run with no arguments to launch the interactive TUI, or use a\n" +
			"subcommand for scriptable operations. Every target-touching action\n" +
			"is gated by scripts/scope_check.sh and fails closed.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.String(),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Send spawned-server logs to a file so they never corrupt the TUI.
			var logs *os.File
			if dir := config.HydraConfigDir(); dir != "" {
				_ = os.MkdirAll(dir, 0o755)
				logs, _ = os.OpenFile(filepath.Join(dir, "opencode-serve.log"),
					os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
			}
			if logs != nil {
				defer logs.Close()
			}
			return tui.RunWithConfig(tui.Config{
				Server:   os.Getenv("OPENCODE_SERVER"),
				Username: "opencode",
				Password: os.Getenv("OPENCODE_SERVER_PASSWORD"),
				Logs:     logs,
			})
		},
	}

	// version.String already carries the program name, so print it verbatim
	// instead of cobra's default "hydra version <x>" template.
	root.SetVersionTemplate("{{.Version}}\n")

	root.AddCommand(
		newGuardCmd(),
		newDoctorCmd(),
		newStatusCmd(),
		newOcCmd(),
		newProvidersCmd(),
	)
	root.AddCommand(backendCommands()...)
	return root
}
