package commands

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sricharanenabothula704-star/hydra/internal/config"
	"github.com/sricharanenabothula704-star/hydra/internal/version"
)

// newStatusCmd prints a concise summary of the hydra install.
func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show hydra version and environment summary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, version.String())
			if root, err := config.RepoRoot(); err == nil {
				fmt.Fprintf(out, "repo:      %s\n", root)
			} else {
				fmt.Fprintf(out, "repo:      (not found: %v)\n", err)
			}
			fmt.Fprintf(out, "allowlist: %s\n", config.AllowlistPath())
			return nil
		},
	}
}
