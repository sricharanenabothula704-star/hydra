package commands

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sricharanenabothula704-star/hydra/internal/gates"
)

// newGuardCmd mirrors the legacy `hydra guard <url>`: it reports the scope
// decision for a target without contacting it. Exit code is 0 on ALLOW and
// non-zero on DENY so it is usable as a shell precondition.
func newGuardCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "guard <url-or-domain>",
		Short: "Show the scope decision for a target (no network contact)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d := gates.CheckScope(args[0])
			if asJSON {
				out, _ := json.MarshalIndent(map[string]any{
					"target":  d.Target,
					"allowed": d.Allowed,
					"reason":  d.Reason,
				}, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
			} else if d.Allowed {
				fmt.Fprintf(cmd.OutOrStdout(), "[SCOPE-ALLOW] %s\n%s\n", d.Target, d.Reason)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "[SCOPE-DENY] %s\n%s\n", d.Target, d.Reason)
			}
			if !d.Allowed {
				// Non-zero exit without a usage dump.
				return errDenied
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the decision as JSON")
	return cmd
}

type deniedError struct{}

func (deniedError) Error() string { return "scope denied" }

var errDenied = deniedError{}
