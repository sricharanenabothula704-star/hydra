// Command hydra is the single cross-platform entrypoint for the HYDRA
// AI bug-bounty system. It replaces the legacy `python -m hydra` UX while
// delegating safety enforcement to the repo's deterministic scope gate.
package main

import (
	"fmt"
	"os"

	"github.com/sricharanenabothula704-star/hydra/commands"
)

func main() {
	if err := commands.NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "hydra:", err)
		os.Exit(1)
	}
}
