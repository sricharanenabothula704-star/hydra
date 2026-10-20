package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/sricharanenabothula704-star/hydra/internal/config"
	"github.com/sricharanenabothula704-star/hydra/internal/opencode"
)

// newOcCmd groups low-level opencode-server commands used to drive and inspect
// a running `opencode serve`. These are the plumbing the TUI builds on.
func newOcCmd() *cobra.Command {
	var server, password, username string
	oc := &cobra.Command{
		Use:   "oc",
		Short: "Talk to the opencode server (info/providers/models/sessions)",
	}
	oc.PersistentFlags().StringVar(&server, "server", "", "attach to an existing opencode server URL (else spawn one)")
	oc.PersistentFlags().StringVar(&password, "password", os.Getenv("OPENCODE_SERVER_PASSWORD"), "server basic-auth password")
	oc.PersistentFlags().StringVar(&username, "username", "opencode", "server basic-auth username")

	// connect resolves a Server: attach to --server, or spawn one in the repo.
	connect := func(ctx context.Context) (*opencode.Server, func(), error) {
		if server != "" {
			s := opencode.Attach(server, username, password)
			if _, err := s.Client.Info(ctx); err != nil {
				return nil, func() {}, fmt.Errorf("attach %s: %w", server, err)
			}
			return s, func() {}, nil
		}
		root, err := config.RepoRoot()
		if err != nil {
			return nil, func() {}, err
		}
		s, err := opencode.Spawn(ctx, opencode.SpawnConfig{Dir: root})
		if err != nil {
			return nil, func() {}, err
		}
		return s, func() { _ = s.Stop() }, nil
	}

	runWith := func(fn func(ctx context.Context, s *opencode.Server, out *cobra.Command) error) func(*cobra.Command, []string) error {
		return func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			s, cleanup, err := connect(ctx)
			if err != nil {
				return err
			}
			defer cleanup()
			return fn(ctx, s, cmd)
		}
	}

	printJSON := func(cmd *cobra.Command, v any) {
		b, _ := json.MarshalIndent(v, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(b))
	}

	infoCmd := &cobra.Command{
		Use: "info", Short: "Show server info (GET /api/info)", Args: cobra.NoArgs,
		RunE: runWith(func(ctx context.Context, s *opencode.Server, cmd *cobra.Command) error {
			info, err := s.Client.Info(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "server %s  (pid %d)\nbase: %s\n", info.Version, info.PID, s.Client.BaseURL())
			return nil
		}),
	}
	providersCmd := &cobra.Command{
		Use: "providers", Short: "List providers (GET /api/provider)", Args: cobra.NoArgs,
		RunE: runWith(func(ctx context.Context, s *opencode.Server, cmd *cobra.Command) error {
			ps, err := s.Client.Providers(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d providers:\n", len(ps))
			for _, p := range ps {
				name := p.Name
				if name == "" {
					name = p.ID
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %-18s %s\n", p.ID, name)
			}
			return nil
		}),
	}
	modelsCmd := &cobra.Command{
		Use: "models", Short: "List models (GET /api/model)", Args: cobra.NoArgs,
		RunE: runWith(func(ctx context.Context, s *opencode.Server, cmd *cobra.Command) error {
			ms, err := s.Client.Models(ctx)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d models:\n", len(ms))
			for _, m := range ms {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s/%s\n", m.ProviderID, m.ID)
			}
			return nil
		}),
	}
	sessionsCmd := &cobra.Command{
		Use: "sessions", Short: "List sessions (GET /api/session)", Args: cobra.NoArgs,
		RunE: runWith(func(ctx context.Context, s *opencode.Server, cmd *cobra.Command) error {
			ss, err := s.Client.ListSessions(ctx)
			if err != nil {
				return err
			}
			printJSON(cmd, ss)
			return nil
		}),
	}

	oc.AddCommand(infoCmd, providersCmd, modelsCmd, sessionsCmd)
	return oc
}
