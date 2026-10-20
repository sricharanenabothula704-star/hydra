package commands

import (
	"context"
	"fmt"

	"github.com/sricharanenabothula704-star/hydra/internal/config"
	"github.com/sricharanenabothula704-star/hydra/internal/opencode"
)

// resolveServer attaches to an existing opencode server when server!="" , else
// spawns one in the repo root. The returned cleanup stops a spawned server and
// is a no-op for an attached one.
func resolveServer(ctx context.Context, server, username, password string) (*opencode.Server, func(), error) {
	noop := func() {}
	if server != "" {
		s := opencode.Attach(server, username, password)
		if _, err := s.Client.Info(ctx); err != nil {
			return nil, noop, fmt.Errorf("attach %s: %w", server, err)
		}
		return s, noop, nil
	}
	root, err := config.RepoRoot()
	if err != nil {
		return nil, noop, err
	}
	s, err := opencode.Spawn(ctx, opencode.SpawnConfig{Dir: root})
	if err != nil {
		return nil, noop, err
	}
	return s, func() { _ = s.Stop() }, nil
}
