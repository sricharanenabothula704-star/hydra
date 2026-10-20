package commands

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/sricharanenabothula704-star/hydra/internal/config"
	"github.com/sricharanenabothula704-star/hydra/internal/providers"
)

// newProvidersCmd groups provider management: list the catalog, connect a
// provider (writes a repo-owned opencode.json entry; never handles secrets),
// disconnect one, and list models from a running server.
func newProvidersCmd() *cobra.Command {
	p := &cobra.Command{
		Use:     "providers",
		Aliases: []string{"provider"},
		Short:   "Manage AI model providers (catalog, connect, models)",
	}
	p.AddCommand(newProvidersListCmd(), newProvidersConnectCmd(), newProvidersDisconnectCmd(), newModelsCmd())
	return p
}

func newProvidersListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Aliases: []string{"ls"}, Short: "List the provider catalog and what is configured", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			configured := map[string]bool{}
			if root, err := config.RepoRoot(); err == nil {
				ids, model, _ := providers.ListConfigured(root)
				for _, id := range ids {
					configured[id] = true
				}
				if model != "" {
					fmt.Fprintf(out, "default model: %s\n\n", model)
				}
			}
			fmt.Fprintf(out, "%-18s %-26s %s\n", "ID", "NAME", "STATUS")
			for _, e := range providers.Catalog {
				status := "catalog"
				if configured[e.ID] {
					status = "configured"
				} else if e.Preloaded {
					status = "preloaded"
				}
				tag := ""
				if e.Local {
					tag = " (local)"
				}
				fmt.Fprintf(out, "%-18s %-26s %s%s\n", e.ID, e.Name, status, tag)
			}
			fmt.Fprintln(out, "\nConnect with:  hydra providers connect <id>")
			return nil
		},
	}
}

func newProvidersConnectCmd() *cobra.Command {
	var keyEnv, baseURL, name, npm, defaultModel string
	var modelFlags []string
	cmd := &cobra.Command{
		Use:   "connect <id>",
		Short: "Configure a provider in the repo's opencode.json (no secrets handled)",
		Long: "Writes a provider entry into the hydra-owned opencode.json. The API key is\n" +
			"referenced as {env:VAR} and never passed to or stored by hydra — set that\n" +
			"environment variable yourself before running hydra.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToLower(strings.TrimSpace(args[0]))
			out := cmd.OutOrStdout()
			root, err := config.RepoRoot()
			if err != nil {
				return err
			}

			entry, known := providers.Lookup(id)
			conf := providers.Configured{ID: id}
			conf.Name = name
			conf.NPM = npm
			conf.BaseURL = baseURL

			if known {
				if conf.Name == "" {
					conf.Name = entry.Name
				}
				if conf.BaseURL == "" {
					conf.BaseURL = entry.BaseURL
				}
			}
			if conf.BaseURL == "" {
				return fmt.Errorf("unknown provider %q: pass --base-url for a custom OpenAI-compatible endpoint", id)
			}

			// API-key reference (skip for local providers unless overridden).
			isLocal := known && entry.Local
			if !isLocal {
				env := keyEnv
				if env == "" {
					env = providers.DefaultEnvKey(id)
				}
				conf.APIKeyRef = fmt.Sprintf("{env:%s}", env)
			}

			// Models from repeated --model id[=Display].
			conf.Models = map[string]string{}
			for _, mf := range modelFlags {
				mid, disp, _ := strings.Cut(mf, "=")
				mid = strings.TrimSpace(mid)
				if mid != "" {
					conf.Models[mid] = strings.TrimSpace(disp)
				}
			}

			if err := providers.Configure(root, conf, defaultModel); err != nil {
				return err
			}

			fmt.Fprintf(out, "Configured provider %q in %s\n", id, providers.ConfigPath(root))
			if conf.APIKeyRef != "" {
				env := strings.TrimSuffix(strings.TrimPrefix(conf.APIKeyRef, "{env:"), "}")
				set := "set"
				if _, ok := os.LookupEnv(env); ok {
					set = "already set ✓"
				}
				fmt.Fprintf(out, "API key: reads $%s (%s). hydra never sees the key itself.\n", env, set)
			}
			if defaultModel != "" {
				fmt.Fprintf(out, "Default model set to %s\n", defaultModel)
			}
			fmt.Fprintln(out, "Run 'hydra providers models' to list available models once connected.")
			return nil
		},
	}
	cmd.Flags().StringVar(&keyEnv, "key-env", "", "env var holding the API key (default: provider's conventional var)")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "OpenAI-compatible base URL (required for custom providers)")
	cmd.Flags().StringVar(&name, "name", "", "display name")
	cmd.Flags().StringVar(&npm, "npm", "", "ai-sdk package (default @ai-sdk/openai-compatible)")
	cmd.Flags().StringVar(&defaultModel, "default-model", "", "also set this as the default model (provider/model)")
	cmd.Flags().StringArrayVar(&modelFlags, "model", nil, "model to register, 'id' or 'id=Display Name' (repeatable)")
	return cmd
}

func newProvidersDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use: "disconnect <id>", Aliases: []string{"remove", "rm"}, Short: "Remove a provider from the repo's opencode.json", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			root, err := config.RepoRoot()
			if err != nil {
				return err
			}
			if err := providers.Remove(root, args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed provider %q (if it was present)\n", args[0])
			return nil
		},
	}
}

func newModelsCmd() *cobra.Command {
	var server, password, username string
	cmd := &cobra.Command{
		Use: "models", Short: "List models from a running opencode server", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
			defer cancel()
			s, cleanup, err := resolveServer(ctx, server, username, password)
			if err != nil {
				return err
			}
			defer cleanup()
			ms, err := s.Client.Models(ctx)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%d models:\n", len(ms))
			for _, m := range ms {
				fmt.Fprintf(out, "  %s/%s\n", m.ProviderID, m.ID)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", os.Getenv("OPENCODE_SERVER"), "attach to an existing opencode server URL (else spawn)")
	cmd.Flags().StringVar(&password, "password", os.Getenv("OPENCODE_SERVER_PASSWORD"), "server basic-auth password")
	cmd.Flags().StringVar(&username, "username", "opencode", "server basic-auth username")
	return cmd
}
