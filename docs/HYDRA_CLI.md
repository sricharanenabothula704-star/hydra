# Hydra CLI (Go)

A single cross-platform binary that drives opencode. Authorized testing only.

## Build

From the repo root (Go 1.26+):

```bash
go build -o dist/hydra ./cmd/hydra        # current platform
```

Cross-platform release builds use GoReleaser (`.goreleaser.yaml`):

```bash
goreleaser build --snapshot --clean       # all platforms into dist/
goreleaser release --clean                # tagged release (needs a git tag)
```

Targets: linux/amd64, linux/arm64, windows/amd64, darwin/amd64, darwin/arm64.
Binaries are static (`CGO_ENABLED=0`) with version info baked in via ldflags.

## Commands

| Command | Purpose |
|---|---|
| `hydra` | Launch the interactive TUI |
| `hydra doctor` | Pre-flight environment and gate checks |
| `hydra status` | Version and environment summary |
| `hydra guard <host>` | Show the scope decision for a host (no network contact) |
| `hydra providers list` | List the provider catalog and what is configured |
| `hydra providers connect <id>` | Configure a provider in the repo's `opencode.json` |
| `hydra providers disconnect <id>` | Remove a provider entry |
| `hydra providers models` | List models from a running opencode server |
| `hydra oc {info,providers,models,sessions}` | Low-level opencode server calls |
| `hydra hunt <target>` | Scope-gated hunt (bridges to the Python backend) |
| `hydra scan <url>` | Scope-gated scan |
| `hydra validate / chains / pipeline / history / stats / skills` | Bridged backend commands |

## How it connects to opencode

Hydra attaches to a running `opencode serve` (opencode v2 HTTP API under `/api`),
or spawns one itself. Set `OPENCODE_SERVER` to attach to an existing server and
`OPENCODE_SERVER_PASSWORD` for its basic auth.

## Providers

`hydra providers connect <id>` writes a provider entry into a repo-owned
`opencode.json`, which opencode merges with the user's global config — the global
`~/.config/opencode/*` files are left untouched. API keys are referenced as
`{env:VAR}`; the CLI never stores or handles the key itself.
