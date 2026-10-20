package opencode

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// Server represents an opencode server that hydra either spawned or attached to.
type Server struct {
	Client   *Client
	cmd      *exec.Cmd // nil when attached to an externally-managed server
	password string
}

// SpawnConfig controls how `opencode serve` is launched.
type SpawnConfig struct {
	Hostname string // default 127.0.0.1
	Port     int    // default 4096
	Dir      string // working dir for the server (repo root)
	Bin      string // opencode binary; default resolved from PATH
	// NoAuth disables generating OPENCODE_SERVER_PASSWORD (loopback only).
	NoAuth bool
	// Logs receives the server's stdout/stderr. Defaults to os.Stderr; the TUI
	// passes a file or io.Discard so server logs don't corrupt the screen.
	Logs io.Writer
}

func (s SpawnConfig) withDefaults() SpawnConfig {
	if s.Hostname == "" {
		s.Hostname = "127.0.0.1"
	}
	if s.Port == 0 {
		s.Port = 4096
	}
	if s.Bin == "" {
		s.Bin = "opencode"
	}
	return s
}

// Attach connects to an already-running server at baseURL. password may be
// empty if the server has no basic auth.
func Attach(baseURL, username, password string) *Server {
	var opts []Option
	if password != "" {
		opts = append(opts, WithBasicAuth(username, password))
	}
	return &Server{Client: New(baseURL, opts...), password: password}
}

// Spawn launches `opencode serve` and returns once it is healthy. The caller
// must call Stop when done. On loopback, a random basic-auth password is
// generated and passed via OPENCODE_SERVER_PASSWORD unless NoAuth is set.
func Spawn(ctx context.Context, cfg SpawnConfig) (*Server, error) {
	cfg = cfg.withDefaults()

	if _, err := exec.LookPath(cfg.Bin); err != nil {
		return nil, fmt.Errorf("opencode binary not found (%q): %w", cfg.Bin, err)
	}

	password := ""
	if !cfg.NoAuth {
		password = randomSecret()
	}

	// Detached from ctx: the server should outlive a single request context.
	cmd := exec.Command(cfg.Bin, "serve", "--hostname", cfg.Hostname, "--port", fmt.Sprint(cfg.Port))
	if cfg.Dir != "" {
		cmd.Dir = cfg.Dir
	}
	cmd.Env = os.Environ()
	if password != "" {
		cmd.Env = append(cmd.Env, "OPENCODE_SERVER_PASSWORD="+password)
	}
	// Surface server logs to the configured writer (default stderr).
	logs := cfg.Logs
	if logs == nil {
		logs = os.Stderr
	}
	cmd.Stdout = logs
	cmd.Stderr = logs

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start opencode serve: %w", err)
	}

	baseURL := fmt.Sprintf("http://%s:%d", cfg.Hostname, cfg.Port)
	var opts []Option
	if password != "" {
		opts = append(opts, WithBasicAuth("opencode", password))
	}
	srv := &Server{Client: New(baseURL, opts...), cmd: cmd, password: password}

	if err := srv.waitHealthy(ctx, 30*time.Second); err != nil {
		_ = srv.Stop()
		return nil, err
	}
	return srv, nil
}

// waitHealthy polls /global/health until healthy or the deadline passes.
func (s *Server) waitHealthy(ctx context.Context, within time.Duration) error {
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		info, err := s.Client.Info(ctx)
		if err == nil && info.Version != "" {
			return nil
		}
		lastErr = err
		// If we spawned it and it already exited, stop waiting.
		if s.cmd != nil && s.cmd.ProcessState != nil && s.cmd.ProcessState.Exited() {
			return fmt.Errorf("opencode serve exited before becoming healthy")
		}
		time.Sleep(250 * time.Millisecond)
	}
	if lastErr != nil {
		return fmt.Errorf("opencode server did not become healthy: %w", lastErr)
	}
	return fmt.Errorf("opencode server did not become healthy within %s", within)
}

// Password returns the basic-auth password hydra set (empty when attached/NoAuth).
func (s *Server) Password() string { return s.password }

// Spawned reports whether hydra owns the server process.
func (s *Server) Spawned() bool { return s.cmd != nil }

// Stop terminates a spawned server. It is a no-op for attached servers.
func (s *Server) Stop() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}
	// Try a graceful kill; opencode has no documented shutdown endpoint.
	err := s.cmd.Process.Kill()
	_, _ = s.cmd.Process.Wait()
	return err
}

func randomSecret() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a time-seeded value; still non-empty so auth stays on.
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b)
}
