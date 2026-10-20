// Package audit provides an append-only record of scope decisions and
// command executions. Every target-touching action writes an entry, so there
// is a durable trail of what was attempted and whether the gate allowed it.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/sricharanenabothula704-star/hydra/internal/config"
)

// Entry is one audit record (one JSON line).
type Entry struct {
	Time     string `json:"time"`
	Action   string `json:"action"`
	Target   string `json:"target,omitempty"`
	Decision string `json:"decision"` // "allow" | "deny" | "run"
	Reason   string `json:"reason,omitempty"`
}

// Path returns the audit log location (~/.config/hydra/audit.log).
func Path() string { return filepath.Join(config.HydraConfigDir(), "audit.log") }

// write appends one entry as a JSON line.
func write(e Entry) error {
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339)
	}
	if err := os.MkdirAll(filepath.Dir(Path()), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(Path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Scope records a scope-gate decision.
func Scope(action, target string, allowed bool, reason string) error {
	d := "deny"
	if allowed {
		d = "allow"
	}
	return write(Entry{Action: action, Target: target, Decision: d, Reason: reason})
}

// Run records that a command was executed.
func Run(action, target string) error {
	return write(Entry{Action: action, Target: target, Decision: "run"})
}
