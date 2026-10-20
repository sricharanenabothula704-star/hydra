package tui

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func readyModel() model {
	m := newModel()
	m2, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	return m2.(model)
}

func TestHelpToggle(t *testing.T) {
	m := readyModel()
	q := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")}
	m2, _ := m.Update(q)
	if m2.(model).view != viewHelp {
		t.Fatalf("expected help view after '?', got %v", m2.(model).view)
	}
	m3, _ := m2.(model).Update(q)
	if m3.(model).view != viewChat {
		t.Fatalf("expected chat view after second '?', got %v", m3.(model).view)
	}
}

func TestQuitKey(t *testing.T) {
	m := readyModel()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if cmd == nil {
		t.Fatal("ctrl+c should return a quit command")
	}
}

func TestScopeGateBlocksOutOfScopeSend(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash unavailable; scope gate not exercisable")
	}
	// Controlled allowlist via fake HOME.
	home := t.TempDir()
	alDir := filepath.Join(home, ".config", "opencode")
	if err := os.MkdirAll(alDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alDir, "SCOPE_ALLOWLIST.txt"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	m := readyModel()
	m.input.SetValue("please hunt evil.invalid for bugs")
	res, cmd := m.onSend()
	mm := res.(model)

	if mm.scopeState != "deny" {
		t.Fatalf("expected scopeState deny, got %q", mm.scopeState)
	}
	if cmd != nil {
		t.Fatal("out-of-scope send must not dispatch a prompt command")
	}
	if mm.input.Value() != "" {
		t.Fatal("input should be cleared after a blocked send")
	}
	joined := strings.Join(mm.lines, "\n")
	if !strings.Contains(joined, "SCOPE-DENY") {
		t.Fatalf("transcript should show SCOPE-DENY, got:\n%s", joined)
	}
}

func TestDetectTarget(t *testing.T) {
	cases := map[string]string{
		"scan https://bugbase.ai/x":       "https://bugbase.ai",
		"look at sub.ackodrive.com please": "sub.ackodrive.com",
		"just some words here":            "",
		"email me at a@b":                 "", // no TLD-like host
	}
	for in, want := range cases {
		got, ok := detectTarget(in)
		if want == "" {
			if ok {
				t.Errorf("detectTarget(%q)=%q, want none", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("detectTarget(%q)=%q(%v), want %q", in, got, ok, want)
		}
	}
}

func TestViewRendersWithoutPanic(t *testing.T) {
	for _, sz := range [][2]int{{80, 24}, {40, 10}, {120, 50}, {20, 6}} {
		m := newModel()
		m2, _ := m.Update(tea.WindowSizeMsg{Width: sz[0], Height: sz[1]})
		out := m2.(model).View()
		if !strings.Contains(out, "HYDRA") {
			t.Errorf("size %v: view missing HYDRA banner", sz)
		}
		// help view too
		m3, _ := m2.(model).Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("?")})
		if out := m3.(model).View(); !strings.Contains(out, "Help") {
			t.Errorf("size %v: help view missing", sz)
		}
	}
}
