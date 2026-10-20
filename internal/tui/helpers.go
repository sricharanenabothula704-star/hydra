package tui

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/sricharanenabothula704-star/hydra/internal/opencode"
)

func keyMatches(msg tea.KeyMsg, b key.Binding) bool {
	return key.Matches(msg, b)
}

// targetRe loosely matches a URL or bare domain in free text so the scope gate
// can be consulted before a prompt that names a host is sent. The gate itself
// is the authority; this only decides whether to consult it.
var targetRe = regexp.MustCompile(`(?i)\b((?:https?://)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?:/[^\s]*)?\b`)

// detectTarget returns the first host-like token in s, if any.
func detectTarget(s string) (string, bool) {
	m := targetRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// eventText extracts human-displayable text from an opencode event payload,
// best-effort across the v2 event shapes. Returns "" when there's nothing to show.
func eventText(ev opencode.Event) string {
	if len(ev.Data) == 0 {
		return ""
	}
	// Try a few common shapes: {text}, {part:{text}}, {properties:{part:{text}}}.
	var probe struct {
		Text string `json:"text"`
		Part struct {
			Text string `json:"text"`
			Type string `json:"type"`
		} `json:"part"`
		Properties struct {
			Part struct {
				Text string `json:"text"`
				Type string `json:"type"`
			} `json:"part"`
		} `json:"properties"`
	}
	if json.Unmarshal(ev.Data, &probe) == nil {
		switch {
		case probe.Properties.Part.Text != "":
			return probe.Properties.Part.Text
		case probe.Part.Text != "":
			return probe.Part.Text
		case probe.Text != "":
			return probe.Text
		}
	}
	return ""
}
