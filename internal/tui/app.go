// Package tui implements hydra's interactive terminal UI (Bubble Tea): a
// chat-style front-end that attaches to an opencode server, with a persistent
// scope banner backed by the real scope gate.
package tui

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/sricharanenabothula704-star/hydra/internal/config"
	"github.com/sricharanenabothula704-star/hydra/internal/gates"
	"github.com/sricharanenabothula704-star/hydra/internal/opencode"
	"github.com/sricharanenabothula704-star/hydra/internal/version"
)

type viewKind int

const (
	viewChat viewKind = iota
	viewHelp
)

type connState int

const (
	connConnecting connState = iota
	connConnected
	connOffline
)

type model struct {
	keys   keymap
	width  int
	height int
	view   viewKind
	ready  bool

	input textinput.Model
	vp    viewport.Model
	lines []string // transcript lines

	conn     connState
	connMsg  string
	server   *opencode.Server
	info     opencode.ServerInfo
	sessID   string
	events   <-chan opencode.Event
	eventErr <-chan error

	scopeState string // "", "allow", "deny"
	scopeMsg   string
}

// Config controls how the TUI connects to opencode.
type Config struct {
	Server   string // attach URL; empty => spawn
	Username string
	Password string
	Logs     io.Writer // server logs sink when spawning
}

func newModel() model {
	ti := textinput.New()
	ti.Placeholder = "Message HYDRA  (authorized targets only)…"
	ti.Prompt = "❯ "
	ti.Focus()
	ti.CharLimit = 4000

	return model{
		keys:       defaultKeymap(),
		view:       viewChat,
		input:      ti,
		conn:       connConnecting,
		connMsg:    "connecting…",
		scopeState: "",
		lines: []string{
			sysStyle.Render("HYDRA — authorized testing only. Connecting to opencode…"),
		},
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, connectCmd(runConfig))
}

// runConfig holds connect configuration for the program, set by RunWithConfig.
var runConfig Config

// ---- messages ----

type connectedMsg struct {
	server   *opencode.Server
	info     opencode.ServerInfo
	events   <-chan opencode.Event
	eventErr <-chan error
}
type connectFailMsg struct{ err error }
type eventMsg struct{ ev opencode.Event }
type streamEndMsg struct{ err error }
type sessionMsg struct{ id string }
type sentMsg struct{}
type errMsg struct{ err error }

// ---- commands ----

func connectCmd(c Config) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()

		var srv *opencode.Server
		if c.Server != "" {
			srv = opencode.Attach(c.Server, c.Username, c.Password)
			if _, err := srv.Client.Info(ctx); err != nil {
				return connectFailMsg{err}
			}
		} else {
			root, err := config.RepoRoot()
			if err != nil {
				return connectFailMsg{err}
			}
			srv, err = opencode.Spawn(ctx, opencode.SpawnConfig{Dir: root, Logs: c.Logs})
			if err != nil {
				return connectFailMsg{err}
			}
		}
		info, err := srv.Client.Info(ctx)
		if err != nil {
			return connectFailMsg{err}
		}
		ev, errc, err := srv.Client.Events(context.Background())
		if err != nil {
			return connectFailMsg{err}
		}
		return connectedMsg{server: srv, info: info, events: ev, eventErr: errc}
	}
}

func waitEventCmd(ev <-chan opencode.Event, errc <-chan error) tea.Cmd {
	return func() tea.Msg {
		select {
		case e, ok := <-ev:
			if !ok {
				return streamEndMsg{}
			}
			return eventMsg{ev: e}
		case err := <-errc:
			return streamEndMsg{err: err}
		}
	}
}

func (m model) sendPromptCmd(text string) tea.Cmd {
	srv := m.server
	sessID := m.sessID
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if sessID == "" {
			s, err := srv.Client.CreateSession(ctx, opencode.CreateSessionInput{Title: "hydra"})
			if err != nil {
				return errMsg{err}
			}
			sessID = s.ID
		}
		if _, err := srv.Client.Prompt(ctx, sessID, opencode.PromptInput{Text: text}); err != nil {
			return errMsg{fmt.Errorf("prompt (session %s): %w", sessID, err)}
		}
		return sessionMsg{id: sessID}
	}
}

// ---- update ----

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		m.ready = true

	case tea.KeyMsg:
		switch {
		case keyMatches(msg, m.keys.Quit):
			return m, tea.Quit
		case keyMatches(msg, m.keys.Help):
			if m.view == viewHelp {
				m.view = viewChat
			} else {
				m.view = viewHelp
			}
			return m, nil
		case keyMatches(msg, m.keys.Chat):
			m.view = viewChat
			return m, nil
		case keyMatches(msg, m.keys.Send):
			if m.view == viewChat {
				return m.onSend()
			}
		}

	case connectedMsg:
		m.conn = connConnected
		m.server = msg.server
		m.info = msg.info
		m.events = msg.events
		m.eventErr = msg.eventErr
		m.connMsg = "connected"
		m.appendLine(sysStyle.Render(fmt.Sprintf("Connected to opencode %s. Ready.", msg.info.Version)))
		cmds = append(cmds, waitEventCmd(m.events, m.eventErr))

	case connectFailMsg:
		m.conn = connOffline
		m.connMsg = "offline"
		m.appendLine(statusErrStyle.Render("Could not reach opencode: " + msg.err.Error()))

	case eventMsg:
		if t := eventText(msg.ev); t != "" {
			m.appendLine(roleHydraStyle.Render("hydra ") + t)
		}
		cmds = append(cmds, waitEventCmd(m.events, m.eventErr))

	case streamEndMsg:
		if msg.err != nil {
			m.appendLine(statusErrStyle.Render("event stream ended: " + msg.err.Error()))
		}

	case sessionMsg:
		m.sessID = msg.id

	case errMsg:
		m.appendLine(statusErrStyle.Render("error: " + msg.err.Error()))
	}

	// Delegate to focused sub-components.
	var cmd tea.Cmd
	if m.view == viewChat {
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
	}
	m.vp, cmd = m.vp.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// onSend handles Enter in the chat view: runs the scope gate if the message
// names a target, blocks on deny, otherwise sends the prompt.
func (m model) onSend() (tea.Model, tea.Cmd) {
	text := strings.TrimSpace(m.input.Value())
	if text == "" {
		return m, nil
	}

	if target, ok := detectTarget(text); ok {
		d := gates.CheckScope(target)
		if d.Allowed {
			m.scopeState, m.scopeMsg = "allow", target
		} else {
			m.scopeState, m.scopeMsg = "deny", target
			m.appendLine(scopeDenyStyle.Render(" SCOPE-DENY ") + " " + dimStyle.Render(firstLine(d.Reason)))
			m.input.SetValue("")
			return m, nil
		}
	}

	m.appendLine(roleYouStyle.Render("you ") + textStyle.Render(text))
	m.input.SetValue("")

	if m.conn != connConnected || m.server == nil {
		m.appendLine(statusWarnStyle.Render("not connected to opencode yet — message not sent"))
		return m, nil
	}
	return m, m.sendPromptCmd(text)
}

func (m *model) appendLine(s string) {
	m.lines = append(m.lines, s)
	m.vp.SetContent(strings.Join(m.lines, "\n"))
	m.vp.GotoBottom()
}

// layout sizes the viewport and input to the window.
func (m *model) layout() {
	if m.width <= 0 {
		return
	}
	headerH, bannerH, footerH, inputH := 1, 1, 1, 1
	bodyH := m.height - headerH - bannerH - footerH - inputH - 1
	if bodyH < 3 {
		bodyH = 3
	}
	if m.vp.Width == 0 {
		m.vp = viewport.New(m.width, bodyH)
	} else {
		m.vp.Width, m.vp.Height = m.width, bodyH
	}
	m.input.Width = m.width - 4
	m.vp.SetContent(strings.Join(m.lines, "\n"))
	m.vp.GotoBottom()
}

// ---- view ----

func (m model) View() string {
	if !m.ready {
		return "\n  " + titleStyle.Render("HYDRA") + "  starting…\n"
	}
	if m.view == viewHelp {
		return m.header() + "\n" + m.scopeBanner() + "\n" + m.helpBody() + "\n" + m.footer()
	}
	return m.header() + "\n" + m.scopeBanner() + "\n" + m.vp.View() + "\n" + m.inputRow() + "\n" + m.footer()
}

func (m model) header() string {
	left := titleStyle.Render("HYDRA")
	var status string
	switch m.conn {
	case connConnected:
		status = statusOKStyle.Render("● opencode " + m.info.Version)
	case connConnecting:
		status = statusWarnStyle.Render("◌ " + m.connMsg)
	default:
		status = statusErrStyle.Render("○ " + m.connMsg)
	}
	line := left + "  " + dimStyle.Render(version.Version) + "   " + status
	return headerStyle.Width(m.width).Render(line)
}

func (m model) scopeBanner() string {
	switch m.scopeState {
	case "allow":
		return scopeAllowStyle.Render(" SCOPE-ALLOW ") + " " + dimStyle.Render(m.scopeMsg)
	case "deny":
		return scopeDenyStyle.Render(" SCOPE-DENY ") + " " + dimStyle.Render(m.scopeMsg)
	default:
		return scopeIdleStyle.Width(m.width).Render("scope: no target — the gate runs before any host is contacted")
	}
}

func (m model) inputRow() string { return m.input.View() }

func (m model) footer() string {
	return footerStyle.Width(m.width).Render(m.keys.shortHelp())
}

func (m model) helpBody() string {
	b := &strings.Builder{}
	fmt.Fprintln(b, titleStyle.Render("Help"))
	fmt.Fprintln(b, textStyle.Render("HYDRA drives opencode for authorized security testing."))
	fmt.Fprintln(b)
	fmt.Fprintln(b, dimStyle.Render("  enter     send the current message"))
	fmt.Fprintln(b, dimStyle.Render("  ctrl+s    sessions (coming soon)"))
	fmt.Fprintln(b, dimStyle.Render("  ?/f1      toggle this help"))
	fmt.Fprintln(b, dimStyle.Render("  esc       back to chat"))
	fmt.Fprintln(b, dimStyle.Render("  ctrl+c    quit"))
	fmt.Fprintln(b)
	fmt.Fprintln(b, sysStyle.Render("  Messages that name a host are checked by the scope gate first;"))
	fmt.Fprintln(b, sysStyle.Render("  out-of-scope targets are blocked before anything is sent."))
	return lipgloss.NewStyle().Padding(0, 1).Render(b.String())
}

// Run starts the interactive TUI and blocks until the user quits.
func Run() error { return RunWithConfig(Config{}) }

// RunWithConfig starts the TUI with explicit connect configuration.
func RunWithConfig(c Config) error {
	runConfig = c
	p := tea.NewProgram(newModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
