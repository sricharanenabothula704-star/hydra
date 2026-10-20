package tui

import "github.com/charmbracelet/bubbles/key"

// keymap defines the TUI's key bindings.
type keymap struct {
	Send     key.Binding
	Help     key.Binding
	Sessions key.Binding
	Chat     key.Binding
	Quit     key.Binding
}

func defaultKeymap() keymap {
	return keymap{
		Send:     key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "send")),
		Help:     key.NewBinding(key.WithKeys("?", "f1"), key.WithHelp("?", "help")),
		Sessions: key.NewBinding(key.WithKeys("ctrl+s"), key.WithHelp("ctrl+s", "sessions")),
		Chat:     key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "chat")),
		Quit:     key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")),
	}
}

// shortHelp is the footer hint line.
func (k keymap) shortHelp() string {
	return "enter send · ctrl+s sessions · ? help · ctrl+c quit"
}
