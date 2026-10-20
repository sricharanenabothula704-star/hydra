package tui

import "github.com/charmbracelet/lipgloss"

// Palette — a restrained, opencode-adjacent dark theme. Colors are ANSI 256 so
// they render on any terminal.
var (
	colAccent = lipgloss.Color("63")  // indigo
	colOK     = lipgloss.Color("42")  // green
	colWarn   = lipgloss.Color("214") // amber
	colDanger = lipgloss.Color("203") // red
	colDim    = lipgloss.Color("244") // grey
	colText   = lipgloss.Color("252")
	colBarBg  = lipgloss.Color("236")
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	dimStyle   = lipgloss.NewStyle().Foreground(colDim)
	textStyle  = lipgloss.NewStyle().Foreground(colText)

	headerStyle = lipgloss.NewStyle().
			Bold(true).Foreground(colText).Background(colBarBg).
			Padding(0, 1)

	footerStyle = lipgloss.NewStyle().Foreground(colDim).Background(colBarBg).Padding(0, 1)

	scopeAllowStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(colOK).Padding(0, 1)
	scopeDenyStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(colDanger).Padding(0, 1)
	scopeIdleStyle  = lipgloss.NewStyle().Foreground(colDim).Background(colBarBg).Padding(0, 1)

	statusOKStyle   = lipgloss.NewStyle().Foreground(colOK)
	statusWarnStyle = lipgloss.NewStyle().Foreground(colWarn)
	statusErrStyle  = lipgloss.NewStyle().Foreground(colDanger)

	roleYouStyle   = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	roleHydraStyle = lipgloss.NewStyle().Bold(true).Foreground(colOK)
	sysStyle       = lipgloss.NewStyle().Foreground(colWarn)
)
