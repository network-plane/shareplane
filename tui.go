package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tickMsg struct{}

func tuiTick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

type statusMsg struct{ body string }
type fetchErrMsg struct{ err error }

func runTUIBlocking(port string) {
	p := tea.NewProgram(newTUIModel(port), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		outPrintf("TUI: %v\n", err)
	}
}

func tuiHTTPClient() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr, Timeout: 4 * time.Second}
}

func newTUIModel(port string) *tuiModel {
	return &tuiModel{
		port:   port,
		client: tuiHTTPClient(),
		width:  100,
	}
}

type tuiModel struct {
	port   string
	body   string
	err    string
	client *http.Client
	width  int
}

func (m *tuiModel) Init() tea.Cmd {
	return m.fetchCmd()
}

func (m *tuiModel) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		scheme := "http"
		if serverCfg.EphemeralTLS || serverCfg.TLSCertFile != "" {
			scheme = "https"
		}
		u := fmt.Sprintf("%s://127.0.0.1:%s/api/status", scheme, m.port)
		resp, err := m.client.Get(u)
		if err != nil {
			return fetchErrMsg{err: err}
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return fetchErrMsg{err: err}
		}
		var out bytes.Buffer
		if err := json.Indent(&out, b, "", "  "); err != nil {
			return fetchErrMsg{err: err}
		}
		return statusMsg{body: out.String()}
	}
}

func (m *tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		s := msg.String()
		if s == "q" || s == "ctrl+c" {
			return m, tea.Quit
		}
	case statusMsg:
		m.body = msg.body
		m.err = ""
		return m, tuiTick()
	case fetchErrMsg:
		m.err = msg.err.Error()
		return m, tuiTick()
	case tickMsg:
		return m, m.fetchCmd()
	}
	return m, nil
}

func (m *tuiModel) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("shareplane — GET /api/status (q quit)")
	help := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("localhost; TLS uses insecure skip-verify for self-signed")
	w := m.width - 4
	if w < 40 {
		w = 40
	}
	if w > 116 {
		w = 116
	}
	var block string
	if m.err != "" {
		block = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Width(w).Render(m.err)
	} else {
		block = lipgloss.NewStyle().Width(w).Render(m.body)
	}
	return title + "\n" + help + "\n\n" + block + "\n"
}
