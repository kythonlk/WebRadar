package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kythonlk/WebRadar/modals/recon"
)

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("205"))
	errorStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
)

type model struct {
	domain string
	result recon.ScanResult
	status string
	done   bool
	err    error
	cursor int
}

func initialModel() model {
	return model{status: "Enter domain and press Enter to start scan"}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		if m.done {
			if msg.String() == "ctrl+c" || msg.String() == "q" {
				return m, tea.Quit
			}
			return m, nil
		}

		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "enter":
			if m.domain == "" {
				m.err = fmt.Errorf("domain required")
				return m, nil
			}
			m.status = "Scanning... (this may take 30–120 seconds)"
			return m, tea.Batch(scanCmd(m.domain))

		default:
			if len(msg.String()) == 1 && msg.Type == tea.KeyRunes {
				m.domain += msg.String()
			} else if msg.Type == tea.KeyBackspace && len(m.domain) > 0 {
				m.domain = m.domain[:len(m.domain)-1]
			}
		}

	case scanFinishedMsg:
		m.result = msg.result
		m.done = true
		m.status = "Scan complete. Results saved."
		if msg.err != nil {
			m.err = msg.err
		}
		return m, nil
	}
	return m, nil
}

type scanFinishedMsg struct {
	result recon.ScanResult
	err    error
}

func scanCmd(domain string) tea.Cmd {
	return func() tea.Msg {
		base := "https://" + domain
		if _, err := http.Get(base); err != nil {
			base = "http://" + domain
		}

		res := recon.ScanResult{
			Domain: domain,
		}

		ip, err := recon.ResolveIP(domain)
		if err == nil {
			res.IP = ip
		} else {
			res.Errors = append(res.Errors, err.Error())
		}

		res.SitemapPages = recon.FetchSitemap(base)

		if len(res.SitemapPages) > 0 {
			res.SitemapPages = append([]string{
				fmt.Sprintf("// %d URLs discovered in sitemap.xml", len(res.SitemapPages)),
			}, res.SitemapPages...)
		} else {
			res.Errors = append(res.Errors, "No sitemap.xml found or empty")
		}

		res.Technologies = recon.DetectTech(base)
		res.OpenPorts = recon.ScanPorts(domain, nil, 2*time.Second)
		res.WHOIS = recon.GetWHOIS(domain)
		res.RobotsTXT = recon.FetchRobotsTXT(base)
		res.SitemapURLs = recon.FetchSitemap(base)
		res.HiddenPaths = recon.DirBrute(base, "wordlist.txt", 12)

		// Save json
		data, _ := json.MarshalIndent(res, "", "  ")
		fname := fmt.Sprintf("scan_%s.json", strings.ReplaceAll(domain, ".", "_"))
		os.WriteFile(fname, data, 0644)

		return scanFinishedMsg{result: res, err: nil}
	}
}

func (m model) View() string {
	var (
		titleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("39")). // cyan
				Background(lipgloss.Color("235")).
				Padding(0, 2)

		subtitleStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("141")). // purple
				Bold(true)

		dimStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("240"))

		successStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("76")) // green

		errorStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("196")).
				Bold(true)

		boxStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("238")).
				Padding(1, 2).
				Margin(0, 0, 1, 0)
	)

	var s strings.Builder

	s.WriteString(titleStyle.Render(" WebRadar • Domain Recon ") + "\n")
	s.WriteString(strings.Repeat("─", 48) + "\n\n")

	if !m.done {
		domainLine := fmt.Sprintf("Domain: %s", m.domain)
		if m.domain == "" {
			domainLine = dimStyle.Render("Domain: [type domain and press Enter]")
		}

		s.WriteString(subtitleStyle.Render("► TARGET") + "\n")
		s.WriteString(boxStyle.Render(domainLine) + "\n\n")

		s.WriteString(subtitleStyle.Render("► STATUS") + "\n")
		statusText := m.status
		if statusText == "" {
			statusText = "Ready to scan"
		}
		s.WriteString(boxStyle.Render(statusText) + "\n\n")

		if m.err != nil {
			s.WriteString(errorStyle.Render("Error: "+m.err.Error()) + "\n\n")
		}

		s.WriteString(dimStyle.Render("  • Press Enter → Start scan") + "\n")
		s.WriteString(dimStyle.Render("  • Esc / Ctrl+C → Quit") + "\n")
	} else {
		s.WriteString(successStyle.Render("✓ Scan completed") + "\n\n")

		summary := lipgloss.JoinHorizontal(lipgloss.Top,
			boxStyle.Copy().
				BorderForeground(lipgloss.Color("39")).
				Render(fmt.Sprintf("IP\n%s", m.result.IP)),

			"  ",

			boxStyle.Copy().
				BorderForeground(lipgloss.Color("141")).
				Render(fmt.Sprintf("Open Ports\n%d found", len(m.result.OpenPorts))),
		)
		s.WriteString(summary + "\n\n")

		// Technologies
		if len(m.result.Technologies) > 0 {
			s.WriteString(subtitleStyle.Render("Technologies / Fingerprints") + "\n")
			techLines := make([]string, 0, len(m.result.Technologies))
			for k, v := range m.result.Technologies {
				techLines = append(techLines, fmt.Sprintf("  • %s: %s", k, v))
			}
			s.WriteString(boxStyle.Render(strings.Join(techLines, "\n")) + "\n")
		}

		// Quick stats
		stats := []string{
			fmt.Sprintf("Hidden paths: %d", len(m.result.HiddenPaths)),
			fmt.Sprintf("Sitemap pages: %d", len(m.result.SitemapPages)),
			fmt.Sprintf("Errors: %d", len(m.result.Errors)),
		}
		s.WriteString(subtitleStyle.Render("Quick Stats") + "\n")
		s.WriteString(boxStyle.Render(strings.Join(stats, "\n")) + "\n\n")

		// File info
		filename := fmt.Sprintf("scan_%s.json", strings.ReplaceAll(m.result.Domain, ".", "_"))
		s.WriteString(successStyle.Render("→ Results saved to: ") + filename + "\n\n")

		// Footer / controls
		s.WriteString(dimStyle.Render("  Press q / Esc / Ctrl+C to quit") + "\n")
	}

	// Final margin + render
	content := s.String()
	return lipgloss.NewStyle().
		Margin(1, 2, 1, 2).
		Render(content)
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}
