package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/kythonlk/WebRadar/modals/output"
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
			return m, tea.Batch(scanCmd(m.domain, "wordlist.txt"))

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

func scanCmd(domain string, wordlistPath string) tea.Cmd {
	return func() tea.Msg {
		var errs []string

		base := "https://" + domain
		client := &http.Client{Timeout: 8 * time.Second}
		resp, err := client.Get(base)
		if err != nil || resp.StatusCode >= 400 {
			base = "http://" + domain
			errs = append(errs, fmt.Sprintf("HTTPS failed, falling back to HTTP: %v", err))
		}
		if resp != nil {
			resp.Body.Close()
		}

		res := recon.ScanResult{
			Domain: domain,
			Errors: []string{},
		}

		// IP
		ip, err := recon.ResolveIP(domain)
		if err == nil {
			res.IP = ip
		} else {
			errs = append(errs, fmt.Sprintf("IP resolution failed: %v", err))
		}

		// Technologies
		res.Technologies = recon.DetectTech(base)

		// Ports
		res.OpenPorts = recon.ScanPorts(domain, nil, 2*time.Second)

		// WHOIS
		whoisRaw := recon.GetWHOIS(domain)
		whoisMap := make(map[string]interface{}, len(whoisRaw))
		for k, v := range whoisRaw {
			whoisMap[k] = v
		}
		res.WHOIS = whoisMap

		// Robots.txt
		res.RobotsTXT = recon.FetchRobotsTXT(base)

		sitemapURLs := recon.FetchSitemap(base)
		if len(sitemapURLs) > 0 {
			res.SitemapPages = append([]string{
				fmt.Sprintf("// %d URLs discovered in sitemap.xml", len(sitemapURLs)),
			}, sitemapURLs...)
		} else {
			errs = append(errs, "No sitemap.xml found or empty")
		}

		// dir brute-force
		if wordlistPath == "" {
			wordlistPath = "wordlist.txt"
		}
		if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("Wordlist not found: %s", wordlistPath))
		} else {
			res.HiddenPaths = recon.DirBrute(base, wordlistPath, 12)
		}

		res.Errors = append(res.Errors, errs...)

		jsonPath, err := output.SaveResultsToJSON(res)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("Failed to save JSON: %v", err))
		}

		if jsonPath != "" {
			htmlPath, htmlErr := output.GenerateAndOpenHTMLForScan(res, jsonPath)
			if htmlErr == nil {
				fmt.Fprintf(os.Stderr, "HTML report opened: %s\n", htmlPath)
			} else {
				fmt.Fprintf(os.Stderr, "HTML generation failed: %v\n", htmlErr)
				res.Errors = append(res.Errors, fmt.Sprintf("HTML generation failed: %v", htmlErr))
			}
		}

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

	s.WriteString(titleStyle.Render(" WebRadar -- Domain Recon ") + "\n")
	s.WriteString(strings.Repeat("-", 48) + "\n\n")

	if !m.done {
		domainLine := fmt.Sprintf("Domain: %s", m.domain)
		if m.domain == "" {
			domainLine = dimStyle.Render("Domain: [type domain and press Enter]")
		}

		s.WriteString(subtitleStyle.Render("> TARGET") + "\n")
		s.WriteString(boxStyle.Render(domainLine) + "\n\n")

		s.WriteString(subtitleStyle.Render("> STATUS") + "\n")
		statusText := m.status
		if statusText == "" {
			statusText = "Ready to scan"
		}
		s.WriteString(boxStyle.Render(statusText) + "\n\n")

		if m.err != nil {
			s.WriteString(errorStyle.Render("Error: "+m.err.Error()) + "\n\n")
		}

		s.WriteString(dimStyle.Render("  • Press Enter -> Start scan") + "\n")
		s.WriteString(dimStyle.Render("  • Esc / Ctrl+C -> Quit") + "\n")
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

		stats := []string{
			fmt.Sprintf("Hidden paths: %d", len(m.result.HiddenPaths)),
			fmt.Sprintf("Sitemap pages: %d", len(m.result.SitemapPages)),
			fmt.Sprintf("Errors: %d", len(m.result.Errors)),
		}
		s.WriteString(subtitleStyle.Render("Quick Stats") + "\n")
		s.WriteString(boxStyle.Render(strings.Join(stats, "\n")) + "\n\n")

		filename := fmt.Sprintf("scan_%s.json", strings.ReplaceAll(m.result.Domain, ".", "_"))
		s.WriteString(successStyle.Render("-> Results saved to: ") + filename + "\n\n")

		s.WriteString(dimStyle.Render("  Press q / Esc / Ctrl+C to quit") + "\n")
	}

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
