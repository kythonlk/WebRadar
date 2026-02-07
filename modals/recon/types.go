package recon

type ScanResult struct {
	Domain       string            `json:"domain"`
	IP           string            `json:"ip,omitempty"`
	OpenPorts    []int             `json:"open_ports,omitempty"`
	Technologies map[string]string `json:"technologies,omitempty"`
	WHOIS        map[string]string `json:"whois,omitempty"`
	RobotsTXT    string            `json:"robots_txt,omitempty"`
	SitemapURLs  []string          `json:"sitemap_urls,omitempty"`
	SitemapPages []string          `json:"sitemap_pages,omitempty"`
	HiddenPaths  []string          `json:"hidden_paths,omitempty"`
	Errors       []string          `json:"errors,omitempty"`
	ScanTime     string            `json:"scan_completed_at,omitempty"`
}
