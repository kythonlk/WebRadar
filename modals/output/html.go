package output

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/kythonlk/WebRadar/modals/recon"
)

func GenerateAndOpenHTMLForScan(result recon.ScanResult, jsonPath string) (string, error) {
	if result.Domain == "" {
		return "", fmt.Errorf("cannot generate HTML: domain is empty")
	}

	base := strings.TrimSuffix(jsonPath, ".json")
	htmlPath := base + ".html"

	prettyJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	whoisJSON, _ := json.MarshalIndent(result.WHOIS, "", "  ")

	// tech list
	var techItems []string
	for k, v := range result.Technologies {
		techItems = append(techItems,
			fmt.Sprintf(`<div class="bg-gray-800 p-4 rounded-lg">
            <div class="font-semibold text-cyan-300">%s</div>
            <div class="text-gray-300 mt-1 break-all">%s</div>
        </div>`, k, v))
	}
	techItemsHTML := strings.Join(techItems, "\n")

	var sitemapItems []string
	for _, url := range result.SitemapPages {
		if strings.HasPrefix(url, "//") {
			continue
		}
		sitemapItems = append(sitemapItems,
			fmt.Sprintf(`<li><a href="%s" target="_blank" class="text-cyan-400 hover:underline break-all">%s</a></li>`, url, url))
	}
	sitemapItemsHTML := strings.Join(sitemapItems, "\n")

	var hiddenPaths []string
	for _, path := range result.HiddenPaths {
		hiddenPaths = append(hiddenPaths,
			fmt.Sprintf(`<li>%s</li>`, template.HTMLEscapeString(path)))
	}
	hiddenPathsHTML := strings.Join(hiddenPaths, "\n")

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
			<html lang="en" class="bg-gray-950 text-gray-100 min-h-screen">
			<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>WebRadar • %s Scan Report</title>
				<script src="https://cdn.tailwindcss.com"></script>
				<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css">
				<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script>
				<script>hljs.highlightAll();</script>
				<style>
					details summary { list-style: none; }
					details summary::-webkit-details-marker { display: none; }
				</style>
			</head>
			<body class="p-6 md:p-10">
				<div class="max-w-5xl mx-auto space-y-10">
					<div class="text-center">
						<h1 class="text-4xl md:text-5xl font-bold text-cyan-400 tracking-tight">
							WebRadar Scan Report
						</h1>
						<p class="mt-3 text-xl text-gray-300">
							<strong>%s</strong>
						</p>
						<p class="mt-2 text-sm text-gray-500">
							Generated: %s
						</p>
					</div>
					<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
						<div class="bg-gray-800/70 border border-gray-700 rounded-xl p-6 text-center shadow-lg">
							<div class="text-sm text-gray-400 uppercase tracking-wide">IP Address</div>
							<div class="mt-2 text-2xl font-mono text-cyan-300">%s</div>
						</div>
						<div class="bg-gray-800/70 border border-gray-700 rounded-xl p-6 text-center shadow-lg">
							<div class="text-sm text-gray-400 uppercase tracking-wide">Open Ports</div>
							<div class="mt-2 text-2xl font-bold text-green-400">%d</div>
						</div>
						<div class="bg-gray-800/70 border border-gray-700 rounded-xl p-6 text-center shadow-lg">
							<div class="text-sm text-gray-400 uppercase tracking-wide">Technologies</div>
							<div class="mt-2 text-2xl font-bold text-purple-400">%d</div>
						</div>
						<div class="bg-gray-800/70 border border-gray-700 rounded-xl p-6 text-center shadow-lg">
							<div class="text-sm text-gray-400 uppercase tracking-wide">Hidden Paths</div>
							<div class="mt-2 text-2xl font-bold text-orange-400">%d</div>
						</div>
					</div>

					<!-- Main Content -->
					<div class="space-y-8">
						<details class="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
							<summary class="px-6 py-4 font-semibold text-lg cursor-pointer hover:bg-gray-800 flex justify-between items-center">
								<span>WHOIS Information</span>
								<span class="text-gray-500 text-sm">click to expand</span>
							</summary>
							<div class="p-6 pt-2">
								<pre class="bg-gray-950 p-5 rounded-lg text-sm overflow-auto"><code class="language-json">%s</code></pre>
							</div>
						</details>
						<details class="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
							<summary class="px-6 py-4 font-semibold text-lg cursor-pointer hover:bg-gray-800 flex justify-between items-center">
								<span>Detected Technologies</span>
								<span class="text-gray-500 text-sm">click to expand</span>
							</summary>
							<div class="p-6 pt-2 grid grid-cols-1 md:grid-cols-2 gap-4">
								%s
							</div>
						</details>
						<details class="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
							<summary class="px-6 py-4 font-semibold text-lg cursor-pointer hover:bg-gray-800 flex justify-between items-center">
								<span>Sitemap Pages (%d found)</span>
								<span class="text-gray-500 text-sm">click to expand</span>
							</summary>
							<div class="p-6 pt-2">
								<ul class="list-disc pl-6 space-y-1 text-sm text-gray-300">
									%s
								</ul>
							</div>
						</details>
						<details class="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
							<summary class="px-6 py-4 font-semibold text-lg cursor-pointer hover:bg-gray-800 flex justify-between items-center">
								<span>Hidden / Interesting Paths (%d found)</span>
								<span class="text-gray-500 text-sm">click to expand</span>
							</summary>
							<div class="p-6 pt-2">
								<ul class="list-disc pl-6 space-y-1 text-sm font-mono text-orange-300">
									%s
								</ul>
							</div>
						</details>
						<details class="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
							<summary class="px-6 py-4 font-semibold text-lg cursor-pointer hover:bg-gray-800 flex justify-between items-center">
								<span>robots.txt Content</span>
								<span class="text-gray-500 text-sm">click to expand</span>
							</summary>
							<div class="p-6 pt-2">
								<pre class="bg-gray-950 p-5 rounded-lg text-sm overflow-auto font-mono whitespace-pre-wrap"><code>%s</code></pre>
							</div>
						</details>

						<details class="bg-gray-900 border border-gray-700 rounded-xl overflow-hidden">
							<summary class="px-6 py-4 font-semibold text-lg cursor-pointer hover:bg-gray-800 flex justify-between items-center">
								<span>Raw JSON (full data)</span>
								<span class="text-gray-500 text-sm">click to expand</span>
							</summary>
							<div class="p-6 pt-2">
								<pre class="bg-gray-950 p-5 rounded-lg text-sm overflow-auto max-h-[60vh]"><code class="language-json">%s</code></pre>
							</div>
						</details>

					</div>

					<div class="text-center text-gray-600 text-sm mt-12">
						Generated by WebRadar • Ethical reconnaissance tool • %s
					</div>

				</div>

				<script>
					document.querySelectorAll('details').forEach(d => {
						d.addEventListener('toggle', () => {
							if (d.open) {
								hljs.highlightElement(d.querySelector('pre code'));
							}
						});
					});
				</script>

			</body>
			</html>`,
		result.Domain,
		result.Domain,
		time.Now().Format("2006-01-02 15:04:05 UTC"),
		result.IP,
		len(result.OpenPorts),
		len(result.Technologies),
		len(result.HiddenPaths),
		template.HTMLEscapeString(string(whoisJSON)),
		techItemsHTML,
		len(result.SitemapPages),
		sitemapItemsHTML,
		len(result.HiddenPaths),
		hiddenPathsHTML,
		template.HTMLEscapeString(result.RobotsTXT),
		template.HTMLEscapeString(string(prettyJSON)),
		time.Now().Format("2006"),
	)

	// html file crete
	err = os.WriteFile(htmlPath, []byte(htmlContent), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write HTML: %w", err)
	}

	// open in browser
	openBrowser(htmlPath)

	return htmlPath, nil
}

func openBrowser(path string) {
	absPath, _ := filepath.Abs(path)
	url := "file://" + absPath

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", absPath)
	case "darwin":
		cmd = exec.Command("open", absPath)
	default:
		fmt.Fprintf(os.Stderr, "Cannot auto-open browser on %s\n", runtime.GOOS)
		return
	}

	_ = cmd.Start()
}
