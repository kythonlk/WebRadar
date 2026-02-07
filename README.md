# WebRadar – Domain Reconnaissance Tool

A lightweight, fast, Go-based web reconnaissance tool designed for ethical security testing, CTF practice. 

## Features

- Resolve domain → IP
- TCP connect port scan (top common ports)
- Basic technology / fingerprint detection (React, Next.js, WordPress, Laravel, Vue, etc.)
- Real WHOIS lookup (IANA → registrar chain, no external libs)
- Fetch & parse `robots.txt`
- Fetch & parse `sitemap.xml` (lists discovered pages)
- Directory / file brute-force (Gobuster-style, with custom wordlist)
- Beautiful Bubble Tea TUI (modern terminal UI with colors, boxes, sections)
- Results saved to timestamped JSON (`scan_example_com_20260207_143022.json`)

## Installation

```bash
git clone https://github.com/kythonlk/WebRadar
cd WebRadar

go mod tidy

go build -o webradar ./cmd/main.go
./webradar

# optional: add `./webradar` to $PATH or symlink
```

## Usage

1. Run the tool a nice TUI appears
2. Type the target domain (e.g. `example.com`)
3. Press **Enter** to start scanning
4. Wait ~30 - 120 seconds (depending on ports + wordlist size)
5. View summary in terminal
6. Full structured results saved as JSON in current directory


## Requirements

- Go 1.21+
- A wordlist file named `wordlist.txt` in project root (recommended: small SecLists dirbuster list)

## Ethical & Legal Warning

> This tool is provided strictly for **educational purposes**, authorized penetration testing, red team exercises, bug bounty programs (with permission), and lab/CTF environments (HTB, TryHackMe, VulnHub, etc.).  
> The author is **not responsible** for any misuse or damage caused by this software.  
> Always obtain explicit written permission before scanning any target you do **not** own.

## Project Goals / Why This Exists

Built as a hands-on learning project to:
- Understand real-world network protocols (DNS, TCP connect scan, HTTP, WHOIS)
- Create clean, maintainable architecture (internal packages)
- Build beautiful TUIs with Bubble Tea + Lip Gloss
- Generate useful JSON reports for enumeration phase easy analysis

## Roadmap (ideas contributions welcome!)

- CLI flags / headless mode
- Rate limiting + user-agent rotation
- Embedded default wordlist (`//go:embed`)
- Live progress updates in TUI (spinner, partial results)
- Markdown / PDF report generation
- Subdomain enumeration module
- More advanced fingerprinting (JA3, Wappalyzer JSON rules)

Made by kythonlk with ❤️ in 2026  
Happy hacking!
