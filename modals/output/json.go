package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kythonlk/WebRadar/modals/recon"
)

func SaveResultsToJSON(result recon.ScanResult) (string, error) {
	if result.Domain == "" {
		return "", fmt.Errorf("cannot save results: domain is empty")
	}

	// Sanitize domain for name
	safeDomain := sanitizeDomain(result.Domain)

	// Generate name: scan_example_com_20260207_134522.json
	timestamp := time.Now().UTC().Format("20060102_150405")
	filename := fmt.Sprintf("scan_%s_%s.json", safeDomain, timestamp)

	outputPath := filepath.Join(".", filename)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("json marshal failed: %w", err)
	}

	// new file
	err = os.WriteFile(outputPath, data, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write file %s: %w", outputPath, err)
	}

	return outputPath, nil
}

// sanitize domain name
func sanitizeDomain(domain string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	clean := re.ReplaceAllString(domain, "_")
	clean = regexp.MustCompile(`_+`).ReplaceAllString(clean, "_")

	clean = strings.Trim(clean, "_")
	if clean == "" {
		clean = "unknown_domain"
	}

	return clean
}

func PrintResultsJSON(result recon.ScanResult) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		return
	}
	fmt.Println(string(data))
}
