package recon

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

// WHOIS lookup
func GetWHOIS(domain string) map[string]string {
	results := make(map[string]string)
	results["domain"] = domain

	ianaResponse, err := queryWHOIS("whois.iana.org", domain)
	if err != nil {
		results["error"] = fmt.Sprintf("IANA query failed: %v", err)
		return results
	}

	referralServer := extractReferral(ianaResponse)
	if referralServer == "" {
		results["error"] = "No referral WHOIS server found"
		return results
	}

	referralResponse, err := queryWHOIS(referralServer, domain)
	if err != nil {
		results["error"] = fmt.Sprintf("Referral query failed: %v", err)
		return results
	}

	results = parseWHOISResponse(referralResponse, results)
	return results
}

func queryWHOIS(server, domain string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:43", server), 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "%s\r\n", domain)
	if err != nil {
		return "", err
	}

	var response strings.Builder
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return "", err
		}
		response.WriteString(line)
	}
	return response.String(), nil
}

func extractReferral(response string) string {
	re := regexp.MustCompile(`(?i)whois:\s*(\S+)`)
	matches := re.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func parseWHOISResponse(response string, results map[string]string) map[string]string {
	patterns := map[string]string{
		"owner":           `(?i)Registrant Name:\s*(.*)`,
		"organization":    `(?i)Registrant Organization:\s*(.*)`,
		"registrar":       `(?i)Registrar:\s*(.*)`,
		"creation_date":   `(?i)Creation Date:\s*(.*)`,
		"expiration_date": `(?i)Expiration Date:\s*(.*)`,
		"updated_date":    `(?i)Updated Date:\s*(.*)`,
		"name_server":     `(?i)Name Server:\s*(.*)`,
		"status":          `(?i)Status:\s*(.*)`,
	}

	for key, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(response)
		if len(matches) > 1 {
			results[key] = strings.TrimSpace(matches[1])
		}
	}

	if len(results) <= 1 {
		results["raw_response"] = response
	}

	return results
}
