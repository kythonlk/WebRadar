package recon

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
)

func FetchRobotsTXT(baseURL string) string {
	resp, err := http.Get(baseURL + "/robots.txt")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// Extract urls from sitemap
func FetchSitemap(baseURL string) []string {
	var urls []string

	candidates := []string{
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/sitemap/sitemap.xml",
	}

	for _, path := range candidates {
		fullURL := baseURL + path
		resp, err := http.Get(fullURL)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		defer resp.Body.Close()

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			continue
		}

		doc.Find("loc").Each(func(i int, s *goquery.Selection) {
			loc := strings.TrimSpace(s.Text())
			if loc != "" {
				urls = append(urls, loc)
			}
		})

		doc.Find("sitemap loc").Each(func(i int, s *goquery.Selection) {
			childSitemap := strings.TrimSpace(s.Text())
			if childSitemap != "" {
				urls = append(urls, "// child sitemap: "+childSitemap)
			}
		})

		if len(urls) > 0 {
			break
		}
	}

	return urls
}

func DirBrute(baseURL, wordlistPath string, threads int) []string {
	var found []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	file, err := os.Open(wordlistPath)
	if err != nil {
		return found
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	sem := make(chan struct{}, threads)

	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}

		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()

			path := strings.Trim(w, "/")
			u := fmt.Sprintf("%s/%s", baseURL, path)
			resp, err := http.Head(u)
			if err == nil && (resp.StatusCode == 200 || resp.StatusCode == 403) {
				mu.Lock()
				found = append(found, u+" ["+resp.Status+"]")
				mu.Unlock()
			}
		}(word)
	}
	wg.Wait()
	return found
}
