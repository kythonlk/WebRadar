package recon

import (
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// check the lib or framework if used
func DetectTech(url string) map[string]string {
	tech := make(map[string]string)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		tech["error"] = err.Error()
		return tech
	}
	defer resp.Body.Close()

	tech["Status"] = resp.Status

	if srv := resp.Header.Get("Server"); srv != "" {
		tech["Server"] = srv
	}

	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		tech["X-Powered-By"] = powered
	}

	if link := resp.Header.Get("Link"); link != "" {
		if strings.Contains(link, "api-platform") {
			tech["API"] = "API Platform (likely)"
		}
		if strings.Contains(link, "rel=\"https://api.w.org/\"") {
			tech["CMS"] = "WordPress (REST API indicator)"
		}
	}

	// Common backend indicators in custom headers
	for k, vals := range resp.Header {
		key := strings.ToLower(k)
		for _, v := range vals {
			switch {
			case strings.Contains(key, "x-django"):
				tech["Backend"] = "Django"
				log.Println("Django", key, v)
			case strings.Contains(key, "x-laravel"):
				tech["Backend"] = "Laravel"
				log.Println("Laravel", key, v)
			case strings.Contains(key, "x-nextjs"):
			case strings.Contains(key, "x-vercel"):
				tech["Framework"] = "Next.js (Vercel)"
			case strings.Contains(key, "x-nuxt"):
				tech["Framework"] = "Nuxt.js"
			case strings.Contains(key, "x-remix"):
				tech["Framework"] = "Remix"
			case strings.Contains(key, "x-svelte"):
				tech["Framework"] = "Svelte"
			case strings.Contains(key, "x-sveltekit"):
				tech["Framework"] = "SvelteKit"
			case strings.Contains(key, "x-vue"):
				tech["Framework"] = "Vue"
			case strings.Contains(key, "x-astro"):
				tech["Framework"] = "Astro"
			}
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		tech["body_error"] = err.Error()
		return tech
	}
	body := string(bodyBytes)

	lowerBody := strings.ToLower(body)

	if strings.Contains(lowerBody, "wp-content") ||
		strings.Contains(lowerBody, "wp-includes") ||
		strings.Contains(lowerBody, "wordpress") ||
		strings.Contains(lowerBody, "wp-json") ||
		strings.Contains(lowerBody, "generator\" content=\"wordpress") {
		tech["CMS"] = "WordPress"
	}

	if strings.Contains(lowerBody, "drupal") ||
		strings.Contains(lowerBody, "sites/all") ||
		strings.Contains(lowerBody, "sites/default/files") {
		tech["CMS"] = "Drupal"
	}

	if strings.Contains(lowerBody, "joomla") ||
		strings.Contains(lowerBody, "/media/jui/") {
		tech["CMS"] = "Joomla"
	}

	if strings.Contains(lowerBody, "shopify") ||
		strings.Contains(lowerBody, "cdn.shopify.com") {
		tech["Platform"] = "Shopify"
	}

	detectJSFramework(lowerBody, tech)

	generatorRe := regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`)
	if m := generatorRe.FindStringSubmatch(body); len(m) > 1 {
		tech["Generator"] = strings.TrimSpace(m[1])
	}

	if strings.Contains(lowerBody, "next/static") ||
		strings.Contains(lowerBody, "_next/static") ||
		strings.Contains(lowerBody, "next/head") {
		tech["Framework"] = "Next.js"
	}

	if strings.Contains(lowerBody, "nuxt") ||
		strings.Contains(lowerBody, "__nuxt") {
		tech["Framework"] = "Nuxt"
	}

	if strings.Contains(lowerBody, "astro") ||
		strings.Contains(lowerBody, "astro-island") {
		tech["Framework"] = "Astro"
	}

	if strings.Contains(lowerBody, "svelte") ||
		strings.Contains(lowerBody, "svelte-") ||
		strings.Contains(lowerBody, "data-svelte") {
		tech["Framework"] = "Svelte / SvelteKit"
	}

	if strings.Contains(lowerBody, "laravel-mix") ||
		strings.Contains(lowerBody, "/js/app.js?id=") {
		tech["Backend"] = "Laravel (likely)"
	}

	return tech
}

func detectJSFramework(body string, tech map[string]string) {
	lower := strings.ToLower(body)

	if strings.Contains(lower, "react-dom") ||
		strings.Contains(lower, "react.production.min.js") ||
		strings.Contains(lower, "react.development.js") ||
		strings.Contains(lower, "__reactfiber") ||
		strings.Contains(lower, "data-reactroot") {
		tech["Frontend"] = "React"
		if strings.Contains(lower, "next/") || strings.Contains(lower, "_next/") {
			tech["Framework"] = "Next.js"
		}
	}

	// Vue
	if strings.Contains(lower, "vue.min.js") ||
		strings.Contains(lower, "vue.runtime") ||
		strings.Contains(lower, "data-v-") ||
		strings.Contains(lower, "__vue__") ||
		strings.Contains(lower, "createapp") && strings.Contains(lower, "vue") {
		tech["Frontend"] = "Vue.js"
		if strings.Contains(lower, "nuxt") {
			tech["Framework"] = "Nuxt"
		}
	}

	// Angular
	if strings.Contains(lower, "angular.min.js") ||
		strings.Contains(lower, "ng-version=") ||
		strings.Contains(lower, "ng-app") ||
		strings.Contains(lower, "ng-csp") {
		tech["Frontend"] = "Angular"
	}

	// Svelte
	if strings.Contains(lower, "svelte/internal") ||
		strings.Contains(lower, "svelte-") ||
		strings.Contains(lower, "data-svelte") {
		tech["Frontend"] = "Svelte"
	}

	// jQuery
	if strings.Contains(lower, "jquery.min.js") || strings.Contains(lower, "jquery-") {
		tech["Library"] = "jQuery"
	}

	if strings.Contains(lower, "lodash") || strings.Contains(lower, "_.assign") {
		tech["Library"] = "Lodash (likely)"
	}
}
