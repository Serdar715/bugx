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
// All payloads use TOKEN which is replaced with a unique canary for verification
// This ensures we only detect injections WE caused, not existing content
var crlfPayloads = []string{
	// Basic CRLF - Set-Cookie injection (most reliable)
	"%0d%0aSet-Cookie:TOKEN=injected",
	"%0d%0aSet-Cookie: TOKEN=injected",

	// Double encoding (for WAF bypass)
	"%250d%250aSet-Cookie:TOKEN=injected",

	// X-Header injection (custom header with token)
	"%0d%0aX-Injected-By:TOKEN",

	// Location header injection (uses TOKEN domain)
	"%0d%0aLocation:https://TOKEN.test.invalid",

	// Full response injection (body contains TOKEN)
	"%0d%0a%0d%0a<html>TOKEN</html>",
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

	// Check for injected headers - ALL checks require our unique TOKEN
	injectionTypes := []string{}

	// 1. Check Set-Cookie header injection (TOKEN must be present)
	for _, cookieHeader := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(cookieHeader, token) {
			injectionTypes = append(injectionTypes, fmt.Sprintf("Set-Cookie injection: %s", cookieHeader))
		}
	}

	// 2. Check X-Injected-By header (our specific header)
	if xInjected := resp.Header.Get("X-Injected-By"); xInjected != "" {
		if strings.Contains(xInjected, token) {
			injectionTypes = append(injectionTypes, fmt.Sprintf("X-Injected-By header: %s", xInjected))
		}
	}

	// 3. Check for any header containing our TOKEN (strict check)
	for name, values := range resp.Header {
		for _, value := range values {
			// Only match if TOKEN is in the value (not just similar strings)
			if strings.Contains(value, token) {
				injectionTypes = append(injectionTypes, fmt.Sprintf("Header %s contains token: %s", name, value))
			}
		}
	}

	// 4. Check for Location header injection (TOKEN domain must be present)
	location := resp.Header.Get("Location")
	if location != "" && strings.Contains(location, token) {
		injectionTypes = append(injectionTypes, fmt.Sprintf("Location header injection: %s", location))
	}

	// 5. Check response body for injected content (CRLF response splitting)
	// Read more of the body to catch injections
	bodyBytes := make([]byte, 1024*50) // 50KB should be enough
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])

	// STRICT CHECK: Response body injection via CRLF is only confirmed if:
	// 1. Our token appears in a legitimate HTML structure that WE injected, OR
	// 2. Token appears at the very beginning of body (response splitting)

	// Check for our specific injection pattern (not just token reflection)
	if strings.Contains(body, fmt.Sprintf("<html>%s</html>", token)) {
		injectionTypes = append(injectionTypes, "Response body injection (HTML) detected")
	}

	// Check if response was truly split (token at start after double CRLF)
	if strings.HasPrefix(strings.TrimSpace(body), token) {
		injectionTypes = append(injectionTypes, "Response splitting detected")
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
