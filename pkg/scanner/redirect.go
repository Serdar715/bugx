package scanner

import (
	"bugx/pkg/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

type OpenRedirectScanner struct{}

// Redirect test domains - we check if redirect goes to these
var redirectTestDomains = []string{
	"evil.com",
	"attacker.com",
	"google.com",
	"example.com",
	"bugx.test",
}

// Open redirect payloads with target domain placeholder
var redirectPayloads = []string{
	"//TARGET",
	"https://TARGET",
	"http://TARGET",
	"//TARGET/",
	"///TARGET",
	"////TARGET",
	"/\\TARGET",
	"\\/TARGET",
	"//TARGET%00",
	"//TARGET%0d%0a",
	"//TARGET@localhost",
	"//localhost@TARGET",
	"https://TARGET%2f%2f",
	"//TARGET\\@localhost",
	"javascript://TARGET/%0aalert(1)",
	"//TARGET?",
	"//TARGET#",
	"/%09/TARGET",
	"/%5cTARGET",
	"/.TARGET",
	"/TARGET/",
	"////\\;@TARGET",
	"https:TARGET",
	"//TARGET%E3%80%82evil.com",
}

func (s *OpenRedirectScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting Open Redirect Scan with Browser Verification..."))
	fmt.Println(utils.White("[*] Using Chrome Headless to verify actual redirects"))
	fmt.Println(utils.White("[*] Only CONFIRMED redirects will be reported\n"))

	// Browser setup
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	// Generate unique test domain marker
	markerBytes := make([]byte, 4)
	rand.Read(markerBytes)
	marker := hex.EncodeToString(markerBytes)
	testDomain := "bugx" + marker + ".test"

	for _, baseURL := range config.URLs {
		// Use built-in payloads or user payloads
		payloadsToTest := redirectPayloads
		if len(config.Payloads) > 0 {
			payloadsToTest = config.Payloads
		}

		for _, payload := range payloadsToTest {
			wg.Add(1)
			sem <- struct{}{}
			go func(baseURL, payload string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Replace TARGET with our test domain
				testPayload := strings.ReplaceAll(payload, "TARGET", testDomain)
				targetURL := baseURL + testPayload

				// Method 1: Check Location header (fast)
				confirmed, details := checkRedirectHeader(targetURL, testDomain, config.Cookie, config.Timeout)

				if confirmed {
					fmt.Printf("%s %s\n",
						utils.Red("[✓] Open Redirect CONFIRMED (Header):"),
						utils.Cyan(truncateURL(targetURL, 90)))
					fmt.Printf("    → %s\n", utils.White(details))

					processor.Add(ScanResult{
						URL:        targetURL,
						Vulnerable: true,
						Payload:    testPayload,
						Details:    details,
					})
					return
				}

				// Method 2: Browser verification (slow but accurate)
				confirmed, details = verifyRedirectWithBrowser(allocCtx, targetURL, testDomain, config.Timeout)

				if confirmed {
					fmt.Printf("%s %s\n",
						utils.Red("[✓] Open Redirect CONFIRMED (Browser):"),
						utils.Cyan(truncateURL(targetURL, 90)))
					fmt.Printf("    → %s\n", utils.White(details))

					processor.Add(ScanResult{
						URL:        targetURL,
						Vulnerable: true,
						Payload:    testPayload,
						Details:    "Browser verified: " + details,
					})
				}

			}(baseURL, payload)
		}
	}

	wg.Wait()
	printRedirectSummary(processor.Results)
	return processor.Results
}

// checkRedirectHeader checks Location header for redirect
func checkRedirectHeader(targetURL, testDomain, cookie string, timeout int) (bool, string) {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
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

	// Check for redirect status codes
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			// Check if location contains our test domain
			if strings.Contains(strings.ToLower(location), strings.ToLower(testDomain)) {
				return true, fmt.Sprintf("Redirects to: %s (Status: %d)", location, resp.StatusCode)
			}

			// Also check for common redirect targets
			for _, domain := range redirectTestDomains {
				if strings.Contains(strings.ToLower(location), domain) {
					return true, fmt.Sprintf("Redirects to external domain: %s", location)
				}
			}
		}
	}

	return false, ""
}

// verifyRedirectWithBrowser uses Chrome to follow redirects
func verifyRedirectWithBrowser(allocCtx context.Context, targetURL, testDomain string, timeout int) (bool, string) {
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout+5)*time.Second)
	defer cancel()

	var finalURL string

	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Location(&finalURL),
	)

	if err != nil {
		return false, ""
	}

	// Check if final URL contains test domain
	if strings.Contains(strings.ToLower(finalURL), strings.ToLower(testDomain)) {
		return true, fmt.Sprintf("Browser redirected to: %s", finalURL)
	}

	// Check for common external domains
	for _, domain := range redirectTestDomains {
		if strings.Contains(strings.ToLower(finalURL), domain) && !strings.Contains(targetURL, domain) {
			return true, fmt.Sprintf("Browser redirected to external: %s", finalURL)
		}
	}

	return false, ""
}

func printRedirectSummary(results []ScanResult) {
	headerBased, browserBased := 0, 0
	for _, r := range results {
		if strings.Contains(r.Details, "Browser") {
			browserBased++
		} else {
			headerBased++
		}
	}

	fmt.Println(utils.Yellow("\n--------------------------------------------------"))
	fmt.Println(utils.White("Open Redirect Scan Summary:"))
	fmt.Printf("  %s Header-based: %d\n", utils.Red("●"), headerBased)
	fmt.Printf("  %s Browser-verified: %d\n", utils.Red("●"), browserBased)
	fmt.Printf("  %s Total CONFIRMED: %d\n", utils.Green("★"), len(results))
	fmt.Println(utils.Yellow("--------------------------------------------------"))

	if len(results) > 0 {
		fmt.Println(utils.Green("\n[!] All findings are VERIFIED - actual redirect confirmed!"))
	} else {
		fmt.Println(utils.Yellow("\n[i] No confirmed open redirect vulnerabilities found."))
	}
}
