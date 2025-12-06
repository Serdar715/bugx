package scanner

import (
	"fmt"
	"loxs/pkg/utils"
	"strings"
	"sync"
)

type LFIScanner struct{}

func (s *LFIScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting Advanced LFI Scan (Wrappers, NullByte, Dual OS)..."))

	// Indicators (Key strings that confirm LFI)
	indicators := []string{
		"root:x:0:0:",
		"[fonts]",
		"[extensions]",
		"for 16-bit app support",
		"boot loader",
		"failed to open stream", // PHP Error
		"Warning: include(",
		"Warning: require(",
	}

	for _, url := range config.URLs {
		for _, payload := range config.Payloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(url, payload string) {
				defer wg.Done()
				defer func() { <-sem }()

				targetURL := url + payload
				resp, err := utils.MakeRequest(targetURL, config.Cookie, config.Timeout)

				if err != nil {
					return
				}

				isVuln := false
				details := ""

				// Standard Indicator Check
				for _, indicator := range indicators {
					if strings.Contains(resp.Body, indicator) {
						isVuln = true
						details = fmt.Sprintf("Found indicator: %s", indicator)
						break
					}
				}

				// Special check for Base64 wrapper
				// If the user payload contains base64 wrapper keywords, check for base64 output
				if strings.Contains(payload, "base64-encode") {
					// Check if body looks like base64
					if utils.RegexMatch(`^[A-Za-z0-9+/=]{20,}$`, resp.Body) || strings.Contains(resp.Body, "PD9w") { // PD9w is <?p in b64
						isVuln = true
						details = "Base64 encoded source code returned"
					}
				}

				if isVuln {
					fmt.Printf("%s %s %s\n", utils.Green("[✓] Vulnerable:"), utils.Cyan(targetURL), utils.Yellow("- "+details))
					processor.Add(ScanResult{
						URL:          targetURL,
						Vulnerable:   true,
						Payload:      payload,
						ResponseTime: resp.Duration,
						Details:      details,
					})
				}
			}(url, payload)
		}
	}

	wg.Wait()
	return processor.Results
}
