package scanner

import (
	"fmt"
	"loxs/pkg/utils"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CRLFScanner struct{}

func (s *CRLFScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting CRLF Scan..."))

	for _, url := range config.URLs {
		for _, payload := range config.Payloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(url, payload string) {
				defer wg.Done()
				defer func() { <-sem }()

				targetURL := url + payload
				start := time.Now()

				client := &http.Client{
					Timeout: 10 * time.Second,
					CheckRedirect: func(req *http.Request, via []*http.Request) error {
						return http.ErrUseLastResponse
					},
				}

				req, err := http.NewRequest("GET", targetURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", utils.GetRandomUserAgent())

				resp, err := client.Do(req)
				elapsed := time.Since(start).Seconds()

				if err != nil {
					return
				}
				defer resp.Body.Close()

				isVuln := false
				details := ""

				// Check headers for injection
				for key, values := range resp.Header {
					for _, val := range values {
						// Check if our payload (or part of it, specifically 'injected') is in headers
						// Common payload: %0d%0aSet-Cookie:loxs=injected
						if strings.Contains(strings.ToLower(key), "set-cookie") && strings.Contains(val, "loxs=injected") {
							isVuln = true
							details = fmt.Sprintf("Header Injection found in %s: %s", key, val)
						}
						if strings.Contains(strings.ToLower(key), "location") && strings.Contains(val, "loxs.pages.dev") {
							isVuln = true
							details = fmt.Sprintf("Open Redirect via Header Injection: %s", val)
						}
					}
				}

				if isVuln {
					fmt.Printf("%s %s %s\n", utils.Green("[✓] Vulnerable:"), utils.Cyan(targetURL), utils.Yellow("- "+details))
					processor.Add(ScanResult{
						URL:          targetURL,
						Vulnerable:   true,
						Payload:      payload,
						ResponseTime: elapsed,
						Details:      details,
					})
				} else {
					fmt.Printf("%s %s\n", utils.Red("[✗] Not Vulnerable:"), targetURL)
				}

			}(url, payload)
		}
	}

	wg.Wait()
	return processor.Results
}
