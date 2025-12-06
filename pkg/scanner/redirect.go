package scanner

import (
	"fmt"
	"loxs/pkg/utils"
	"net/http"
	"strings"
	"sync"
	"time"
)

type OpenRedirectScanner struct{}

func (s *OpenRedirectScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting Open Redirect Scan..."))

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

				// Check Location header
				location := resp.Header.Get("Location")
				if location != "" {
					// Check if redirected to google.com or typical payload targets
					if strings.Contains(location, "google.com") || strings.Contains(location, "example.com") {
						isVuln = true
						details = fmt.Sprintf("Redirected to: %s", location)
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
