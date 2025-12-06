package scanner

import (
	"fmt"
	"loxs/pkg/utils"
	"regexp"
	"strings"
	"sync"
)

type XSSScanner struct{}

func (s *XSSScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting Advanced XSS Scan (Reflected, Polyglots)..."))

	// User Payloads Only (as requested)
	var payloads []string
	if len(config.Payloads) > 0 {
		payloads = config.Payloads
	}

	for _, url := range config.URLs {
		for _, payload := range payloads {
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

				// 1. Basic Reflection Check
				if utils.RegexMatch(regexp.QuoteMeta(payload), resp.Body) {
					// 2. Context Analysis (Naive)
					// If payload contains specific HTML chars and they are reflected RAW, it's likely vulnerable.
					// We check if < > " ' are escaped.

					specials := []string{"<", ">", "\"", "'"}
					escapedCount := 0
					for _, char := range specials {
						if strings.Contains(payload, char) {
							// If the response contains the CHAR, and the HTML Entity version is NOT present (or simply raw char IS present)
							// Actually, if raw char is present, it's dangerous.
							if strings.Contains(resp.Body, char) {
								// Reflected raw char!
							} else {
								escapedCount++
							}
						}
					}

					// If we reflected the payload, and key chars were NOT escaped
					if escapedCount == 0 {
						isVuln = true
						details = "Payload reflected completely unescaped"
					} else {
						// Maybe partial reflection?
						details = "Payload reflected but potentially escaped"
						// We mark as potential if full payload match found
						isVuln = true
					}
				}

				if isVuln {
					fmt.Printf("%s %s %s\n", utils.Green("[✓] XSS Found:"), utils.Cyan(targetURL), utils.Yellow("- "+details))
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
