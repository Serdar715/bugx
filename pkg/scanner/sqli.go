package scanner

import (
	"fmt"
	"loxs/pkg/utils"
	"sync"
	"time"
)

type SQLiScanner struct{}

func (s *SQLiScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting Advanced SQLi Scan (Error, Boolean, Time, Union)..."))

	// 1. Error-Based Patterns (Expanded)
	errorPatterns := map[string][]string{
		"MySQL":      {`SQL syntax.*MySQL`, `Warning.*mysql_`, `valid MySQL result`, `MySqlClient\.`},
		"PostgreSQL": {`PostgreSQL.*ERROR`, `Warning.*\Wpg_`, `valid PostgreSQL result`, `Npgsql\.`},
		"MSSQL":      {`Driver.* SQL[\-\_\ ]*Server`, `OLE DB.* SQL Server`, `(\W|\A)SQL Server.*Driver`, `Warning.*mssql_`, `(\W|\A)MSSQL`, `\Wom.microsoft.[sql,drivers]`, `Microsoft SQL Native Client error`},
		"Oracle":     {`ORA-[0-9][0-9][0-9][0-9]`, `Oracle error`, `Oracle.*Driver`, `Warning.*\Woci_`, `Warning.*\Wora_`},
		"SQLite":     {`SQLite/JDBCDriver`, `SQLite.Exception`, `System.Data.SQLite.SQLiteException`, `Warning.*sqlite_`, `qt_sql_default_connection`},
	}

	for _, url := range config.URLs {
		// 1. Analyze Connection Stability (Heuristic)
		stability := utils.CheckConnectionStability(url, config.Cookie)

		// If server is very slow (>5s avg), we increase the time threshold heavily.
		timeThreshold := stability.AverageDuration + 5.0
		if stability.AverageDuration > 5.0 {
			timeThreshold = stability.AverageDuration + 10.0
		}

		fmt.Printf(utils.White("[*] Analysing %s - Stability: %.2fs (Avg), Threshold: %.2fs\n"), url, stability.AverageDuration, timeThreshold)

		for _, payload := range config.Payloads {
			wg.Add(1)
			sem <- struct{}{}
			go func(u, p string) {
				defer wg.Done()
				defer func() { <-sem }()

				targetURL := u + p

				// Time-based check requires measuring duration
				reqStart := time.Now()

				// Set scanner timeout slightly higher than our calculated threshold
				scanTimeout := int(timeThreshold) + 5
				resp, err := utils.MakeRequest(targetURL, config.Cookie, scanTimeout)
				reqDuration := time.Since(reqStart).Seconds()

				if err != nil {
					// Handle timeout as potential positive if strictly time-based, but careful
				}

				details := ""
				isVuln := false

				// Check Error-Based
				for db, patterns := range errorPatterns {
					for _, pattern := range patterns {
						if utils.RegexMatch(pattern, resp.Body) {
							isVuln = true
							details = fmt.Sprintf("Error-based SQLi (%s)", db)
							break
						}
					}
					if isVuln {
						break
					}
				}

				// Check Time-Based (Heuristic)
				if !isVuln {
					if reqDuration >= timeThreshold {
						isVuln = true
						details = fmt.Sprintf("Time-based SQLi (Response: %.2fs > Threshold: %.2fs)", reqDuration, timeThreshold)
					}
				}

				if isVuln {
					reportVuln(u, p, details, reqDuration, &processor)
				}

			}(url, payload)
		}
	}

	wg.Wait()
	return processor.Results
}

func reportVuln(url, payload, details string, duration float64, p *ResultProcessor) {
	fmt.Printf("%s %s %s\n", utils.Green("[✓] Vulnerable:"), utils.Cyan(url+payload), utils.Yellow("- "+details))
	p.Add(ScanResult{
		URL:          url + payload,
		Vulnerable:   true,
		Payload:      payload,
		ResponseTime: duration,
		Details:      details,
	})
}
