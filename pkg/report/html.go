package report

import (
	"fmt"
	"loxs/pkg/scanner"
	"loxs/pkg/utils"
	"os"
	"strings"
	"time"
)

func GenerateHTMLReport(scanType string, results []scanner.ScanResult, duration time.Duration) string {
	vulnerableURLs := ""
	totalFound := 0
	for _, res := range results {
		if res.Vulnerable {
			totalFound++
			vulnerableURLs += fmt.Sprintf(`<li class="vulnerable-item"><a href="%s" target="_blank">%s</a> - %s</li>`, res.URL, res.URL, res.Details)
		}
	}

	totalScanned := len(results)
	if totalScanned == 0 {
		totalScanned = 1 // Avoid division by zero
	}

	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Loxs Security Report</title>
    <style>
        body { font-family: 'Courier New', monospace; background-color: #111; color: #eee; padding: 20px; }
        .container { max-width: 900px; margin: 0 auto; background: #222; padding: 20px; border-radius: 8px; border: 1px solid #444; }
        h1 { color: #ff7f50; text-align: center; }
        .summary { background: #333; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .vulnerable-list { list-style: none; padding: 0; }
        .vulnerable-item { background: #3a1c1c; border: 1px solid #ff4444; padding: 10px; margin-bottom: 5px; border-radius: 3px; word-break: break-all; }
        a { color: #ff7f50; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Loxs Security Scan Report</h1>
        <div class="summary">
            <p><strong>Scan Type:</strong> %s</p>
            <p><strong>Total Vulnerabilities:</strong> %d</p>
            <p><strong>Total Scanned:</strong> %d</p>
            <p><strong>Duration:</strong> %.2fs</p>
        </div>
        <h2>Vulnerable URLs</h2>
        <ul class="vulnerable-list">
            %s
        </ul>
    </div>
</body>
</html>
`, scanType, totalFound, totalScanned, duration.Seconds(), vulnerableURLs)

	return htmlContent
}

func SaveReport(content string) {
	filename := fmt.Sprintf("report_%d.html", time.Now().Unix())
	fmt.Print(utils.Cyan("[?] Do you want to save the report? (y/n): "))
	var choice string
	fmt.Scanln(&choice)

	if choice == "y" || choice == "Y" {
		fmt.Print(utils.Cyan("[?] Enter filename (default: " + filename + "): "))
		var inputName string
		fmt.Scanln(&inputName)
		if inputName != "" {
			if !strings.HasSuffix(inputName, ".html") {
				inputName += ".html"
			}
			filename = inputName
		}

		err := os.WriteFile(filename, []byte(content), 0644)
		if err != nil {
			fmt.Println(utils.Red("[!] Failed to save report: " + err.Error()))
		} else {
			fmt.Println(utils.Green("[✓] Report saved as " + filename))
		}
	}
}
