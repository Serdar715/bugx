# BUGX

```
  ____  _   _  ____ __  __
 | __ )| | | |/ ___|\ \/ /
 |  _ \| | | | |  _  \  / 
 | |_) | |_| | |_| | /  \ 
 |____/ \___/ \____|/_/\_\
```

**BugX** is a powerful, modular vulnerability scanner written in Go. It supports detecting various web vulnerabilities including LFI, SQLi, XSS, CRLF Injection, and Open Redirects.

## Features

- **LFI Scanner**: Detects Local File Inclusion vulnerabilities with confirmed file signature matching.
- **SQLi Scanner**: Scans for SQL Injection flaws.
- **XSS Scanner**: Checks for Reflected Cross-Site Scripting.
- **CRLF Scanner**: Identifies CRLF injection points.
- **Open Redirect Scanner**: Finds open redirect vulnerabilities.
- **Reports**: Generates HTML reports for findings.
- **Multi-threaded**: Fast scanning with configurable threads.
- **Modular**: Easy to extend with new scanners.

## Installation

1. Ensure you have Go installed (version 1.25+ recommended).
2. Clone the repository:
   ```bash
   git clone https://github.com/Serdar715/bugx.git && cd bugx && go mod tidy && go build -o bugx cmd/bugx/main.go
   ```

## Usage

**BugX** is designed to be easy to use with an interactive command-line interface.

### Running the Tool
To start the scanner, simply run the executable:

```bash
./bugx
```

### Scanning Workflow
1.  **Select a Module:** Choose the vulnerability type you want to test (e.g., LFI, SQLi) from the main menu.
2.  **Target List:** Provide the path to a text file containing the target URLs.
    *   **Format:** One URL per line (e.g., `http://example.com/page.php?id=1`).
    *   *Tip:* You can also enter a single URL directly.
3.  **Payloads:** Provide the path to a payload file.
    *   The tool comes with default payloads in the `payloads/` directory.
4.  **Concurrency:** Set the number of threads (Default: 5) to control scan speed.

### Updating
To update the tool to the latest version directly from the repository:

```bash
./bugx -update
```

### Output & Reports
*   **Console:** Real-time findings are displayed in the terminal with colored status indicators.
*   **HTML Reports:** If confirmed vulnerabilities are found, a comprehensive HTML report is automatically generated in the `reports/` directory.

## Disclaimer

This tool is for educational and authorized security testing purposes only. Usage of this tool for attacking targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.


