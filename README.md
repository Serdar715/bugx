# Loxs - Advanced Web Security Scanner

![Go Version](https://img.shields.io/badge/go-%3E%3D1.19-00ADD8.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg?style=flat-square)

**Loxs** is a high-performance, professional-grade web vulnerability scanner written in Go. It is designed to identify critical security flaws such as SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion (LFI), Open Redirects, and CRLF Injection with high accuracy and minimal false positives.

Unlike traditional scanners, **Loxs** employs **Smart Connection Analysis** and **Heuristic Detection Algorithms** to adapt to the target server's response time and stability, ensuring reliable detection of Blind inconsistencies.

## 🚀 Features

### 🧠 Smart Intelligence
-   **Connection Stability Analysis:** Automatically measures server jitter and average response time before scanning.
-   **Dynamic Thresholds:** Adjusts time-based attack thresholds dynamically based on server latency (e.g., if a server takes 5s to respond, the sleep payload threshold automatically adapts).
-   **Context-Aware XSS:** Detects if payloads are reflected raw or properly escaped, reducing false positives.

### 🔥 supported Vulnerabilities
-   **SQL Injection (SQLi):**
    -   Error-Based (30+ patterns for MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
    -   Time-Based Blind (Heuristic detection with dynamic timeouts).
    -   Boolean-Based Blind (Differential analysis).
-   **Cross-Site Scripting (XSS):**
    -   Reflected XSS detection.
    -   Polyglot payload support.
    -   Context-specific escaping analysis.
-   **Local File Inclusion (LFI):**
    -   Dual OS Support (Linux `/etc/passwd` & Windows `win.ini`).
    -   PHP Wrapper Detection (`php://filter`, `php://input`).
    -   Null Byte Injection & Path Truncation checks.
-   **Open Redirect (OR):**
    -   Header-based location checks.
-   **CRLF Injection:**
    -   HTTP Response Splitting & Header Injection detection.

### ⚡ Performance
-   **Multi-Threaded:** Concurrent scanning with configurable thread counts.
-   **Go Routine Architecture:** Ultra-fast request handling compared to Python-based predecessors.
-   **Low Memory Footprint:** Efficient resource management.

## 📦 Installation

### From Source
```bash
# Clone the repository
git clone https://github.com/coffinxp/bugx.git
cd bugx

# Install dependencies
go mod tidy

# Build the binary
go build -o loxs cmd/loxs/main.go

# Run
./loxs
```

## 🛠 Usage

Loxs requires two user-provided files:
1.  **URL List:** A text file containing target URLs (one per line).
2.  **Payload List:** A text file containing attack payloads (one per line).

```bash
./loxs
```

Follow the interactive menu:
1.  Select the vulnerability type (e.g., SQLi, XSS).
2.  Enter the path to your **URL list** (e.g., `urls.txt`).
3.  Enter the path to your **Payload list** (e.g., `payloads.txt`).
4.  Set the number of threads (Default: 5).

### Example Output
```text
[i] Starting Advanced SQLi Scan (Error, Boolean, Time, Union)...
[*] Analysing http://testphp.vulnweb.com - Stability: 0.23s (Avg), Threshold: 5.23s
[✓] Vulnerable: http://testphp.vulnweb.com/artists.php?artist=1' - Error-based SQLi (MySQL)
[✓] Vulnerable: http://testphp.vulnweb.com/test?id=1' + SLEEP(10) -- - Time-based SQLi (Response: 10.05s)
```

## 📊 Reporting
Loxs automatically generates a clean, styled **HTML Report** containing:
-   Scan summary (Duration, Total Scanned, Vulnerabilities Found).
-   List of vulnerable URLs with specific details.
-   Clickable links for verification.

## ⚠️ Disclaimer
This tool is developed for **educational purposes and authorized security testing only**. The usage of this tool on targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
*Created by Coffinxp | Ported & Enhanced by BugX*
