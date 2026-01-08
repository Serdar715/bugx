# BUGX

```
  ____  _   _  ____ __  __
 | __ )| | | |/ ___|\ \/ /
 |  _ \| | | | |  _  \  / 
 | |_) | |_| | |_| | /  \ 
 |____/ \___/ \____|/_/\_\
```

**BugX** is a highly advanced, modular, and multi-threaded web vulnerability scanner written in Go. It is designed for security professionals and bug bounty hunters to automate the detection of common web vulnerabilities with high accuracy and low false positives.

## 🚀 Key Features

*   **🔍 Smart LFI Scanner:** Goes beyond simple string matching. It verifies Local File Inclusion by checking known file signatures (e.g., `/etc/passwd`, `win.ini`) and supports base64 wrapper detection.
*   **💉 Advanced SQLi Scanner:** Uses multiple detection techniques including Error-based, Boolean-based, and Time-based blind injection (with heuristic checks) to confirm vulnerabilities.
*   **🛡️ XSS Scanner:** specialized in Reflected XSS, testing various contexts to ensure the payload is reflected and executed.
*   **🌐 Open Redirect & CRLF:** Efficiently scans for Unvalidated Redirects and HTTP Response Splitting vulnerabilities.
*   **⚡ High Performance:** Fully concurrent architecture allows scanning thousands of URLs in seconds using configurable threads.
*   **📊 HTML Reporting:** Automatically generates detailed, professional HTML reports for all confirmed findings.
*   **🔄 Auto-Update:** Built-in self-update mechanism to fetch the latest changes from the repository.

---

## 📥 Installation

1.  **Prerequisites:** Ensure you have **Go 1.25+** installed.
2.  **Quick Install:** Run the following command to clone, install dependencies, and build the tool in one go:

    ```bash
    git clone https://github.com/Serdar715/bugx.git && cd bugx && go mod tidy && go build -o bugx cmd/bugx/main.go
    ```

---

## 🛠️ Usage

**BugX** operates primarily in an interactive mode, guiding you through the scanning process.

### 1. Basic Execution
Start the tool by running the executable:

```bash
./bugx
```

You will be presented with a sleek interactive menu:

```text
1] LFi Scanner
2] OR Scanner
3] SQLi Scanner
4] XSS Scanner (Reflected)
5] CRLF Scanner
6] Tool Update
7] Exit
```

### 2. Updating the Tool
BugX includes a self-update feature. To update to the latest version immediately:

```bash
./bugx -update
```

---

## 📋 detailed Workflow

To get the best results, follow this recommended workflow:

### Step 1: Prepare Your Targets
Create a text file (e.g., `urls.txt`) containing the list of URLs you want to scan. Ensure parameters are included for fuzzing.

**Example `urls.txt`:**
```text
http://testphp.vulnweb.com/artists.php?artist=1
http://example.com/page.php?file=index
https://target.com/search?q=query
```

### Step 2: Prepare Payloads (Optional)
BugX comes with optimized default payloads in the `payloads/` directory. However, you can create your own custom payload file (e.g., `lfi_payloads.txt`).

**Example `custom_payloads.txt`:**
```text
../../../../etc/passwd
' OR 1=1 --
<script>alert(1)</script>
```

### Step 3: Run the Scan
1.  Select your desired scanner from the menu (e.g., `3` for SQLi).
2.  **URL Input:** Enter the path to your `urls.txt`.
3.  **Payload Input:** Enter the path to your payload file (e.g., `payloads/lfi.txt`).
4.  **Threads:** Choose the number of concurrent threads (Default is `5`). Higher numbers increase speed but may trigger WAFs.

### Step 4: Analyze Results
*   **Live Output:** Vulnerabilities will appear in the terminal with a `[✓] CONFIRMED` tag in green/red.
*   **HTML Report:** Once the scan is complete, an HTML report file will be generated in the `reports/` folder. Open this file in your browser to view a structured summary of findings.

---

## 🧠 Scanner Modules Explained

| Module | Description | Detection Method |
| :--- | :--- | :--- |
| **LFI Scanner** | Detects local file inclusion flaws. | Checks for file content signatures (e.g., "root:x:0:0") in responses to confirm successful inclusion, drastically reducing false positives. |
| **SQLi Scanner** | Identifies SQL injection vectors. | Uses a hybrid approach: **Error-based** parsing, **Boolean-based** content length comparison, and **Time-based** delay analysis. |
| **XSS Scanner** | Finds Reflected XSS vulnerabilities. | Injects specific probes and analyzes the HTTP response body to verify if the input is reflected without sanitization. |
| **OR Scanner** | Check for Open Redirects. | Validates if the application redirects to an external, attacker-controlled domain (e.g., `google.com`) provided in the payload. |
| **CRLF Scanner** | Detects HTTP Response Splitting. | Injects CRLF characters (`%0d%0a`) and checks if they successfully inject new headers or modify the response structure. |

---

## ⚖️ Disclaimer

> **⚠️ WARNING:** This tool is developed for **educational and authorized security testing purposes only**. Usage of this tool for attacking targets without prior mutual consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---
