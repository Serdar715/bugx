<div align="center">

# 🔥 BUGX

```
  ____  _   _  ____ __  __
 | __ )| | | |/ ___\ \/ /
 |  _ \| | | | |  _  \  / 
 | |_) | |_| | |_| | /  \ 
 |____/ \___/ \____|/_/\_\
```

### **Advanced Web Vulnerability Scanner**

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![License](https://img.shields.io/badge/License-BSD_3-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20Windows%20|%20macOS-blue?style=for-the-badge)]()

**A high-performance, multi-threaded web vulnerability scanner with advanced false-positive reduction techniques.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-scanner-modules) • [Documentation](#-documentation)

</div>

---

## 🎯 Overview

**BugX** is a next-generation vulnerability scanner designed for security professionals and bug bounty hunters. Unlike traditional scanners that flood you with false positives, BugX employs **advanced verification techniques** inspired by industry-leading tools like SQLMap, Nuclei, and Dalfox.

### Why BugX?

| Traditional Scanners | BugX |
|---------------------|------|
| Pattern matching only | **Multi-layer verification** |
| High false positive rate | **Confirmed vulnerabilities only** |
| Single detection method | **Hybrid detection (Error + Time + Boolean)** |
| Basic signature matching | **Deep content analysis with canary tokens** |

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 **Smart Detection**
- Multi-pattern signature matching
- Baseline comparison to eliminate FPs
- Unique canary token verification
- Content similarity analysis (Jaccard)

</td>
<td width="50%">

### ⚡ **High Performance**
- Fully concurrent architecture
- Configurable thread pools
- Optimized HTTP client
- Batch URL processing

</td>
</tr>
<tr>
<td>

### 🛡️ **Accuracy First**
- Triple verification for time-based SQLi
- Network stability detection
- Browser-verified XSS (Headless Chrome)
- Strict pattern requirements

</td>
<td>

### 📊 **Professional Reporting**
- Clean HTML reports
- Real-time terminal output
- Severity classification
- Export-ready format

</td>
</tr>
</table>

---

## 📥 Installation

### Prerequisites
- **Go 1.25+** installed
- **Chrome/Chromium** (for XSS verification)

### Quick Install

```bash
# Clone the repository
git clone https://github.com/Serdar715/bugx.git

# Navigate to directory
cd bugx

# Install dependencies and build
go mod tidy && go build -o bugx cmd/bugx/main.go

# Run BugX
./bugx
```

### One-Liner Install

```bash
git clone https://github.com/Serdar715/bugx.git && cd bugx && go mod tidy && go build -o bugx cmd/bugx/main.go && ./bugx
```

---

## 🚀 Usage

### Interactive Mode

```bash
./bugx
```

```
┌──────────────────────────────────┐
│           BUGX MENU              │
├──────────────────────────────────┤
│  1] LFI Scanner                  │
│  2] Open Redirect Scanner        │
│  3] SQLi Scanner                 │
│  4] XSS Scanner (Reflected)      │
│  5] CRLF Scanner                 │
│  6] Tool Update                  │
│  7] Exit                         │
└──────────────────────────────────┘
```

### Update Tool

```bash
./bugx -update
```

---

## 🔧 Scanner Modules

### 1️⃣ LFI Scanner
**Local File Inclusion Detection**

| Feature | Description |
|---------|-------------|
| **Signatures** | `/etc/passwd`, `/etc/shadow`, `win.ini`, `/etc/group` |
| **Verification** | 4+ pattern matches required |
| **FP Reduction** | Baseline comparison, required patterns |

```
[✓] LFI CONFIRMED: http://target.com/page.php?file=../../../etc/passwd
    → Signature: etc_passwd (Linux)
    → Matched 5 patterns
```

### 2️⃣ SQLi Scanner
**SQL Injection Detection**

| Detection Type | Technique |
|---------------|-----------|
| **Error-based** | Database-specific error patterns |
| **Time-based** | Triple verification (2/3 required) |
| **Boolean-based** | Content similarity + length analysis |

```
[✓] SQLi CONFIRMED (Time-based): http://target.com/search?id=1
    → MySQL detected (delay: 5.2s)
    → Verified 3/3 attempts
```

### 3️⃣ XSS Scanner
**Cross-Site Scripting Detection**

| Feature | Description |
|---------|-------------|
| **Verification** | Headless Chrome with dialog interception |
| **Canary Token** | Unique token must appear in alert message |
| **Auto-Execute** | Only payloads requiring no user interaction |

```
[✓] XSS CONFIRMED: http://target.com/search?q=<payload>
    → JavaScript alert() triggered with canary: bugx7a3f2b
```

### 4️⃣ Open Redirect Scanner
**Unvalidated Redirect Detection**

| Feature | Description |
|---------|-------------|
| **Test Domains** | Unique `.invalid` TLD domains |
| **Verification** | Header + Browser redirect check |
| **Payloads** | Protocol-relative, encoding bypasses |

### 5️⃣ CRLF Scanner
**HTTP Response Splitting Detection**

| Feature | Description |
|---------|-------------|
| **Token-based** | Unique canary in injected headers |
| **Detection** | Set-Cookie, Location, X-Header injection |
| **Verification** | Token must appear in response headers |

---

## 📁 Project Structure

```
bugx/
├── cmd/bugx/
│   └── main.go           # Entry point
├── pkg/
│   ├── scanner/
│   │   ├── lfi.go        # LFI scanner module
│   │   ├── sqli.go       # SQLi scanner module
│   │   ├── xss.go        # XSS scanner module
│   │   ├── redirect.go   # Open Redirect scanner
│   │   └── crlf.go       # CRLF scanner module
│   ├── utils/
│   │   └── utils.go      # Utility functions
│   └── report/
│       └── html.go       # HTML report generator
├── payloads/
│   ├── lfi.txt           # LFI payloads
│   ├── sqli.txt          # SQLi payloads
│   └── xss.txt           # XSS payloads
└── reports/              # Generated HTML reports
```

---

## 📚 Documentation

### Input Format

**urls.txt** - One URL per line with parameters:
```
http://target.com/page.php?file=test
http://target.com/search?q=query&id=1
http://target.com/redirect?url=home
```

### Report Output

Reports are automatically generated in `reports/` directory:
- `lfi_report_2024-01-19.html`
- `sqli_report_2024-01-19.html`
- etc.

---

## 🔐 False Positive Reduction Techniques

BugX employs multiple layers of verification to ensure accurate results:

```
┌─────────────────────────────────────────────────────────────┐
│                    VERIFICATION PIPELINE                     │
├─────────────────────────────────────────────────────────────┤
│  1. BASELINE CAPTURE     → Record normal response           │
│  2. PAYLOAD INJECTION    → Send malicious payload           │
│  3. PATTERN MATCHING     → Check for vulnerability signs    │
│  4. CANARY VERIFICATION  → Ensure OUR payload triggered it  │
│  5. RE-VERIFICATION      → Test again for consistency       │
│  6. CONFIRMATION         → Only report if all checks pass   │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Disclaimer

> **This tool is intended for authorized security testing only.**
>
> Usage of BugX for attacking targets without prior mutual consent is **illegal**. 
> The developers assume no liability for any misuse or damage caused by this program.
> 
> Always obtain proper authorization before testing any system.

---


<div align="center">

**Made with ❤️ for the Security Community**

</div>

