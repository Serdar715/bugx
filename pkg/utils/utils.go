package utils

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"path/filepath"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
)

var (
	Red    = color.New(color.FgRed).SprintFunc()
	Green  = color.New(color.FgGreen).SprintFunc()
	Yellow = color.New(color.FgYellow).SprintFunc()
	Blue   = color.New(color.FgBlue).SprintFunc()
	Cyan   = color.New(color.FgCyan).SprintFunc()
	White  = color.New(color.FgWhite).SprintFunc()
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func GetRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func ClearScreen() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "cls")
	} else {
		cmd = exec.Command("clear")
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func Prompt(text string) string {
	// Use custom FileCompleter to fix trailing space and navigation
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          Cyan(text),
		AutoComplete:    &FileCompleter{},
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistoryFile:     "",
	})
	if err != nil {
		// Fallback
		fmt.Print(Cyan(text))
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		return strings.TrimSpace(input)
	}
	defer rl.Close()

	line, err := rl.Readline()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

// FileCompleter implements readline.AutoCompleter
type FileCompleter struct{}

func (c *FileCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	path := string(line[:pos])

	// Find matches
	matches, err := filepath.Glob(path + "*")
	if err != nil || len(matches) == 0 {
		return nil, 0
	}

	var candidates [][]rune
	for _, match := range matches {
		info, err := os.Stat(match)
		// If directory, append separator to navigation easier
		if err == nil && info.IsDir() {
			match += string(os.PathSeparator)
		}

		// Suffix Strategy:
		// We only return the part of the match that hasn't been typed yet.
		// Length 0 tells readline to "append" this candidate.
		if strings.HasPrefix(match, path) {
			suffix := match[len(path):]
			candidates = append(candidates, []rune(suffix))
		} else {
			// If prefix doesn't match exactly (e.g. case sensitivity issues or ./ normalization),
			// we fallback to complete replacement of the basename to be safe,
			// though on Linux Glob usually respects the prefix.
			// Ideally we skip or handle carefully. For now, strict prefix is safest.
		}
	}

	// Return suffixes with 0 length to append them
	return candidates, 0
}

func ReadLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// RequestResponse holds basic response info
type RequestResponse struct {
	Body       string
	StatusCode int
	Duration   float64
}

func MakeRequest(url string, cookie string, timeout int) (RequestResponse, error) {
	// Disable HTTP/2 by setting TLSNextProto to empty map
	// Also skip SSL verification for scanning headers
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		TLSNextProto:    make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return RequestResponse{}, err
	}

	req.Header.Set("User-Agent", GetRandomUserAgent())
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start).Seconds()

	if err != nil {
		return RequestResponse{}, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := ioutil.ReadAll(resp.Body)

	return RequestResponse{
		Body:       string(bodyBytes),
		StatusCode: resp.StatusCode,
		Duration:   duration,
	}, nil
}

type ConnectionStability struct {
	AverageDuration float64
	MaxDuration     float64
	IsStable        bool
}

func CheckConnectionStability(url string, cookie string) ConnectionStability {
	var totalDuration float64
	var maxDuration float64
	iterations := 5

	for i := 0; i < iterations; i++ {
		resp, err := MakeRequest(url, cookie, 10)
		if err != nil {
			continue
		}
		totalDuration += resp.Duration
		if resp.Duration > maxDuration {
			maxDuration = resp.Duration
		}
	}

	avg := totalDuration / float64(iterations)

	return ConnectionStability{
		AverageDuration: avg,
		MaxDuration:     maxDuration,
		IsStable:        (maxDuration - avg) < 1.0, // Considered stable if jitter is < 1s
	}
}

func RegexMatch(pattern string, content string) bool {
	matched, _ := regexp.MatchString(pattern, content)
	return matched
}

// ContentSimilarity calculates the similarity ratio between two strings
// using a simple token-based Jaccard similarity (inspired by SQLMap's page comparison)
// Returns a value between 0.0 (completely different) and 1.0 (identical)
func ContentSimilarity(content1, content2 string) float64 {
	if content1 == content2 {
		return 1.0
	}
	if len(content1) == 0 || len(content2) == 0 {
		return 0.0
	}

	// Simple word tokenization
	words1 := strings.Fields(content1)
	words2 := strings.Fields(content2)

	if len(words1) == 0 || len(words2) == 0 {
		// Fall back to length-based comparison
		shorter := len(content1)
		longer := len(content2)
		if shorter > longer {
			shorter, longer = longer, shorter
		}
		return float64(shorter) / float64(longer)
	}

	// Create word sets
	set1 := make(map[string]bool)
	for _, w := range words1 {
		set1[w] = true
	}

	set2 := make(map[string]bool)
	for _, w := range words2 {
		set2[w] = true
	}

	// Calculate intersection and union
	intersection := 0
	for w := range set1 {
		if set2[w] {
			intersection++
		}
	}

	union := len(set1)
	for w := range set2 {
		if !set1[w] {
			union++
		}
	}

	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// FindUniqueStrings finds strings that appear in content but NOT in baseline
// This is used to identify potential "positive match" indicators (like SQLMap's --string)
func FindUniqueStrings(content, baseline string, minLen int) []string {
	if minLen < 3 {
		minLen = 3
	}

	contentWords := strings.Fields(content)
	baselineSet := make(map[string]bool)
	for _, w := range strings.Fields(baseline) {
		baselineSet[w] = true
	}

	var unique []string
	seen := make(map[string]bool)
	for _, w := range contentWords {
		if len(w) >= minLen && !baselineSet[w] && !seen[w] {
			unique = append(unique, w)
			seen[w] = true
		}
	}

	return unique
}

// FindChromePath attempts to locate the Chrome executable in common locations
func FindChromePath() string {
	var paths []string

	switch runtime.GOOS {
	case "windows":
		paths = []string{
			os.Getenv("ProgramFiles") + "\\Google\\Chrome\\Application\\chrome.exe",
			os.Getenv("ProgramFiles(x86)") + "\\Google\\Chrome\\Application\\chrome.exe",
			os.Getenv("LocalAppData") + "\\Google\\Chrome\\Application\\chrome.exe",
			"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
			"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
		}
	case "darwin":
		paths = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "linux":
		paths = []string{
			"/usr/bin/google-chrome",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
		}
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Return empty string to let chromedp attempt default detection
	return ""
}
