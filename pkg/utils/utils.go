package utils

import (
	"bufio"
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
	// Setup generic readline config
	// Removing the restrictive AutoComplete checks allows users to type any path.
	// While chzyer/readline doesn't always have "smart" file completion out of the box without config,
	// the previous configuration was actively preventing using paths outside the current directory
	// because it was hardcoded to `listFiles(".")`.
	// By removing it, we at least stop breaking the input.
	// For full file completion, we would need a complex recursive function,
	// but for now, let's unlock the input.

	rl, err := readline.NewEx(&readline.Config{
		Prompt:          Cyan(text),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
		HistoryFile:     "",
		// AutoComplete: nil, // Let's rely on default behavior or just raw input
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
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
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
