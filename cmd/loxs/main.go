package main

import (
	"fmt"
	"loxs/pkg/report"
	"loxs/pkg/scanner"
	"loxs/pkg/utils"
	"os"
	"strconv"
	"time"
)

func main() {
	utils.ClearScreen()
	printBanner()

	for {
		printMenu()
		choice := utils.Prompt("Select an option: ")

		if choice == "7" {
			fmt.Println(utils.Red("Exiting..."))
			os.Exit(0)
		}

		handleChoice(choice)
		utils.Prompt("\nPress Enter to return to menu...")
		utils.ClearScreen()
		printBanner()
	}
}

func printBanner() {
	banner := `
     ____           ____  ___                
    |    |    _____ \   \/  /  ______
    |    |   /     \ \     /  /  ___/
    |    |__(   O  / /     \  \___  \
    |_______/\____/ /___/\  \ /_____/ 
                          \_/                 
    `
	fmt.Println(utils.Blue(banner))
	fmt.Println(utils.White("Created by: Coffinxp | Ported to Go by BugX Agent"))
	fmt.Println(utils.White("--------------------------------------------------"))
}

func printMenu() {
	options := []string{
		"1] LFi Scanner",
		"2] OR Scanner",
		"3] SQLi Scanner",
		"4] XSS Scanner (Reflected)",
		"5] CRLF Scanner",
		"6] Tool Update",
		"7] Exit",
	}

	for _, opt := range options {
		fmt.Println(utils.Cyan(opt))
	}
	fmt.Println(utils.White("--------------------------------------------------"))
}

func handleChoice(choice string) {
	var s scanner.Scanner
	var scanType string

	switch choice {
	case "1":
		s = &scanner.LFIScanner{}
		scanType = "LFI"
	case "2":
		s = &scanner.OpenRedirectScanner{}
		scanType = "Open Redirect"
	case "3":
		s = &scanner.SQLiScanner{}
		scanType = "SQL Injection"
	case "4":
		s = &scanner.XSSScanner{}
		scanType = "XSS (Reflected)"
	case "5":
		s = &scanner.CRLFScanner{}
		scanType = "CRLF Injection"
	case "6":
		fmt.Println(utils.Yellow("Update feature not implemented in Go version yet."))
		return
	default:
		fmt.Println(utils.Red("Invalid selection!"))
		return
	}

	runScan(s, scanType)
}

func runScan(s scanner.Scanner, scanType string) {
	utils.ClearScreen()
	fmt.Println(utils.Green("Starting " + scanType + " Scanner"))

	// Get URLs
	urlInput := utils.Prompt("[?] Enter path to URL list file (or single URL): ")
	urls := []string{}

	if _, err := os.Stat(urlInput); err == nil {
		lines, err := utils.ReadLines(urlInput)
		if err != nil {
			fmt.Println(utils.Red("[!] Error reading file: " + err.Error()))
			return
		}
		urls = lines
	} else {
		// Assume single URL if file not found, basic validation
		if len(urlInput) > 0 {
			urls = []string{urlInput}
		}
	}

	if len(urls) == 0 {
		fmt.Println(utils.Red("[!] No URLs provided!"))
		return
	}

	// Get Payloads
	payloadInput := utils.Prompt("[?] Enter path to payload file: ")
	payloads := []string{}
	if _, err := os.Stat(payloadInput); err == nil {
		lines, err := utils.ReadLines(payloadInput)
		if err != nil {
			fmt.Println(utils.Red("[!] Error reading payload file: " + err.Error()))
			return
		}
		payloads = lines
	} else {
		fmt.Println(utils.Red("[!] Payload file not found!"))
		return
	}

	// Threads
	threadsInput := utils.Prompt("[?] Enter number of threads (default 5): ")
	threads, err := strconv.Atoi(threadsInput)
	if err != nil || threads <= 0 {
		threads = 5
	}

	startTime := time.Now()
	config := scanner.ScanConfig{
		URLs:     urls,
		Payloads: payloads,
		Threads:  threads,
		Timeout:  10,
	}

	results := s.Scan(config)
	duration := time.Since(startTime)

	fmt.Println(utils.Yellow("\n--------------------------------------------------"))
	fmt.Printf("Scan Finished in %.2fs\n", duration.Seconds())
	fmt.Printf("Total Vulnerabilities Found: %d\n", len(results))

	if len(results) > 0 {
		report.SaveReport(report.GenerateHTMLReport(scanType, results, duration))
	}
}
