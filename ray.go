package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ANSI color codes
const (
	ColorReset   = "\033[0m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorPurple  = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorBold    = "\033[1m"
	ColorBgGreen = "\033[42m"
	ColorBgRed   = "\033[41m"
	ColorDim     = "\033[2m"
)

// FuzzMode determines what to fuzz
type FuzzMode int

const (
	ModeSingleURL FuzzMode = iota
	ModeDomainList
	ModeDomainScan
)

// Config holds all configuration
type Config struct {
	URL           string
	Wordlist      string
	DomainList    string
	DomainScan    string
	Method        string
	Headers       map[string]string
	Data          string
	Timeout       int
	Concurrency   int
	Rate          int
	MatchCodes    []int
	FilterCodes   []int
	MatchLen      []int
	FilterLen     []int
	MatchRegex    string
	FilterRegex   string
	Silent        bool
	Colors        bool
	Output        string
	Delay         int
	AutoCalibrate bool
	SaveJson      string
	FuzzMode      FuzzMode
	Verbose       bool
	MaxRetries    int
}

// Result represents a fuzzing result
type Result struct {
	URL         string    `json:"url"`
	StatusCode  int       `json:"status"`
	Length      int       `json:"length"`
	Word        string    `json:"word"`
	Time        float64   `json:"time"`
	Lines       int       `json:"lines"`
	Words       int       `json:"words"`
	Hash        string    `json:"hash"`
	ContentType string    `json:"content_type"`
	Title       string    `json:"title"`
	Timestamp   time.Time `json:"timestamp"`
	Anomaly     bool      `json:"anomaly"`
}

// StatusSummary tracks results by status code
type StatusSummary struct {
	Code    int
	Count   int
	Samples []string
}

// Stats tracks real-time statistics
type Stats struct {
	Total       int64
	Requests    int64
	Matches     int64
	Errors      int64
	StartTime   time.Time
	LastPrint   time.Time
	BaselineLen int
	BaselineCode int
	StatusCodes map[int]int
	Lock        sync.RWMutex
}

type AnomalyDetector struct {
	BaselineLen  int
	BaselineCode int
	LenThreshold float64
	CodeDiff     bool
}

var (
	config           Config
	stats            Stats
	anomalyDetector  AnomalyDetector
	results          []Result
	resultsLock      sync.Mutex
	sigChan          = make(chan os.Signal, 1)
)

func main() {
	printBanner()
	parseFlags()
	validateConfig()

	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	stats.StartTime = time.Now()
	stats.LastPrint = time.Now()
	stats.StatusCodes = make(map[int]int)

	// Load wordlist
	words, err := loadWordlist(config.Wordlist)
	if err != nil {
		fatal(fmt.Sprintf("Error loading wordlist: %v", err))
	}
	stats.Total = int64(len(words))

	// Determine fuzz mode and load targets
	var targets []string
	switch config.FuzzMode {
	case ModeSingleURL:
		targets = []string{config.URL}
		if !config.Silent {
			fmt.Printf("%s[+] Mode: Single URL Fuzzing%s\n", ColorGreen, ColorReset)
		}
	case ModeDomainList:
		domains, err := loadDomainList(config.DomainList)
		if err != nil {
			fatal(fmt.Sprintf("Error loading domain list: %v", err))
		}
		targets = domains
		stats.Total = int64(len(words) * len(domains))
		if !config.Silent {
			fmt.Printf("%s[+] Mode: Domain List Fuzzing (%d domains)%s\n", ColorGreen, len(domains), ColorReset)
		}
	case ModeDomainScan:
		domains, err := loadDomainList(config.DomainScan)
		if err != nil {
			fatal(fmt.Sprintf("Error loading domain scan list: %v", err))
		}
		targets = domains
		// For domain scan, we're just checking the domains themselves
		if !config.Silent {
			fmt.Printf("%s[+] Mode: Domain Enumeration Scan (%d domains)%s\n", ColorGreen, len(domains), ColorReset)
		}
		stats.Total = int64(len(domains))
	}

	if !config.Silent {
		printConfig(words, targets)
	}

	// Create optimized HTTP client
	client := createOptimizedClient()

	// Auto-calibrate baseline
	if config.AutoCalibrate && config.FuzzMode == ModeSingleURL {
		calibrateBaseline(client)
	}

	// Compile regex patterns
	var matchRe, filterRe *regexp.Regexp
	if config.MatchRegex != "" {
		matchRe = regexp.MustCompile(config.MatchRegex)
	}
	if config.FilterRegex != "" {
		filterRe = regexp.MustCompile(config.FilterRegex)
	}

	// Create context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup channels
	jobs := make(chan Job, config.Concurrency*3)
	jobResults := make(chan Result, config.Concurrency*2)

	// Rate limiter
	var rateLimiter <-chan time.Time
	if config.Rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(config.Rate))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, jobResults, client, matchRe, filterRe, rateLimiter)
	}

	// Results collector
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go resultCollector(ctx, &collectWg, jobResults)

	// Live stats printer
	var statsWg sync.WaitGroup
	statsWg.Add(1)
	go statsPrinter(ctx, &statsWg)

	// Job dispatcher
	go func() {
		defer close(jobs)
		switch config.FuzzMode {
		case ModeSingleURL:
			for _, word := range words {
				select {
				case <-sigChan:
					return
				case jobs <- Job{URL: config.URL, Word: word}:
				}
			}
		case ModeDomainList:
			for _, target := range targets {
				for _, word := range words {
					select {
					case <-sigChan:
						return
					case jobs <- Job{URL: target, Word: word}:
					}
				}
			}
		case ModeDomainScan:
			for _, target := range targets {
				select {
				case <-sigChan:
					return
				case jobs <- Job{URL: target, Word: ""}:
				}
			}
		}
	}()

	// Graceful shutdown handler
	go func() {
		<-sigChan
		if !config.Silent {
			fmt.Printf("\n%s[!] Graceful shutdown initiated...%s\n", ColorYellow, ColorReset)
		}
		cancel()
	}()

	// Wait for completion
	wg.Wait()
	close(jobResults)
	collectWg.Wait()
	statsWg.Wait()

	// Final output
	if !config.Silent {
		printFinalStats()
	}

	// Save results
	if config.SaveJson != "" {
		saveResults()
	}
	if config.Output != "" {
		saveOutput()
	}
}

// Job represents a fuzzing task
type Job struct {
	URL  string
	Word string
}

// createOptimizedClient creates a highly optimized HTTP client
func createOptimizedClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	transport := &http.Transport{
		Dial:                  dialer.Dial,
		DialContext:           dialer.DialContext,
		MaxIdleConns:          config.Concurrency * 2,
		MaxIdleConnsPerHost:   config.Concurrency,
		MaxConnsPerHost:       config.Concurrency,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:        tls.VersionTLS12,
		},
		DisableKeepAlives:     false,
		DisableCompression:    false,
		ResponseHeaderTimeout: time.Duration(config.Timeout) * time.Second,
	}

	return &http.Client{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		Transport: transport,
	}
}

// calibrateBaseline detects baseline response
func calibrateBaseline(client *http.Client) {
	if !config.Silent {
		fmt.Printf("%s[*] Calibrating baseline...%s\n", ColorYellow, ColorReset)
	}

	testWord := "BASELINEXYZ" + strconv.FormatInt(time.Now().Unix(), 10)
	testURL := strings.ReplaceAll(config.URL, "FUZZ", testWord)

	req, _ := http.NewRequest("GET", testURL, nil)
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		stats.BaselineLen = len(body)
		stats.BaselineCode = resp.StatusCode
		anomalyDetector.BaselineLen = stats.BaselineLen
		anomalyDetector.BaselineCode = stats.BaselineCode
		anomalyDetector.LenThreshold = float64(stats.BaselineLen) * 0.15

		if !config.Silent {
			fmt.Printf("%s[+] Baseline: %d bytes, Status %d%s\n", ColorGreen, stats.BaselineLen, stats.BaselineCode, ColorReset)
		}
	}
}

// worker processes jobs
func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Job, results chan<- Result, 
	client *http.Client, matchRe, filterRe *regexp.Regexp, rateLimiter <-chan time.Time) {
	defer wg.Done()

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			if rateLimiter != nil {
				<-rateLimiter
			}
			if config.Delay > 0 {
				time.Sleep(time.Millisecond * time.Duration(config.Delay))
			}

			var result Result
			if config.FuzzMode == ModeDomainScan {
				result = domainScan(client, job.URL)
			} else {
				result = fuzz(client, job.URL, job.Word)
			}

			atomic.AddInt64(&stats.Requests, 1)
			stats.Lock.Lock()
			stats.StatusCodes[result.StatusCode]++
			stats.Lock.Unlock()

			if shouldDisplay(result, matchRe, filterRe) {
				atomic.AddInt64(&stats.Matches, 1)
				results <- result
			}
		}
	}
}

// fuzz performs a fuzzing request
func fuzz(client *http.Client, targetURL, word string) Result {
	start := time.Now()

	encodedWord := url.PathEscape(word)
	targetURL = strings.ReplaceAll(targetURL, "FUZZ", encodedWord)
	body := strings.ReplaceAll(config.Data, "FUZZ", word)

	var req *http.Request
	var err error
	if config.Data != "" {
		req, err = http.NewRequest(config.Method, targetURL, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(config.Method, targetURL, nil)
	}

	if err != nil {
		atomic.AddInt64(&stats.Errors, 1)
		return Result{URL: targetURL, StatusCode: 0, Word: word, Time: time.Since(start).Seconds(), Timestamp: time.Now()}
	}

	// Add headers
	for key, value := range config.Headers {
		req.Header.Set(key, value)
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "RAY/1.0 (Security Scanner)")
	}

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddInt64(&stats.Errors, 1)
		return Result{URL: targetURL, StatusCode: 0, Word: word, Time: time.Since(start).Seconds(), Timestamp: time.Now()}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	length := len(bodyBytes)
	bodyStr := string(bodyBytes)
	lines := strings.Count(bodyStr, "\n") + 1
	words := len(strings.Fields(bodyStr))

	// Extract title
	title := extractTitle(bodyStr)

	return Result{
		URL:         targetURL,
		StatusCode:  resp.StatusCode,
		Length:      length,
		Word:        word,
		Time:        time.Since(start).Seconds(),
		Lines:       lines,
		Words:       words,
		ContentType: resp.Header.Get("Content-Type"),
		Title:       title,
		Timestamp:   time.Now(),
		Anomaly:     detectAnomaly(length, resp.StatusCode),
	}
}

// domainScan checks if a domain is alive
func domainScan(client *http.Client, domain string) Result {
	start := time.Now()

	// Ensure domain has scheme
	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "https://" + domain
	}

	req, _ := http.NewRequest("GET", domain, nil)
	req.Header.Set("User-Agent", "RAY/1.0 (Security Scanner)")

	resp, err := client.Do(req)
	if err != nil {
		// Try HTTP if HTTPS fails
		if strings.HasPrefix(domain, "https://") {
			domain = strings.Replace(domain, "https://", "http://", 1)
			req, _ := http.NewRequest("GET", domain, nil)
			req.Header.Set("User-Agent", "RAY/1.0 (Security Scanner)")
			resp, err = client.Do(req)
			if err != nil {
				atomic.AddInt64(&stats.Errors, 1)
				return Result{URL: domain, StatusCode: 0, Time: time.Since(start).Seconds(), Timestamp: time.Now()}
			}
		} else {
			atomic.AddInt64(&stats.Errors, 1)
			return Result{URL: domain, StatusCode: 0, Time: time.Since(start).Seconds(), Timestamp: time.Now()}
		}
	}

	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)
	length := len(bodyBytes)
	bodyStr := string(bodyBytes)
	lines := strings.Count(bodyStr, "\n") + 1
	words := len(strings.Fields(bodyStr))
	title := extractTitle(bodyStr)

	return Result{
		URL:         domain,
		StatusCode:  resp.StatusCode,
		Length:      length,
		Time:        time.Since(start).Seconds(),
		Lines:       lines,
		Words:       words,
		ContentType: resp.Header.Get("Content-Type"),
		Title:       title,
		Timestamp:   time.Now(),
	}
}

// detectAnomaly detects anomalous responses
func detectAnomaly(length, code int) bool {
	if config.AutoCalibrate && stats.BaselineLen > 0 {
		diff := float64(length - stats.BaselineLen)
		if diff < 0 {
			diff = -diff
		}
		return diff > anomalyDetector.LenThreshold
	}
	return false
}

// extractTitle extracts title from HTML
func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// shouldDisplay checks if result should be displayed
func shouldDisplay(result Result, matchRe, filterRe *regexp.Regexp) bool {
	if result.StatusCode == 0 {
		return false
	}

	// Status code filters
	if len(config.MatchCodes) > 0 && !intContains(config.MatchCodes, result.StatusCode) {
		return false
	}
	if len(config.FilterCodes) > 0 && intContains(config.FilterCodes, result.StatusCode) {
		return false
	}

	// Length filters
	if len(config.MatchLen) > 0 && !intContains(config.MatchLen, result.Length) {
		return false
	}
	if len(config.FilterLen) > 0 && intContains(config.FilterLen, result.Length) {
		return false
	}

	return true
}

// resultCollector collects results
func resultCollector(ctx context.Context, wg *sync.WaitGroup, jobResults <-chan Result) {
	defer wg.Done()

	for res := range jobResults {
		resultsLock.Lock()
		results = append(results, res)
		resultsLock.Unlock()
		printResult(res)
	}
}

// printResult prints a result
func printResult(result Result) {
	if config.Silent {
		fmt.Println(result.URL)
		return
	}

	statusColor := getStatusColor(result.StatusCode)
	anomalyMarker := ""
	if result.Anomaly {
		anomalyMarker = " " + ColorRed + "⚠" + ColorReset
	}

	if config.Colors {
		fmt.Printf("[%s%3d%s] [%sLen: %8d%s] [%sL: %4d%s] [%sW: %6d%s] [%s%.3fs%s]%s %s%-50s%s",
			statusColor, result.StatusCode, ColorReset,
			ColorCyan, result.Length, ColorReset,
			ColorBlue, result.Lines, ColorReset,
			ColorBlue, result.Words, ColorReset,
			ColorYellow, result.Time, ColorReset,
			anomalyMarker,
			ColorGreen+ColorBold, truncate(result.Word, 50), ColorReset)

		if result.Title != "" {
			fmt.Printf(" | %s%s%s", ColorPurple, truncate(result.Title, 40), ColorReset)
		}
		if result.ContentType != "" {
			fmt.Printf(" | %s%s%s", ColorDim, truncate(result.ContentType, 30), ColorReset)
		}
		fmt.Println()
	} else {
		fmt.Printf("[%d] [Len: %d] [L: %d] [W: %d] [%.3fs] %s\n",
			result.StatusCode, result.Length, result.Lines, result.Words, result.Time, result.Word)
	}
}

// getStatusColor returns color for status code
func getStatusColor(code int) string {
	if !config.Colors {
		return ""
	}
	switch {
	case code >= 200 && code < 300:
		return ColorGreen + ColorBold
	case code >= 300 && code < 400:
		return ColorYellow + ColorBold
	case code >= 400 && code < 500:
		return ColorRed
	case code >= 500:
		return ColorPurple + ColorBold
	default:
		return ColorWhite
	}
}

// truncate truncates string to max length
func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

// statsPrinter prints live statistics
func statsPrinter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if config.Silent {
				continue
			}
			elapsed := time.Since(stats.StartTime)
			if elapsed.Seconds() > 0 {
				reqPerSec := float64(stats.Requests) / elapsed.Seconds()
				fmt.Fprintf(os.Stderr, "%s[%s] Req: %d | Matches: %d | Errors: %d | Rate: %.0f/s%s\r",
					ColorDim, time.Now().Format("15:04:05"), stats.Requests, stats.Matches, stats.Errors, reqPerSec, ColorReset)
			}
		}
	}
}

// printFinalStats prints final statistics
func printFinalStats() {
	fmt.Printf("\n\n%s╔════════════════════════════════════════════════════════════╗%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Printf("%s║               ✓ FUZZING COMPLETED SUCCESSFULLY             ║%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorBold+ColorCyan, ColorReset)

	elapsed := time.Since(stats.StartTime)
	reqPerSec := float64(stats.Requests) / elapsed.Seconds()

	fmt.Printf("%s[Statistics]%s\n", ColorBold+ColorYellow, ColorReset)
	fmt.Printf("  %-25s: %s%d%s\n", "Total Requests", ColorGreen, stats.Requests, ColorReset)
	fmt.Printf("  %-25s: %s%d%s\n", "Matches Found", ColorGreen+ColorBold, stats.Matches, ColorReset)
	fmt.Printf("  %-25s: %s%d%s\n", "Errors", ColorRed, stats.Errors, ColorReset)
	fmt.Printf("  %-25s: %s%v%s\n", "Time Elapsed", ColorCyan, elapsed.Round(time.Millisecond), ColorReset)
	fmt.Printf("  %-25s: %s%.2f%s req/s\n", "Request Rate", ColorGreen+ColorBold, reqPerSec, ColorReset)

	// Print status code summary
	fmt.Printf("\n%s[Status Codes Summary]%s\n", ColorBold+ColorYellow, ColorReset)
	
	stats.Lock.RLock()
	var codes []int
	for code := range stats.StatusCodes {
		codes = append(codes, code)
	}
	stats.Lock.RUnlock()
	
	sort.Ints(codes)
	for _, code := range codes {
		count := stats.StatusCodes[code]
		color := getStatusColor(code)
		fmt.Printf("  %s[%d]%s: %d results\n", color, code, ColorReset, count)
	}

	fmt.Println()
}

// printBanner prints animated banner
func printBanner() {
	frames := []string{
		fmt.Sprintf("%s╦═╗╔═╗╦ ╦%s", ColorCyan+ColorBold, ColorReset),
		fmt.Sprintf("%s╠╦╝╠═╣╚╦╝%s", ColorGreen+ColorBold, ColorReset),
		fmt.Sprintf("%s╩╚═╩ ╩ ╩%s", ColorYellow+ColorBold, ColorReset),
	}

	for _, frame := range frames {
		fmt.Println(frame)
	}

	banner := fmt.Sprintf(`%s  🚀 World's Best Web Fuzzer
  High-Performance Security Scanner
  Developed by Biswajeet Ray
  %s%s`,
		ColorPurple+ColorBold,
		time.Now().Format("2006-01-02 15:04:05"),
		ColorReset)

	fmt.Println(banner)
	fmt.Printf("%s▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓%s\n\n", ColorGreen, ColorReset)
}

// printConfig prints configuration
func printConfig(words []string, targets []string) {
	fmt.Printf("%s[Configuration]%s\n", ColorBold+ColorYellow, ColorReset)
	fmt.Printf("  %-25s: %d words\n", "Wordlist", len(words))
	fmt.Printf("  %-25s: %d targets\n", "Targets", len(targets))
	fmt.Printf("  %-25s: %s\n", "Method", config.Method)
	fmt.Printf("  %-25s: %d workers\n", "Concurrency", config.Concurrency)
	fmt.Printf("  %-25s: %ds\n", "Timeout", config.Timeout)
	if config.Rate > 0 {
		fmt.Printf("  %-25s: %d req/s\n", "Rate Limit", config.Rate)
	}
	if config.AutoCalibrate && config.FuzzMode != ModeDomainScan {
		fmt.Printf("  %-25s: %s\n", "Auto-Calibrate", "ENABLED")
	}
	fmt.Printf("\n%s[Starting Scan]%s\n\n", ColorBold+ColorGreen, ColorReset)
}

// parseFlags parses command-line arguments
func parseFlags() {
	flag.StringVar(&config.URL, "u", "", "Target URL with FUZZ placeholder")
	flag.StringVar(&config.Wordlist, "w", "", "Wordlist file")
	flag.StringVar(&config.DomainList, "L", "", "List of domains to fuzz")
	flag.StringVar(&config.DomainScan, "scan", "", "List of domains to scan")
	flag.StringVar(&config.Method, "X", "GET", "HTTP method")
	flag.StringVar(&config.Data, "d", "", "POST data")
	flag.IntVar(&config.Timeout, "timeout", 10, "Timeout in seconds")
	flag.IntVar(&config.Concurrency, "c", 100, "Concurrency level")
	flag.IntVar(&config.Rate, "rate", 0, "Rate limit (req/s)")
	flag.IntVar(&config.Delay, "delay", 0, "Delay per request (ms)")
	flag.IntVar(&config.MaxRetries, "retries", 2, "Max retries")
	flag.BoolVar(&config.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&config.Colors, "colors", true, "Colorized output")
	flag.BoolVar(&config.AutoCalibrate, "calibrate", false, "Auto-calibrate baseline")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose mode")
	flag.StringVar(&config.Output, "o", "", "Output file")
	flag.StringVar(&config.SaveJson, "json", "", "Save as JSON")

	var mc, fc, ml, fl, headers string
	flag.StringVar(&mc, "mc", "", "Match status codes (200,201)")
	flag.StringVar(&fc, "fc", "", "Filter status codes (404,403)")
	flag.StringVar(&ml, "ml", "", "Match length")
	flag.StringVar(&fl, "fl", "", "Filter length")
	flag.StringVar(&config.MatchRegex, "mr", "", "Match regex")
	flag.StringVar(&config.FilterRegex, "fr", "", "Filter regex")
	flag.StringVar(&headers, "H", "", "Custom headers (Key:Value,Key:Value)")

	flag.Parse()

	// Parse headers
	config.Headers = make(map[string]string)
	if headers != "" {
		for _, h := range strings.Split(headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				config.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Parse integer lists
	if mc != "" {
		config.MatchCodes = parseIntList(mc)
	}
	if fc != "" {
		config.FilterCodes = parseIntList(fc)
	}
	if ml != "" {
		config.MatchLen = parseIntList(ml)
	}
	if fl != "" {
		config.FilterLen = parseIntList(fl)
	}

	// Determine fuzz mode
	if config.URL != "" {
		config.FuzzMode = ModeSingleURL
	} else if config.DomainList != "" {
		config.FuzzMode = ModeDomainList
	} else if config.DomainScan != "" {
		config.FuzzMode = ModeDomainScan
	}
}

// validateConfig validates configuration
func validateConfig() {
	if config.URL == "" && config.DomainList == "" && config.DomainScan == "" {
		fatal("Specify -u (URL), -L (domain list), or -scan (domain scan)")
	}
	if config.URL != "" && config.DomainList != "" {
		fatal("Cannot use both -u and -L")
	}
	if config.URL != "" && config.DomainScan != "" {
		fatal("Cannot use both -u and -scan")
	}
	if config.DomainList != "" && config.DomainScan != "" {
		fatal("Cannot use both -L and -scan")
	}
	if config.Wordlist == "" && config.FuzzMode != ModeDomainScan {
		fatal("Wordlist (-w) is required for fuzzing")
	}
	if config.URL != "" && !strings.Contains(config.URL, "FUZZ") {
		fatal("URL must contain FUZZ placeholder")
	}
	if config.Concurrency < 1 {
		config.Concurrency = 1
	}
	if config.Concurrency > 2000 {
		config.Concurrency = 2000
	}
}

// loadWordlist loads words from file
func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			words = append(words, word)
		}
	}
	return words, scanner.Err()
}

// loadDomainList loads domains from file
func loadDomainList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" && !strings.HasPrefix(domain, "#") {
			// For fuzzing mode, ensure FUZZ placeholder
			if config.FuzzMode == ModeDomainList {
				if !strings.Contains(domain, "FUZZ") {
					domain = strings.TrimRight(domain, "/") + "/FUZZ"
				}
			}
			domains = append(domains, domain)
		}
	}
	return domains, scanner.Err()
}

// Helper functions
func parseIntList(s string) []int {
	var result []int
	for _, part := range strings.Split(s, ",") {
		if num, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
			result = append(result, num)
		}
	}
	return result
}

func intContains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// saveResults saves results as JSON
func saveResults() {
	resultsLock.Lock()
	defer resultsLock.Unlock()

	file, err := os.Create(config.SaveJson)
	if err != nil {
		return
	}
	defer file.Close()

	// Sort by status code
	sort.Slice(results, func(i, j int) bool {
		if results[i].StatusCode != results[j].StatusCode {
			return results[i].StatusCode < results[j].StatusCode
		}
		return results[i].Length > results[j].Length
	})

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(results)

	if !config.Silent {
		fmt.Printf("%s[+] Results saved to %s (%d matches)%s\n", ColorGreen, config.SaveJson, len(results), ColorReset)
	}
}

// saveOutput saves results as text
func saveOutput() {
	resultsLock.Lock()
	defer resultsLock.Unlock()

	file, err := os.Create(config.Output)
	if err != nil {
		return
	}
	defer file.Close()

	// Sort by status code
	sort.Slice(results, func(i, j int) bool {
		if results[i].StatusCode != results[j].StatusCode {
			return results[i].StatusCode < results[j].StatusCode
		}
		return results[i].URL < results[j].URL
	})

	for _, r := range results {
		line := fmt.Sprintf("[%d] %s (Len: %d, Lines: %d, Words: %d, Time: %.3fs)\n",
			r.StatusCode, r.URL, r.Length, r.Lines, r.Words, r.Time)
		file.WriteString(line)
		if r.Title != "" {
			file.WriteString(fmt.Sprintf("    Title: %s\n", r.Title))
		}
	}

	if !config.Silent {
		fmt.Printf("%s[+] Output saved to %s (%d matches)%s\n", ColorGreen, config.Output, len(results), ColorReset)
	}
}

// fatal prints error and exits
func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "%s[ERROR]%s %s\n", ColorRed+ColorBold, ColorReset, msg)
	os.Exit(1)
}
