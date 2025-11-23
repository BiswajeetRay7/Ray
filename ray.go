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
	ColorDim     = "\033[2m"
)

// FuzzMode determines what to fuzz
type FuzzMode int

const (
	ModeSingleURL FuzzMode = iota
	ModeDomainList
	ModeDomainScan
)

// MultiFlag allows repeated flags (e.g. -H "A: B" -H "C: D")
type MultiFlag []string

func (m *MultiFlag) String() string {
	return strings.Join(*m, ", ")
}

func (m *MultiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// Config holds all configuration
type Config struct {
	URL           string
	Wordlist      string
	DomainList    string
	DomainScan    string
	Method        string
	Headers       MultiFlag 
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
	ContentType string    `json:"content_type"`
	Title       string    `json:"title"`
	Timestamp   time.Time `json:"timestamp"`
	Anomaly     bool      `json:"anomaly"`
	Error       error     `json:"-"`
}

// Stats tracks real-time statistics
type Stats struct {
	Total        int64
	Requests     int64
	Matches      int64
	Errors       int64
	StartTime    time.Time
	BaselineLen  int
	BaselineCode int
	StatusCodes  map[int]int
	Lock         sync.RWMutex
}

type AnomalyDetector struct {
	BaselineLen  int
	LenThreshold float64
}

var (
	config          Config
	stats           Stats
	anomalyDetector AnomalyDetector
	results         []Result
	resultsLock     sync.Mutex
)

func main() {
	// 1. Setup Context and Signal Handling
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Printf("\n%s[!] Shutting down gracefully...%s\n", ColorRed, ColorReset)
		cancel()
	}()

	// 2. Initialization
	printBanner()
	parseFlags()
	validateConfig()

	stats.StartTime = time.Now()
	stats.StatusCodes = make(map[int]int)

	// 3. Load Resources
	words, err := loadWordlist(config.Wordlist)
	if err != nil && config.FuzzMode != ModeDomainScan {
		fatal(fmt.Sprintf("Error loading wordlist: %v", err))
	}

	var targets []string
	switch config.FuzzMode {
	case ModeSingleURL:
		targets = []string{config.URL}
		stats.Total = int64(len(words))
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
		stats.Total = int64(len(domains))
		if !config.Silent {
			fmt.Printf("%s[+] Mode: Domain Enumeration (%d domains)%s\n", ColorGreen, len(domains), ColorReset)
		}
	}

	if !config.Silent {
		printConfig(len(words), len(targets))
	}

	// 4. HTTP Client & Regex
	client := createOptimizedClient()

	// Calibration
	if config.AutoCalibrate && config.FuzzMode == ModeSingleURL {
		calibrateBaseline(ctx, client)
	}

	var matchRe, filterRe *regexp.Regexp
	if config.MatchRegex != "" {
		matchRe = regexp.MustCompile(config.MatchRegex)
	}
	if config.FilterRegex != "" {
		filterRe = regexp.MustCompile(config.FilterRegex)
	}

	// 5. Pipelines
	jobs := make(chan Job, config.Concurrency)
	jobResults := make(chan Result, config.Concurrency)

	// Rate Limiter
	var rateLimiter <-chan time.Time
	if config.Rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(config.Rate))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// 6. Start Workers
	var wg sync.WaitGroup
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go worker(ctx, &wg, jobs, jobResults, client, matchRe, filterRe, rateLimiter)
	}

	// 7. Start Collector & Stats Printer
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go resultCollector(&collectWg, jobResults)

	var statsWg sync.WaitGroup
	statsWg.Add(1)
	go statsPrinter(ctx, &statsWg)

	// 8. Dispatch Jobs
	go func() {
		defer close(jobs)
		
		if config.FuzzMode == ModeDomainScan {
			for _, target := range targets {
				select {
				case <-ctx.Done():
					return
				case jobs <- Job{URL: target, Word: ""}:
				}
			}
			return
		}

		// Fuzzing Modes
		for _, target := range targets {
			for _, word := range words {
				select {
				case <-ctx.Done():
					return
				case jobs <- Job{URL: target, Word: word}:
				}
			}
		}
	}()

	// 9. Wait and Cleanup
	wg.Wait()        
	close(jobResults) 
	collectWg.Wait() 
	statsWg.Wait()   

	if !config.Silent {
		printFinalStats()
	}

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

func createOptimizedClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          config.Concurrency,
		MaxIdleConnsPerHost:   config.Concurrency, 
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(config.Timeout) * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DisableKeepAlives: false,
	}

	return &http.Client{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse 
		},
	}
}

func calibrateBaseline(ctx context.Context, client *http.Client) {
	if !config.Silent {
		fmt.Printf("%s[*] Calibrating baseline...%s\n", ColorYellow, ColorReset)
	}

	// Use a random string that is unlikely to exist
	testWord := "R4ND0M" + strconv.FormatInt(time.Now().Unix(), 10)
	testURL := strings.ReplaceAll(config.URL, "FUZZ", testWord)

	req, _ := http.NewRequestWithContext(ctx, config.Method, testURL, nil)
	addHeaders(req)
	
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		stats.BaselineLen = len(body)
		stats.BaselineCode = resp.StatusCode
		anomalyDetector.BaselineLen = stats.BaselineLen
		anomalyDetector.LenThreshold = float64(stats.BaselineLen) * 0.15 

		if !config.Silent {
			fmt.Printf("%s[+] Baseline: %d bytes, Status %d%s\n", ColorGreen, stats.BaselineLen, stats.BaselineCode, ColorReset)
		}
	}
}

func worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Job, results chan<- Result,
	client *http.Client, matchRe, filterRe *regexp.Regexp, rateLimiter <-chan time.Time) {
	defer wg.Done()

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if rateLimiter != nil {
			select {
			case <-rateLimiter:
			case <-ctx.Done():
				return
			}
		}
		
		if config.Delay > 0 {
			time.Sleep(time.Millisecond * time.Duration(config.Delay))
		}

		var result Result
		if config.FuzzMode == ModeDomainScan {
			result = domainScan(ctx, client, job.URL)
		} else {
			result = fuzz(ctx, client, job.URL, job.Word)
		}

		atomic.AddInt64(&stats.Requests, 1)
		
		if result.Error == nil {
			stats.Lock.Lock()
			stats.StatusCodes[result.StatusCode]++
			stats.Lock.Unlock()

			if shouldDisplay(result, matchRe, filterRe) {
				atomic.AddInt64(&stats.Matches, 1)
				results <- result
			}
		} else {
			atomic.AddInt64(&stats.Errors, 1)
		}
	}
}

func fuzz(ctx context.Context, client *http.Client, targetURL, word string) Result {
	start := time.Now()

	finalURL := strings.ReplaceAll(targetURL, "FUZZ", word)
	bodyStr := strings.ReplaceAll(config.Data, "FUZZ", word)

	var req *http.Request
	var err error
	
	if config.Data != "" {
		req, err = http.NewRequestWithContext(ctx, config.Method, finalURL, strings.NewReader(bodyStr))
	} else {
		req, err = http.NewRequestWithContext(ctx, config.Method, finalURL, nil)
	}

	if err != nil {
		return Result{URL: finalURL, Error: err, Timestamp: time.Now()}
	}

	addHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return Result{URL: finalURL, Error: err, Timestamp: time.Now()}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{URL: finalURL, Error: err, Timestamp: time.Now()}
	}

	length := len(bodyBytes)
	bodyString := string(bodyBytes)
	
	return Result{
		URL:         finalURL,
		StatusCode:  resp.StatusCode,
		Length:      length,
		Word:        word,
		Time:        time.Since(start).Seconds(),
		Lines:       strings.Count(bodyString, "\n") + 1,
		Words:       len(strings.Fields(bodyString)),
		ContentType: resp.Header.Get("Content-Type"),
		Title:       extractTitle(bodyString),
		Timestamp:   time.Now(),
		Anomaly:     detectAnomaly(length),
	}
}

func domainScan(ctx context.Context, client *http.Client, domain string) Result {
	start := time.Now()
	
	target := domain
	if !strings.HasPrefix(target, "http") {
		target = "https://" + domain
	}

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return Result{URL: target, Error: err}
	}
	
	req.Header.Set("User-Agent", "RAY/1.0 (Scanner)")

	resp, err := client.Do(req)
	// If HTTPS fails, try HTTP
	if err != nil && strings.HasPrefix(target, "https://") {
		target = strings.Replace(target, "https://", "http://", 1)
		req, _ = http.NewRequestWithContext(ctx, "GET", target, nil)
		req.Header.Set("User-Agent", "RAY/1.0 (Scanner)")
		resp, err = client.Do(req)
	}

	if err != nil {
		return Result{URL: domain, Error: err}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	return Result{
		URL:         target,
		StatusCode:  resp.StatusCode,
		Length:      len(bodyBytes),
		Time:        time.Since(start).Seconds(),
		Lines:       strings.Count(bodyString, "\n") + 1,
		Words:       len(strings.Fields(bodyString)),
		ContentType: resp.Header.Get("Content-Type"),
		Title:       extractTitle(bodyString),
		Timestamp:   time.Now(),
	}
}

func addHeaders(req *http.Request) {
	for _, h := range config.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "RAY/1.0 (Security Scanner)")
	}
}

func detectAnomaly(length int) bool {
	if config.AutoCalibrate && stats.BaselineLen > 0 {
		diff := float64(length - stats.BaselineLen)
		if diff < 0 {
			diff = -diff
		}
		return diff > anomalyDetector.LenThreshold
	}
	return false
}

func extractTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func shouldDisplay(result Result, matchRe, filterRe *regexp.Regexp) bool {
	if result.StatusCode == 0 {
		return false
	}

	// Default: If no filters/matchers specified, show everything except 404
	if len(config.MatchCodes) == 0 && len(config.FilterCodes) == 0 && len(config.MatchLen) == 0 {
		if result.StatusCode == 404 {
			return false
		}
	}

	if len(config.MatchCodes) > 0 && !intContains(config.MatchCodes, result.StatusCode) {
		return false
	}
	if len(config.FilterCodes) > 0 && intContains(config.FilterCodes, result.StatusCode) {
		return false
	}
	if len(config.MatchLen) > 0 && !intContains(config.MatchLen, result.Length) {
		return false
	}
	if len(config.FilterLen) > 0 && intContains(config.FilterLen, result.Length) {
		return false
	}

	return true
}

func resultCollector(wg *sync.WaitGroup, jobResults <-chan Result) {
	defer wg.Done()
	for res := range jobResults {
		resultsLock.Lock()
		results = append(results, res)
		resultsLock.Unlock()
		printResult(res)
	}
}

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
		fmt.Printf("[%s%3d%s] [%sLen: %8d%s] [%sL: %4d%s] [%sW: %6d%s] [%s%.3fs%s]%s %s%-40s%s",
			statusColor, result.StatusCode, ColorReset,
			ColorCyan, result.Length, ColorReset,
			ColorBlue, result.Lines, ColorReset,
			ColorBlue, result.Words, ColorReset,
			ColorYellow, result.Time, ColorReset,
			anomalyMarker,
			ColorGreen+ColorBold, truncate(result.Word, 40), ColorReset)

		if result.Title != "" {
			fmt.Printf(" | %s%s%s", ColorPurple, truncate(result.Title, 30), ColorReset)
		}
		fmt.Println()
	} else {
		fmt.Printf("[%d] [Len: %d] [L: %d] [W: %d] [%.3fs] %s\n",
			result.StatusCode, result.Length, result.Lines, result.Words, result.Time, result.URL)
	}
}

func getStatusColor(code int) string {
	if !config.Colors { return "" }
	switch {
	case code >= 200 && code < 300: return ColorGreen + ColorBold
	case code >= 300 && code < 400: return ColorYellow + ColorBold
	case code >= 400 && code < 500: return ColorRed
	case code >= 500: return ColorPurple + ColorBold
	default: return ColorWhite
	}
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

func statsPrinter(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if config.Silent { continue }
			elapsed := time.Since(stats.StartTime)
			if elapsed.Seconds() > 0 {
				reqPerSec := float64(stats.Requests) / elapsed.Seconds()
				fmt.Fprintf(os.Stderr, "%s[%s] Req: %d | Matches: %d | Errors: %d | Rate: %.0f/s%s\r",
					ColorDim, time.Now().Format("15:04:05"), 
					atomic.LoadInt64(&stats.Requests), 
					atomic.LoadInt64(&stats.Matches), 
					atomic.LoadInt64(&stats.Errors), 
					reqPerSec, ColorReset)
			}
		}
	}
}

func printFinalStats() {
	fmt.Printf("\n\n%s╔════════════════════════════════════════════════════════════╗%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Printf("%s║                  FUZZING COMPLETED                         ║%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", ColorBold+ColorCyan, ColorReset)

	elapsed := time.Since(stats.StartTime)
	reqPerSec := float64(stats.Requests) / elapsed.Seconds()

	fmt.Printf("%s[Statistics]%s\n", ColorBold+ColorYellow, ColorReset)
	fmt.Printf("  Total Requests: %s%d%s\n", ColorGreen, stats.Requests, ColorReset)
	fmt.Printf("  Matches Found : %s%d%s\n", ColorGreen+ColorBold, stats.Matches, ColorReset)
	fmt.Printf("  Errors        : %s%d%s\n", ColorRed, stats.Errors, ColorReset)
	fmt.Printf("  Time Elapsed  : %s%v%s\n", ColorCyan, elapsed.Round(time.Millisecond), ColorReset)
	fmt.Printf("  Avg Speed     : %s%.2f%s req/s\n", ColorGreen+ColorBold, reqPerSec, ColorReset)

	fmt.Printf("\n%s[Status Codes]%s\n", ColorBold+ColorYellow, ColorReset)
	
	stats.Lock.RLock()
	var codes []int
	for code := range stats.StatusCodes {
		codes = append(codes, code)
	}
	stats.Lock.RUnlock()
	
	sort.Ints(codes)
	for _, code := range codes {
		stats.Lock.RLock()
		count := stats.StatusCodes[code]
		stats.Lock.RUnlock()
		fmt.Printf("  %s[%d]%s: %d\n", getStatusColor(code), code, ColorReset, count)
	}
	fmt.Println()
}

// printBanner displays the tool banner with your custom ASCII art
func printBanner() {
	banner := `
██████╗  █████╗ ██╗   ██╗
██╔══██╗██╔══██╗╚██╗ ██╔╝
██████╔╝███████║ ╚████╔╝ 
██╔══██╗██╔══██║  ╚██╔╝  
██║  ██║██║  ██║   ██║   
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   `
	
	if config.Colors {
		fmt.Println(ColorCyan + ColorBold + banner + ColorReset)
		fmt.Printf("%s  High-Performance Security Scanner%s\n", ColorGreen, ColorReset)
		fmt.Printf("%s  Developed by Biswajeet Ray%s\n\n", ColorDim, ColorReset)
	} else {
		fmt.Println(banner)
		fmt.Println("  High-Performance Security Scanner")
		fmt.Println("  Developed by Biswajeet Ray\n")
	}
}

func printConfig(wordCount, targetCount int) {
	fmt.Printf("%s[Config]%s\n", ColorBold+ColorYellow, ColorReset)
	fmt.Printf("  Targets: %d | Words: %d | Threads: %d\n", targetCount, wordCount, config.Concurrency)
	fmt.Printf("  Method : %s | Timeout: %ds\n", config.Method, config.Timeout)
	fmt.Printf("\n%s[Starting]%s\n\n", ColorBold+ColorGreen, ColorReset)
}

func parseFlags() {
	flag.StringVar(&config.URL, "u", "", "Target URL with FUZZ placeholder")
	flag.StringVar(&config.Wordlist, "w", "", "Wordlist file")
	flag.StringVar(&config.DomainList, "L", "", "List of domains to fuzz")
	flag.StringVar(&config.DomainScan, "scan", "", "List of domains to check alive")
	flag.StringVar(&config.Method, "X", "GET", "HTTP method")
	flag.StringVar(&config.Data, "d", "", "POST data")
	flag.IntVar(&config.Timeout, "timeout", 10, "Timeout in seconds")
	flag.IntVar(&config.Concurrency, "c", 50, "Concurrency level")
	flag.IntVar(&config.Rate, "rate", 0, "Rate limit (req/s)")
	flag.IntVar(&config.Delay, "delay", 0, "Delay per request (ms)")
	flag.BoolVar(&config.Silent, "silent", false, "Silent mode")
	flag.BoolVar(&config.Colors, "colors", true, "Colorized output")
	flag.BoolVar(&config.AutoCalibrate, "calibrate", false, "Auto-calibrate baseline")
	flag.StringVar(&config.Output, "o", "", "Output file (txt)")
	flag.StringVar(&config.SaveJson, "json", "", "Save as JSON")

	flag.Var(&config.Headers, "H", "Custom headers (e.g. -H 'Cookie: 1' -H 'Auth: 2')")

	var mc, fc, ml, fl string
	flag.StringVar(&mc, "mc", "", "Match status codes (comma-separated)")
	flag.StringVar(&fc, "fc", "", "Filter status codes")
	flag.StringVar(&ml, "ml", "", "Match length")
	flag.StringVar(&fl, "fl", "", "Filter length")
	flag.StringVar(&config.MatchRegex, "mr", "", "Match regex pattern")
	flag.StringVar(&config.FilterRegex, "fr", "", "Filter regex pattern")
	
	flag.Parse()

	if mc != "" { config.MatchCodes = parseIntList(mc) }
	if fc != "" { config.FilterCodes = parseIntList(fc) }
	if ml != "" { config.MatchLen = parseIntList(ml) }
	if fl != "" { config.FilterLen = parseIntList(fl) }

	if config.URL != "" { config.FuzzMode = ModeSingleURL }
	if config.DomainList != "" { config.FuzzMode = ModeDomainList }
	if config.DomainScan != "" { config.FuzzMode = ModeDomainScan }
}

func validateConfig() {
	if config.URL == "" && config.DomainList == "" && config.DomainScan == "" {
		fatal("Missing target! Use -u, -L, or -scan")
	}
	if config.Wordlist == "" && config.FuzzMode != ModeDomainScan {
		fatal("Wordlist (-w) is required")
	}
	if config.URL != "" && !strings.Contains(config.URL, "FUZZ") && !strings.Contains(config.Data, "FUZZ") {
		fatal("URL or Data must contain 'FUZZ'")
	}
}

func loadWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()
	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		w := strings.TrimSpace(scanner.Text())
		if w != "" && !strings.HasPrefix(w, "#") { words = append(words, w) }
	}
	return words, scanner.Err()
}

func loadDomainList(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()
	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		d := strings.TrimSpace(scanner.Text())
		if d != "" {
			if config.FuzzMode == ModeDomainList && !strings.Contains(d, "FUZZ") {
				d = strings.TrimRight(d, "/") + "/FUZZ"
			}
			domains = append(domains, d)
		}
	}
	return domains, scanner.Err()
}

func parseIntList(s string) []int {
	var res []int
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil { res = append(res, n) }
	}
	return res
}

func intContains(s []int, v int) bool {
	for _, i := range s { if i == v { return true } }
	return false
}

func saveResults() {
	file, err := os.Create(config.SaveJson)
	if err != nil { return }
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	enc.Encode(results)
}

func saveOutput() {
	file, err := os.Create(config.Output)
	if err != nil { return }
	defer file.Close()
	for _, r := range results {
		file.WriteString(fmt.Sprintf("[%d] %s | Len:%d\n", r.StatusCode, r.URL, r.Length))
	}
}

func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "%s[ERROR]%s %s\n", ColorRed+ColorBold, ColorReset, msg)
	os.Exit(1)
}
