package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"golang.org/x/term"
)

// Buffer size for reading network data
const defaultBufferSize = 4096

// Maximum allowed chunk size (100MB) to prevent DoS/OOM attacks
const maxChunkSize = 100 * 1024 * 1024

// WebSocket read deadline for context checking
const wsReadDeadline = 100 * time.Millisecond

// Minimum length for quoted strings in environment files
const minQuotedStringLen = 2

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
)

// Compiled regular expressions (avoid recompilation in hot paths)
var (
	envVarRegex = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)
)

type config struct {
	target          string
	file            string
	unixSocket      string
	env             bool
	envFile         string
	useTLS          bool
	noTLS           bool
	noVerify        bool
	dumpTLS         bool
	useHTTP2        bool
	useHTTP3        bool
	useWebSocket    bool
	dumpFrames      bool
	timeout         time.Duration
	maxBytes        int64
	printRequest    bool
	quiet           bool
	verbose         bool
	showTiming      bool
	retryCount      int
	retryDelay      time.Duration
	followRedirects bool
	maxRedirects    int
	basicAuth       string
	headersOnly     bool
	bodyOnly        bool
	noColor         bool
	useColor        bool // Computed: whether to actually use colors
	noAltSvc        bool
}

// timingInfo holds detailed timing information for a request
type timingInfo struct {
	dnsStart     time.Time
	dnsDone      time.Time
	connectStart time.Time
	connectDone  time.Time
	tlsStart     time.Time
	tlsDone      time.Time
	sendStart    time.Time
	sendDone     time.Time
	firstByte    time.Time
	responseDone time.Time
}

// responseInfo holds information about an HTTP response for redirect handling
type responseInfo struct {
	statusCode int
	location   string
	headers    string
}

// durations returns the timing breakdown as a formatted string
func (t *timingInfo) durations() string {
	var parts []string

	if !t.dnsStart.IsZero() && !t.dnsDone.IsZero() {
		parts = append(parts, fmt.Sprintf("DNS lookup:      %v", t.dnsDone.Sub(t.dnsStart).Round(time.Microsecond)))
	}
	if !t.connectStart.IsZero() && !t.connectDone.IsZero() {
		parts = append(parts, fmt.Sprintf("TCP connect:     %v", t.connectDone.Sub(t.connectStart).Round(time.Microsecond)))
	}
	if !t.tlsStart.IsZero() && !t.tlsDone.IsZero() {
		parts = append(parts, fmt.Sprintf("TLS handshake:   %v", t.tlsDone.Sub(t.tlsStart).Round(time.Microsecond)))
	}
	if !t.sendStart.IsZero() && !t.sendDone.IsZero() {
		parts = append(parts, fmt.Sprintf("Request send:    %v", t.sendDone.Sub(t.sendStart).Round(time.Microsecond)))
	}
	if !t.sendDone.IsZero() && !t.firstByte.IsZero() {
		parts = append(parts, fmt.Sprintf("Server processing: %v", t.firstByte.Sub(t.sendDone).Round(time.Microsecond)))
	}
	if !t.firstByte.IsZero() && !t.responseDone.IsZero() {
		parts = append(parts, fmt.Sprintf("Content download: %v", t.responseDone.Sub(t.firstByte).Round(time.Microsecond)))
	}
	if !t.dnsStart.IsZero() && !t.responseDone.IsZero() {
		parts = append(parts, fmt.Sprintf("Total:           %v", t.responseDone.Sub(t.dnsStart).Round(time.Microsecond)))
	}

	return strings.Join(parts, "\n")
}

// Color helpers
func (cfg *config) colorize(color, text string) string {
	if !cfg.useColor {
		return text
	}
	return color + text + colorReset
}

func (cfg *config) colorStatus(status string) string {
	// Color based on HTTP status code
	if strings.HasPrefix(status, "2") {
		return cfg.colorize(colorGreen, status)
	} else if strings.HasPrefix(status, "3") {
		return cfg.colorize(colorCyan, status)
	} else if strings.HasPrefix(status, "4") {
		return cfg.colorize(colorYellow, status)
	} else if strings.HasPrefix(status, "5") {
		return cfg.colorize(colorRed, status)
	}
	return status
}

func (cfg *config) colorHeaderKey(key string) string {
	return cfg.colorize(colorCyan, key)
}

func (cfg *config) colorizeHTTPResponse(response []byte) []byte {
	if !cfg.useColor {
		return response
	}

	lines := bytes.Split(response, []byte("\r\n"))
	var colorized [][]byte

	for i, line := range lines {
		lineStr := string(line)

		// First line is status line (HTTP/1.1 200 OK)
		if i == 0 && strings.HasPrefix(lineStr, "HTTP/") {
			parts := strings.SplitN(lineStr, " ", 3)
			if len(parts) >= 2 {
				// Protocol in gray, status code in color, rest normal
				colored := cfg.colorize(colorGray, parts[0])
				if len(parts) >= 2 {
					colored += " " + cfg.colorStatus(parts[1])
				}
				if len(parts) >= 3 {
					colored += " " + parts[2]
				}
				colorized = append(colorized, []byte(colored))
				continue
			}
		}

		// Headers (key: value)
		if colonIdx := bytes.IndexByte(line, ':'); colonIdx != -1 && len(line) > 0 {
			key := string(line[:colonIdx])
			value := string(line[colonIdx:])
			colored := cfg.colorHeaderKey(key) + value
			colorized = append(colorized, []byte(colored))
			continue
		}

		// Empty line or other content
		colorized = append(colorized, line)
	}

	return bytes.Join(colorized, []byte("\r\n"))
}

func main() {
	cfg := parseArgs()

	var lastErr error
	for attempt := 0; attempt <= cfg.retryCount; attempt++ {
		if attempt > 0 {
			if !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[*] Retrying in %v... (attempt %d/%d)\n", cfg.retryDelay, attempt, cfg.retryCount)
			}
			time.Sleep(cfg.retryDelay)
		}

		err := run(cfg)
		if err == nil {
			// Success!
			os.Exit(0)
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			if !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[!] Error: %v (not retryable)\n", err)
			}
			os.Exit(1)
		}

		if attempt < cfg.retryCount && !cfg.quiet {
			fmt.Fprintf(os.Stderr, "[!] Attempt %d failed: %v\n", attempt+1, err)
		}
	}

	// All retries exhausted
	if !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[!] Error: %v (all %d retries exhausted)\n", lastErr, cfg.retryCount)
	}
	os.Exit(1)
}

// isRetryableError determines if an error should trigger a retry
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Network errors that might be transient
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary",
		"no such host",
		"DNS lookup failed",
		"TLS handshake failed",
		"broken pipe",
		"network is unreachable",
	}

	for _, pattern := range retryablePatterns {
		if strings.Contains(strings.ToLower(errStr), pattern) {
			return true
		}
	}

	return false
}

func parseArgs() *config {
	cfg := &config{}

	// Show help if no arguments provided (check before modifying os.Args)
	if len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [target] [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Send raw HTTP requests over TCP or TLS.\n\n")
		fmt.Fprintf(os.Stderr, "Arguments:\n")
		fmt.Fprintf(os.Stderr, "  target              host[:port] (optional, extracted from Host header if not provided)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -f, --file string   Read request from file\n")
		fmt.Fprintf(os.Stderr, "  --help              Show this help message\n")
		fmt.Fprintf(os.Stderr, "\nFor full options, run: %s --help\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s example.com -f request.http                  # Auto-TLS for port 443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f request.http                              # Uses Host from request\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  echo 'GET / HTTP/1.1' | %s example.com          # Read from stdin\n", os.Args[0])
		os.Exit(0)
	}

	// Parse target first (before flags)
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cfg.target = args[0]
		os.Args = append([]string{os.Args[0]}, args[1:]...)
	}

	flag.StringVar(&cfg.file, "f", "", "Read request from file")
	flag.StringVar(&cfg.file, "file", "", "Read request from file")
	flag.StringVar(&cfg.unixSocket, "unix-socket", "", "Connect to Unix socket")
	flag.BoolVar(&cfg.env, "env", false, "Expand environment variables ($VAR or ${VAR})")
	flag.StringVar(&cfg.envFile, "env-file", "", "Load environment variables from file (enables --env)")
	flag.BoolVar(&cfg.useTLS, "tls", false, "Force TLS (auto-enabled for port 443)")
	flag.BoolVar(&cfg.noTLS, "no-tls", false, "Disable TLS (force plain TCP)")
	flag.BoolVar(&cfg.noVerify, "no-verify", false, "Disable TLS certificate verification")
	flag.BoolVar(&cfg.dumpTLS, "dump-tls", false, "Display TLS session and certificate info only, then exit")
	flag.BoolVar(&cfg.useHTTP2, "http2", false, "Use HTTP/2 (requires TLS)")
	flag.BoolVar(&cfg.useHTTP3, "http3", false, "Use HTTP/3 (QUIC)")
	flag.BoolVar(&cfg.useWebSocket, "websocket", false, "Upgrade to WebSocket protocol")
	flag.BoolVar(&cfg.useWebSocket, "ws", false, "Upgrade to WebSocket protocol (alias for --websocket)")
	flag.BoolVar(&cfg.dumpFrames, "dump-frames", false, "Display HTTP/2 frames (use with --http2)")
	flag.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "Socket timeout")
	flag.Int64Var(&cfg.maxBytes, "max-bytes", 0, "Limit response output to N bytes")
	flag.IntVar(&cfg.retryCount, "retry", 0, "Number of retries on failure (0 = no retries)")
	flag.DurationVar(&cfg.retryDelay, "retry-delay", 1*time.Second, "Delay between retries")
	flag.BoolVar(&cfg.followRedirects, "follow", false, "Follow HTTP redirects (3xx)")
	flag.BoolVar(&cfg.followRedirects, "L", false, "Follow HTTP redirects (alias for --follow)")
	flag.IntVar(&cfg.maxRedirects, "max-redirects", 10, "Maximum number of redirects to follow")
	flag.StringVar(&cfg.basicAuth, "user", "", "Basic auth credentials (username:password)")
	flag.BoolVar(&cfg.printRequest, "print-request", false, "Print the request being sent to stderr")
	flag.BoolVar(&cfg.quiet, "q", false, "Suppress stderr messages")
	flag.BoolVar(&cfg.quiet, "quiet", false, "Suppress stderr messages")
	flag.BoolVar(&cfg.verbose, "v", false, "Verbose connection info")
	flag.BoolVar(&cfg.verbose, "verbose", false, "Verbose connection info")
	flag.BoolVar(&cfg.showTiming, "timing", false, "Show detailed request/response timing breakdown")
	flag.BoolVar(&cfg.headersOnly, "head", false, "Print only HTTP response headers")
	flag.BoolVar(&cfg.bodyOnly, "body", false, "Print only HTTP response body")
	flag.BoolVar(&cfg.noColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&cfg.noAltSvc, "no-alt-svc", false, "Suppress Alt-Svc protocol upgrade hints")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [target] [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Send raw HTTP requests over TCP or TLS.\n\n")
		fmt.Fprintf(os.Stderr, "Arguments:\n")
		fmt.Fprintf(os.Stderr, "  target              host[:port] (optional, extracted from Host header if not provided)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s example.com -f request.http                  # Auto-TLS for port 443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f request.http                              # Uses Host from request\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --http2 -f request.http                      # HTTP/2 with auto-host\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s example.com:8443 --tls -f request.http       # Explicit TLS for non-443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s example.com:443 --no-tls -f request.http     # Force plain TCP on 443\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --env-file .env -f request.http | jq\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  sudo %s --unix-socket /var/run/docker.sock -f docker.http\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  echo 'GET / HTTP/1.1' | %s example.com          # Read from stdin\n", os.Args[0])
	}

	flag.Parse()

	// Determine if we should use colors
	// Use colors if stdout is a terminal and --no-color is not set
	cfg.useColor = !cfg.noColor && term.IsTerminal(int(os.Stdout.Fd()))

	return cfg
}

func validateConfig(cfg *config) error {
	// Validate timeout value
	if cfg.timeout < 0 {
		return fmt.Errorf("timeout cannot be negative")
	}
	if cfg.timeout == 0 {
		cfg.timeout = 10 * time.Second // Set default if zero
	}

	// Validate maxRedirects value
	if cfg.maxRedirects < 0 {
		return fmt.Errorf("max-redirects cannot be negative")
	}
	if cfg.maxRedirects == 0 {
		cfg.maxRedirects = 10 // Set default if zero
	}

	// Validate retryCount value
	if cfg.retryCount < 0 {
		return fmt.Errorf("retry count cannot be negative")
	}

	// Validate maxBytes value
	if cfg.maxBytes < 0 {
		return fmt.Errorf("max-bytes cannot be negative")
	}

	// Validate mutually exclusive output options
	if cfg.headersOnly && cfg.bodyOnly {
		return fmt.Errorf("cannot use --head and --body together")
	}

	// Validate TLS flag conflicts
	if cfg.useTLS && cfg.noTLS {
		return fmt.Errorf("cannot use --tls and --no-tls together")
	}

	// Validate Unix socket incompatibilities
	if cfg.unixSocket != "" {
		if cfg.useTLS {
			return fmt.Errorf("cannot use --tls with --unix-socket")
		}
		if cfg.noTLS {
			return fmt.Errorf("cannot use --no-tls with --unix-socket")
		}
		if cfg.dumpTLS {
			return fmt.Errorf("cannot use --dump-tls with --unix-socket")
		}
		if cfg.useHTTP2 {
			return fmt.Errorf("--http2 cannot be used with --unix-socket")
		}
		if cfg.useWebSocket {
			return fmt.Errorf("--websocket cannot be used with --unix-socket")
		}
	}

	// Validate HTTP/2 requirements
	if cfg.dumpFrames && !cfg.useHTTP2 {
		return fmt.Errorf("--dump-frames requires --http2")
	}

	// Validate protocol conflicts
	if cfg.useWebSocket && cfg.useHTTP2 {
		return fmt.Errorf("cannot use --websocket and --http2 together")
	}
	if cfg.useWebSocket && cfg.useHTTP3 {
		return fmt.Errorf("cannot use --websocket and --http3 together")
	}
	if cfg.useHTTP2 && cfg.useHTTP3 {
		return fmt.Errorf("cannot use --http2 and --http3 together")
	}
	if cfg.unixSocket != "" && cfg.useHTTP3 {
		return fmt.Errorf("--http3 cannot be used with --unix-socket")
	}

	return nil
}

func run(cfg *config) error {
	// Validate configuration
	if err := validateConfig(cfg); err != nil {
		return err
	}

	// Load environment file if specified
	if cfg.envFile != "" {
		if err := loadEnvFile(cfg.envFile); err != nil {
			return err
		}
		cfg.env = true
	}

	// Smart TLS inference (unless explicitly set)
	if cfg.unixSocket == "" && !cfg.useTLS && !cfg.noTLS {
		port := extractPort(cfg.target)
		// Default to TLS for port 443 or when no port is specified (will default to 443)
		if port == "443" || port == "" {
			cfg.useTLS = true
			if !cfg.quiet && port == "443" {
				fmt.Fprintf(os.Stderr, "[*] Auto-enabling TLS for port 443\n")
			}
		}
	}

	// Validate TLS-dependent flags after inference
	// For dump-tls, force enable TLS if not already set
	if cfg.dumpTLS {
		if !cfg.useTLS && !cfg.noTLS {
			cfg.useTLS = true
		}
		if !cfg.useTLS {
			return fmt.Errorf("--dump-tls requires TLS (port 443 or --tls)")
		}
	}

	if cfg.useHTTP2 && !cfg.useTLS {
		return fmt.Errorf("--http2 requires TLS (port 443 or --tls)")
	}

	// Apply --no-tls override
	if cfg.noTLS {
		cfg.useTLS = false
	}

	// For TLS dump, we don't need a request - just connect and dump
	if cfg.dumpTLS {
		conn, err := connect(cfg, nil)
		if err != nil {
			return err
		}
		defer func() {
			if err := conn.Close(); err != nil && !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[!] Warning: failed to close connection: %v\n", err)
			}
		}()

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			return fmt.Errorf("internal error: expected TLS connection but got %T", conn)
		}
		return dumpTLSInfo(tlsConn, cfg.target)
	}

	// Read request (needed for HTTP/1.1, HTTP/2, and WebSocket)
	request, err := readRequest(cfg)
	if err != nil {
		return err
	}

	// Process Basic Auth if specified
	if cfg.basicAuth != "" {
		// Parse and encode credentials
		encodedCreds, err := parseBasicAuth(cfg.basicAuth)
		if err != nil {
			return err
		}

		// Warn if using Basic Auth without TLS
		if !cfg.useTLS && !cfg.quiet {
			fmt.Fprintf(os.Stderr, "[!] Warning: Using --user without TLS (credentials sent in plain text)\n")
		}

		// Inject Authorization header
		request = injectBasicAuthHeader(request, encodedCreds)
	}

	// If no target specified and not using unix socket, extract from Host header
	if cfg.target == "" && cfg.unixSocket == "" {
		host, err := extractHostFromRequest(request)
		if err != nil {
			return fmt.Errorf("target not specified and could not extract from Host header: %w", err)
		}
		cfg.target = host
		if !cfg.quiet {
			fmt.Fprintf(os.Stderr, "[*] Using host from request: %s\n", host)
		}
	}

	// Validate we have a target or unix socket
	if cfg.unixSocket == "" && cfg.target == "" {
		return fmt.Errorf("target is required unless --unix-socket is used")
	}

	// Initialize timing if requested
	var timing *timingInfo
	if cfg.showTiming {
		timing = &timingInfo{}
	}

	// Use HTTP/3 if requested (handles its own connection via QUIC)
	if cfg.useHTTP3 {
		return runHTTP3(request, cfg, timing)
	}

	// Use WebSocket if requested (handles its own connection)
	if cfg.useWebSocket {
		return runWebSocket(request, cfg, timing)
	}

	// Connect (for HTTP/1.1 and HTTP/2)
	conn, err := connect(cfg, timing)
	if err != nil {
		return err
	}
	defer func() {
		if err := conn.Close(); err != nil && !cfg.quiet {
			fmt.Fprintf(os.Stderr, "[!] Warning: failed to close connection: %v\n", err)
		}
	}()

	// Use HTTP/2 if requested
	if cfg.useHTTP2 {
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			return fmt.Errorf("internal error: expected TLS connection but got %T", conn)
		}
		return runHTTP2(tlsConn, request, cfg, timing)
	}

	// HTTP/1.1 mode
	if cfg.followRedirects {
		return runHTTP1WithRedirects(conn, request, cfg, timing)
	}
	return runHTTP1(conn, request, cfg, timing)
}

// runHTTP1WithRedirects handles HTTP/1.1 with automatic redirect following
func runHTTP1WithRedirects(conn net.Conn, initialRequest string, cfg *config, timing *timingInfo) error {
	request := initialRequest
	redirectCount := 0
	visited := make(map[string]bool) // Track visited URLs to detect loops

	for {
		// Send request and get response info
		respInfo, err := runHTTP1WithResponse(conn, request, cfg, timing)
		if err != nil {
			return err
		}

		// Check if this is a redirect status
		if respInfo.statusCode < 300 || respInfo.statusCode >= 400 {
			// Not a redirect, we're done
			return nil
		}

		// Check if we have a Location header
		if respInfo.location == "" {
			if !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[!] Warning: Got %d redirect but no Location header\n", respInfo.statusCode)
			}
			return nil
		}

		// Check redirect limit
		if redirectCount >= cfg.maxRedirects {
			return fmt.Errorf("too many redirects (limit: %d)", cfg.maxRedirects)
		}

		// Check for redirect loop
		if visited[respInfo.location] {
			return fmt.Errorf("redirect loop detected: %s", respInfo.location)
		}
		visited[respInfo.location] = true

		redirectCount++

		if !cfg.quiet {
			fmt.Fprintf(os.Stderr, "[*] Following redirect %d/%d to: %s\n", redirectCount, cfg.maxRedirects, respInfo.location)
		}

		// Parse the redirect location
		newTarget, newPath, err := parseRedirectLocation(respInfo.location, cfg.target)
		if err != nil {
			return fmt.Errorf("invalid redirect location: %w", err)
		}

		// Close current connection if target changed
		if newTarget != cfg.target {
			if closeErr := conn.Close(); closeErr != nil && !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[!] Warning: failed to close old connection: %v\n", closeErr)
			}

			// Update target
			cfg.target = newTarget

			// Reconnect to new target
			conn, err = connect(cfg, nil) // Don't track timing for redirects
			if err != nil {
				return err
			}
			// Note: connection will be closed by caller's defer
		}

		// Build new request with updated path
		request, err = updateRequestPath(initialRequest, newPath, newTarget)
		if err != nil {
			return fmt.Errorf("failed to update request: %w", err)
		}
	}
}

// runHTTP1 handles HTTP/1.1 request/response with detailed timing
func runHTTP1(conn net.Conn, request string, cfg *config, timing *timingInfo) error {
	// Print request if requested
	if cfg.printRequest && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] Sending request:\n")
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
		fmt.Fprintf(os.Stderr, "%s", request)
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
	}

	// Timing: request send start
	if timing != nil {
		timing.sendStart = time.Now()
	}

	// Send request
	if _, err := conn.Write([]byte(request)); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}

	// Timing: request send done
	if timing != nil {
		timing.sendDone = time.Now()
	}

	// Read first byte to capture TTFB timing
	if timing != nil {
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(cfg.timeout))
		n, err := conn.Read(buf)
		if err != nil {
			return fmt.Errorf("read failed: %w", err)
		}
		if n > 0 {
			timing.firstByte = time.Now()

			// Push the byte back by creating a wrapped connection
			conn = &prefixConn{
				Conn:   conn,
				prefix: buf[:n],
			}
		}
	}

	// Read and process response
	err := readResponse(conn, cfg)

	// Mark response completion
	if timing != nil {
		timing.responseDone = time.Now()
	}

	// Display timing breakdown
	if timing != nil && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "\n[*] Timing breakdown:\n")
		fmt.Fprintf(os.Stderr, "%s\n", timing.durations())
	}

	return err
}

// runHTTP1WithResponse is like runHTTP1 but returns response info for redirect handling
func runHTTP1WithResponse(conn net.Conn, request string, cfg *config, timing *timingInfo) (*responseInfo, error) {
	// Print request if requested
	if cfg.printRequest && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] Sending request:\n")
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
		fmt.Fprintf(os.Stderr, "%s", request)
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
	}

	// Timing: request send start
	if timing != nil {
		timing.sendStart = time.Now()
	}

	// Send request
	if _, err := conn.Write([]byte(request)); err != nil {
		return nil, fmt.Errorf("send failed: %w", err)
	}

	// Timing: request send done
	if timing != nil {
		timing.sendDone = time.Now()
	}

	// Read first byte to capture TTFB timing
	if timing != nil {
		buf := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(cfg.timeout))
		n, err := conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("read failed: %w", err)
		}
		if n > 0 {
			timing.firstByte = time.Now()

			// Push the byte back by creating a wrapped connection
			conn = &prefixConn{
				Conn:   conn,
				prefix: buf[:n],
			}
		}
	}

	// Read and process response, capturing response info
	respInfo, err := readResponseWithInfo(conn, cfg)

	// Mark response completion
	if timing != nil {
		timing.responseDone = time.Now()
	}

	if err != nil {
		return nil, err
	}

	// Print Alt-Svc hint if present
	if altSvc := extractAltSvc(respInfo.headers); altSvc != "" {
		printAltSvcHint(altSvc, cfg)
	}

	return respInfo, nil
}

// parseRedirectLocation parses a redirect location and returns new target and path
func parseRedirectLocation(location, currentTarget string) (newTarget, newPath string, err error) {
	// Handle relative URLs
	if !strings.HasPrefix(location, "http://") && !strings.HasPrefix(location, "https://") {
		// Relative URL - keep same target
		newTarget = currentTarget
		if strings.HasPrefix(location, "/") {
			newPath = location
		} else {
			newPath = "/" + location
		}
		return newTarget, newPath, nil
	}

	// Parse absolute URL
	// Remove scheme
	schemeEnd := strings.Index(location, "://")
	if schemeEnd == -1 {
		return "", "", fmt.Errorf("invalid URL: %s", location)
	}

	remainder := location[schemeEnd+3:]

	// Find path separator
	pathStart := strings.Index(remainder, "/")
	if pathStart == -1 {
		// No path, just host
		newTarget = remainder
		newPath = "/"
	} else {
		newTarget = remainder[:pathStart]
		newPath = remainder[pathStart:]
	}

	return newTarget, newPath, nil
}

// updateRequestPath updates the request with a new path and host
func updateRequestPath(originalRequest, newPath, newHost string) (string, error) {
	lines := strings.Split(originalRequest, "\r\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty request")
	}

	// Update request line
	parts := strings.Fields(lines[0])
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid request line")
	}

	// Build new request line
	lines[0] = parts[0] + " " + newPath + " " + parts[2]

	// Update Host header
	for i := 1; i < len(lines); i++ {
		if strings.HasPrefix(strings.ToLower(lines[i]), "host:") {
			lines[i] = "Host: " + newHost
			break
		}
	}

	return strings.Join(lines, "\r\n"), nil
}

// readResponseWithInfo reads response and extracts status code and Location header
func readResponseWithInfo(conn net.Conn, cfg *config) (*responseInfo, error) {
	output := os.Stdout
	reader := bufio.NewReader(conn)
	buffer := &bytes.Buffer{}
	headerEnded := false
	var contentLength *int64
	chunked := false
	var bytesWritten int64

	respInfo := &responseInfo{}

	// Set read deadline for the entire response
	if err := conn.SetReadDeadline(time.Now().Add(cfg.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read until we find the end of headers
	chunk := make([]byte, defaultBufferSize) // Allocate once, reuse in loop
	for !headerEnded {
		n, err := reader.Read(chunk)
		if n > 0 {
			buffer.Write(chunk[:n])
		}
		if err != nil {
			if err == io.EOF && buffer.Len() > 0 {
				break
			}
			return nil, err
		}

		// Check for end of headers
		if idx := bytes.Index(buffer.Bytes(), []byte("\r\n\r\n")); idx != -1 {
			headerEnded = true
			headers := buffer.Bytes()[:idx+4]
			body := buffer.Bytes()[idx+4:]

			// Parse status code and Location
			respInfo.headers = string(headers)
			respInfo.statusCode = extractStatusCode(respInfo.headers)
			respInfo.location = extractLocation(respInfo.headers)

			// Parse headers for body handling
			contentLength, chunked = parseHeaders(string(headers))

			// Write headers if needed
			if !cfg.bodyOnly {
				toWrite := cfg.colorizeHTTPResponse(headers)
				if cfg.maxBytes > 0 && bytesWritten+int64(len(toWrite)) > cfg.maxBytes {
					remaining := cfg.maxBytes - bytesWritten
					if remaining <= 0 {
						return respInfo, nil // Already at limit
					}
					if int64(len(toWrite)) > remaining {
						toWrite = toWrite[:remaining]
					}
				}
				if _, err := output.Write(toWrite); err != nil {
					return nil, err
				}
				bytesWritten += int64(len(toWrite))
			}

			// If headers-only, we're done
			if cfg.headersOnly {
				return respInfo, nil
			}

			// Reset buffer with body
			buffer.Reset()
			buffer.Write(body)
			break
		}
	}

	if !headerEnded {
		// No body, just write what we have
		if !cfg.bodyOnly {
			if _, err := output.Write(buffer.Bytes()); err != nil {
				return nil, err
			}
		}
		return respInfo, nil
	}

	// Handle body based on transfer encoding
	var err error
	if chunked {
		err = readChunkedBody(reader, buffer, output, cfg, &bytesWritten)
	} else {
		err = readRegularBody(reader, buffer, output, cfg, contentLength, &bytesWritten)
	}

	return respInfo, err
}

// extractStatusCode extracts the HTTP status code from response headers
func extractStatusCode(headers string) int {
	lines := strings.Split(headers, "\r\n")
	if len(lines) == 0 {
		return 0
	}

	// Parse status line: "HTTP/1.1 200 OK"
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return 0
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0
	}

	return code
}

// extractLocation extracts the Location header from response headers
func extractLocation(headers string) string {
	lines := strings.Split(headers, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "location:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// extractAltSvc extracts Alt-Svc header value from response headers
func extractAltSvc(headers string) string {
	lines := strings.Split(headers, "\r\n")
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "alt-svc:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// printAltSvcHint prints helpful information about Alt-Svc if present
func printAltSvcHint(altSvc string, cfg *config) {
	if altSvc == "" || cfg.noAltSvc || cfg.quiet {
		return
	}

	// Parse Alt-Svc value to provide helpful hints
	// Format: h3=":443"; ma=2592000
	if strings.Contains(altSvc, "h3=") {
		fmt.Fprintf(os.Stderr, "[i] Server advertises HTTP/3 support via Alt-Svc\n")
		if !cfg.useHTTP3 {
			fmt.Fprintf(os.Stderr, "[i] Tip: Use --http3 flag for faster HTTP/3 connection\n")
		}
	} else if strings.Contains(altSvc, "h2=") {
		fmt.Fprintf(os.Stderr, "[i] Server advertises HTTP/2 support via Alt-Svc\n")
		if !cfg.useHTTP2 {
			fmt.Fprintf(os.Stderr, "[i] Tip: Use --http2 flag for HTTP/2 connection\n")
		}
	}
}

// prefixConn wraps a net.Conn to prepend bytes that were already read
type prefixConn struct {
	net.Conn
	prefix []byte
	used   bool
}

func (c *prefixConn) Read(p []byte) (n int, err error) {
	if !c.used && len(c.prefix) > 0 {
		c.used = true
		n = copy(p, c.prefix)
		return n, nil
	}
	return c.Conn.Read(p)
}

// readResponseWithTiming reads response while tracking first byte and completion timing
func connect(cfg *config, timing *timingInfo) (net.Conn, error) {
	if cfg.unixSocket != "" {
		if !cfg.quiet {
			fmt.Fprintf(os.Stderr, "[*] Connecting to Unix socket %s\n", cfg.unixSocket)
		}
		return net.DialTimeout("unix", cfg.unixSocket, cfg.timeout)
	}

	// Parse host:port
	host, port := parseTarget(cfg.target, cfg.useTLS)

	if !cfg.quiet {
		tlsStr := ""
		if cfg.useTLS {
			tlsStr = " (TLS)"
		}
		fmt.Fprintf(os.Stderr, "[*] Connecting to %s:%s%s\n", host, port, tlsStr)
	}

	// DNS resolution timing
	if timing != nil {
		timing.dnsStart = time.Now()
	}

	// Resolve hostname to get timing
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	_, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed: %w", err)
	}

	if timing != nil {
		timing.dnsDone = time.Now()
	}

	// TCP connection timing
	if timing != nil {
		timing.connectStart = time.Now()
	}

	// Connect TCP
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), cfg.timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	if timing != nil {
		timing.connectDone = time.Now()
	}

	// Wrap with TLS if needed
	if cfg.useTLS {
		tlsConfig := &tls.Config{
			ServerName: host,
		}
		if cfg.noVerify {
			tlsConfig.InsecureSkipVerify = true
		}

		// Add ALPN for HTTP/2 if requested
		if cfg.useHTTP2 {
			tlsConfig.NextProtos = []string{"h2", "http/1.1"}
		}

		tlsConn := tls.Client(conn, tlsConfig)

		// TLS handshake timing
		if timing != nil {
			timing.tlsStart = time.Now()
		}

		if err := tlsConn.Handshake(); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}

		if timing != nil {
			timing.tlsDone = time.Now()
		}

		// Verify HTTP/2 was negotiated if requested
		if cfg.useHTTP2 {
			state := tlsConn.ConnectionState()
			if state.NegotiatedProtocol != "h2" {
				if !cfg.quiet {
					fmt.Fprintf(os.Stderr, "[!] Warning: Server did not negotiate HTTP/2 (got %s)\n", state.NegotiatedProtocol)
				}
				return nil, fmt.Errorf("http/2 not supported by server")
			}
			if !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[*] Negotiated protocol: %s\n", state.NegotiatedProtocol)
			}
		}

		return tlsConn, nil
	}

	return conn, nil
}

func parseTarget(target string, useTLS bool) (host, port string) {
	// Use net.SplitHostPort to properly handle IPv6 addresses like [::1]:8080
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		// No port specified, return target as host with default port
		defaultPort := "80"
		if useTLS {
			defaultPort = "443"
		}
		return target, defaultPort
	}
	return h, p
}

func extractPort(target string) string {
	// Use net.SplitHostPort to properly handle IPv6 addresses
	_, port, err := net.SplitHostPort(target)
	if err != nil {
		return "" // No port specified
	}
	return port
}

func splitHostPort(target string) (host, port string) {
	// Use net.SplitHostPort to properly handle IPv6 addresses
	h, p, err := net.SplitHostPort(target)
	if err != nil {
		return target, "" // No port specified
	}
	return h, p
}

func loadEnvFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("environment file not found: %s", path)
	}
	defer func() {
		// Close file, error is not actionable here
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "[!] Warning: Invalid line %d in %s: %s\n", lineNum, path, line)
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= minQuotedStringLen {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		if err := os.Setenv(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Warning: failed to set environment variable %s: %v\n", key, err)
		}
	}

	return scanner.Err()
}

func readRequest(cfg *config) (string, error) {
	var data []byte
	var err error

	if cfg.file != "" {
		data, err = os.ReadFile(cfg.file)
		if err != nil {
			return "", err
		}
	} else {
		// Check if stdin is a terminal
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return "", fmt.Errorf("no input provided. Use -f to specify a file or pipe data to stdin")
		}
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
	}

	request := string(data)

	// Expand environment variables if requested
	if cfg.env {
		request = expandEnvVars(request, cfg)
	}

	// Normalize line endings to CRLF
	request = strings.ReplaceAll(request, "\r\n", "\n")
	request = strings.ReplaceAll(request, "\n", "\r\n")

	// Split headers and body
	parts := strings.SplitN(request, "\r\n\r\n", 2)
	headers := parts[0]
	body := ""

	if len(parts) == 2 {
		// Has a body - strip trailing whitespace
		body = strings.TrimRight(parts[1], "\r\n")

		// Check Content-Length if present
		if !cfg.quiet {
			checkContentLength(headers, body)
		}

		request = headers + "\r\n\r\n" + body
	} else {
		// Headers only - ensure proper termination
		request = strings.TrimRight(request, "\r\n") + "\r\n\r\n"
	}

	return request, nil
}

func expandEnvVars(data string, cfg *config) string {
	// Use pre-compiled regex for performance
	return envVarRegex.ReplaceAllStringFunc(data, func(match string) string {
		// Extract variable name
		varName := strings.TrimPrefix(match, "$")
		varName = strings.TrimPrefix(varName, "{")
		varName = strings.TrimSuffix(varName, "}")

		if val := os.Getenv(varName); val != "" {
			// Warn about non-HTREQ prefixed variables (potential security risk)
			if !strings.HasPrefix(varName, "HTREQ_") && !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[!] Warning: expanding environment variable %s (consider using HTREQ_ prefix for safety)\n", varName)
			}
			return val
		}
		return match
	})
}

// parseBasicAuth parses "username:password" and returns base64-encoded credentials
func parseBasicAuth(userPass string) (string, error) {
	if userPass == "" {
		return "", nil
	}

	// Validate format
	if !strings.Contains(userPass, ":") {
		return "", fmt.Errorf("invalid --user format: expected 'username:password'")
	}

	// Base64 encode the credentials
	encoded := base64.StdEncoding.EncodeToString([]byte(userPass))
	return encoded, nil
}

// injectBasicAuthHeader adds Authorization header to the request
func injectBasicAuthHeader(request, encodedCreds string) string {
	if encodedCreds == "" {
		return request
	}

	// Split request into lines
	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return request
	}

	// Find the end of the first line (request line)
	// Insert Authorization header after the request line
	authHeader := fmt.Sprintf("Authorization: Basic %s", encodedCreds)

	// Insert after first line
	result := []string{lines[0], authHeader}
	result = append(result, lines[1:]...)

	return strings.Join(result, "\r\n")
}

func checkContentLength(headers, body string) {
	headerLines := strings.Split(strings.ToLower(headers), "\r\n")
	for _, line := range headerLines {
		if strings.HasPrefix(line, "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if declared, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					actual := len(body)
					if declared != actual {
						fmt.Fprintf(os.Stderr, "[!] Warning: Content-Length is %d but body is %d bytes\n", declared, actual)
					}
				}
			}
			break
		}
	}
}

func readResponse(conn net.Conn, cfg *config) error {
	output := os.Stdout
	reader := bufio.NewReader(conn)
	buffer := &bytes.Buffer{}
	headerEnded := false
	var contentLength *int64
	chunked := false
	var bytesWritten int64

	// Set read deadline for the entire response
	if err := conn.SetReadDeadline(time.Now().Add(cfg.timeout)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read until we find the end of headers
	chunk := make([]byte, defaultBufferSize) // Allocate once, reuse in loop
	for !headerEnded {
		n, err := reader.Read(chunk)
		if n > 0 {
			buffer.Write(chunk[:n])
		}
		if err != nil {
			if err == io.EOF && buffer.Len() > 0 {
				break
			}
			return err
		}

		// Check for end of headers
		if idx := bytes.Index(buffer.Bytes(), []byte("\r\n\r\n")); idx != -1 {
			headerEnded = true
			headers := buffer.Bytes()[:idx+4]
			body := buffer.Bytes()[idx+4:]

			// Parse headers
			contentLength, chunked = parseHeaders(string(headers))

			// Write headers if needed
			if !cfg.bodyOnly {
				toWrite := cfg.colorizeHTTPResponse(headers)
				if cfg.maxBytes > 0 && bytesWritten+int64(len(toWrite)) > cfg.maxBytes {
					remaining := cfg.maxBytes - bytesWritten
					if remaining <= 0 {
						return nil // Already at limit
					}
					if int64(len(toWrite)) > remaining {
						toWrite = toWrite[:remaining]
					}
				}
				if _, err := output.Write(toWrite); err != nil {
					return err
				}
				bytesWritten += int64(len(toWrite))
			}

			// Check for Alt-Svc hints
			if altSvc := extractAltSvc(string(headers)); altSvc != "" {
				printAltSvcHint(altSvc, cfg)
			}

			// If headers-only, we're done
			if cfg.headersOnly {
				return nil
			}

			// Reset buffer with body
			buffer.Reset()
			buffer.Write(body)
			break
		}
	}

	if !headerEnded {
		// No body, just write what we have
		if !cfg.bodyOnly {
			if _, err := output.Write(buffer.Bytes()); err != nil {
				return err
			}
		}
		return nil
	}

	// Handle body based on transfer encoding
	if chunked {
		return readChunkedBody(reader, buffer, output, cfg, &bytesWritten)
	}

	return readRegularBody(reader, buffer, output, cfg, contentLength, &bytesWritten)
}

func parseHeaders(headers string) (*int64, bool) {
	var contentLength *int64
	chunked := false

	lines := strings.Split(strings.ToLower(headers), "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "content-length:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if cl, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64); err == nil {
					contentLength = &cl
				}
			}
		} else if strings.HasPrefix(line, "transfer-encoding:") && strings.Contains(line, "chunked") {
			chunked = true
		}
	}

	return contentLength, chunked
}

func readChunkedBody(reader *bufio.Reader, buffer *bytes.Buffer, output io.Writer, cfg *config, bytesWritten *int64) error {
	chunk := make([]byte, defaultBufferSize) // Allocate once, reuse in all loops
	for {
		// Ensure we have enough data for chunk size line
		for !bytes.Contains(buffer.Bytes(), []byte("\r\n")) {
			n, err := reader.Read(chunk)
			if n > 0 {
				buffer.Write(chunk[:n])
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
		}

		// Read chunk size
		line, err := buffer.ReadBytes('\n')
		if err != nil {
			return err
		}

		sizeLine := strings.TrimSpace(string(line))
		sizeStr := strings.Split(sizeLine, ";")[0] // Ignore extensions

		chunkSize, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return fmt.Errorf("invalid chunk size %q: expected hexadecimal number, parse error: %w", sizeStr, err)
		}

		// Validate chunk size to prevent DoS/OOM attacks
		if chunkSize < 0 || chunkSize > maxChunkSize {
			return fmt.Errorf("chunk size %d out of valid range [0, %d]", chunkSize, maxChunkSize)
		}

		// Last chunk
		if chunkSize == 0 {
			break
		}

		// Read chunk data + trailing CRLF
		needed := chunkSize + 2
		for int64(buffer.Len()) < needed {
			n, err := reader.Read(chunk)
			if n > 0 {
				buffer.Write(chunk[:n])
			}
			if err != nil {
				return err
			}
		}

		// Extract chunk data (skip trailing CRLF)
		chunkData := make([]byte, chunkSize)
		if _, err := buffer.Read(chunkData); err != nil {
			return fmt.Errorf("failed to read chunk data: %w", err)
		}
		buffer.Next(2) // Skip CRLF

		// Write chunk data if needed
		if !cfg.headersOnly {
			toWrite := chunkData
			if cfg.maxBytes > 0 && *bytesWritten+int64(len(toWrite)) > cfg.maxBytes {
				toWrite = toWrite[:cfg.maxBytes-*bytesWritten]
			}
			if _, err := output.Write(toWrite); err != nil {
				return err
			}
			*bytesWritten += int64(len(toWrite))

			if cfg.maxBytes > 0 && *bytesWritten >= cfg.maxBytes {
				break
			}
		}
	}

	return nil
}

func readRegularBody(reader *bufio.Reader, buffer *bytes.Buffer, output io.Writer, cfg *config, contentLength *int64, bytesWritten *int64) error {
	// Track body bytes separately for Content-Length validation
	// bytesWritten may include headers if bodyOnly=false
	var bodyReceived int64

	// Write initial buffer if not headers-only
	if !cfg.headersOnly && buffer.Len() > 0 {
		data := buffer.Bytes()
		toWrite := data
		if cfg.maxBytes > 0 && *bytesWritten+int64(len(toWrite)) > cfg.maxBytes {
			toWrite = toWrite[:cfg.maxBytes-*bytesWritten]
		}
		if _, err := output.Write(toWrite); err != nil {
			return err
		}
		*bytesWritten += int64(len(toWrite))
		bodyReceived += int64(len(toWrite))
		buffer.Reset()
	}

	// Read rest of body
	chunk := make([]byte, defaultBufferSize) // Allocate once, reuse in loop
	for (cfg.maxBytes == 0 || *bytesWritten < cfg.maxBytes) && (contentLength == nil || bodyReceived < *contentLength) {

		n, err := reader.Read(chunk)
		if n > 0 {
			if !cfg.headersOnly {
				toWrite := chunk[:n]
				if cfg.maxBytes > 0 && *bytesWritten+int64(len(toWrite)) > cfg.maxBytes {
					toWrite = toWrite[:cfg.maxBytes-*bytesWritten]
				}
				if _, err := output.Write(toWrite); err != nil {
					return err
				}
				*bytesWritten += int64(len(toWrite))
				bodyReceived += int64(len(toWrite))
			}
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}

	return nil
}

func dumpTLSInfo(conn *tls.Conn, host string) error {
	state := conn.ConnectionState()

	fmt.Printf("# TLS information for %s\n\n", host)
	fmt.Printf("Protocol: %s\n", tlsVersionString(state.Version))
	fmt.Printf("Cipher: %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("Server name (SNI): %s\n\n", state.ServerName)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		fmt.Println("[Certificate]")
		fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
		fmt.Printf("  Issuer:  %s\n", cert.Issuer.CommonName)
		fmt.Printf("  Valid from: %s\n", cert.NotBefore.Format(time.RFC3339))
		fmt.Printf("  Valid until: %s\n\n", cert.NotAfter.Format(time.RFC3339))

		// SHA256 fingerprint
		hash := sha256.Sum256(cert.Raw)
		fmt.Printf("SHA256 Fingerprint: %X\n\n", hash)

		// PEM encoding
		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}
		fmt.Print(string(pem.EncodeToMemory(pemBlock)))
	}

	return nil
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// HTTP/3 implementation

func runHTTP3(request string, cfg *config, timing *timingInfo) error {
	// Parse the HTTP request into method, path, headers, body
	method, path, headers, body, err := parseHTTPRequest(request)
	if err != nil {
		return err
	}

	// Get host from config
	host, port := splitHostPort(cfg.target)
	if port == "" {
		port = "443" // Default HTTP/3 port
	}

	// Build full URL
	url := fmt.Sprintf("https://%s:%s%s", host, port, path)

	// Print request if requested
	if cfg.printRequest && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] Sending HTTP/3 request:\n")
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
		fmt.Fprintf(os.Stderr, "%s %s\n", method, url)
		for k, v := range headers {
			fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
		}
		if body != "" {
			fmt.Fprintf(os.Stderr, "\n%s", body)
		}
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
	}

	// Create HTTP/3 transport
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.noVerify,
			ServerName:         host,
		},
	}
	defer transport.Close()

	// Create HTTP client
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.timeout,
	}

	// Create HTTP request
	var reqBody io.Reader
	if body != "" {
		reqBody = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Timing: connection and request start (HTTP/3 combines these)
	if timing != nil {
		timing.dnsStart = time.Now()
		timing.connectStart = timing.dnsStart
		timing.sendStart = timing.dnsStart
	}

	if !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] Connecting to %s:%s (HTTP/3/QUIC)\n", host, port)
	}

	// Send request (includes QUIC handshake + request)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http/3 request failed: %w", err)
	}
	defer resp.Body.Close()

	// Timing: first byte received (after QUIC handshake + request)
	if timing != nil {
		timing.firstByte = time.Now()
		timing.dnsDone = timing.firstByte
		timing.connectDone = timing.firstByte
		timing.tlsDone = timing.firstByte // QUIC includes TLS 1.3
		timing.sendDone = timing.firstByte
	}

	// Output response
	output := os.Stdout

	// Print status line
	if !cfg.bodyOnly {
		protocol := cfg.colorize(colorGray, "HTTP/3")
		status := fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		coloredStatus := cfg.colorStatus(status)
		if _, err := fmt.Fprintf(output, "%s %s\r\n", protocol, coloredStatus); err != nil {
			return err
		}

		// Print headers
		for k, values := range resp.Header {
			for _, v := range values {
				headerName := cfg.colorize(colorCyan, k)
				if _, err := fmt.Fprintf(output, "%s: %s\r\n", headerName, v); err != nil {
					return err
				}
			}
		}
		if _, err := fmt.Fprintf(output, "\r\n"); err != nil {
			return err
		}
	}

	// Print body if not headers-only
	if !cfg.headersOnly {
		var bytesWritten int64
		buf := make([]byte, defaultBufferSize)
		for {
			if cfg.maxBytes > 0 && bytesWritten >= cfg.maxBytes {
				break
			}

			n, err := resp.Body.Read(buf)
			if n > 0 {
				toWrite := n
				if cfg.maxBytes > 0 && bytesWritten+int64(n) > cfg.maxBytes {
					toWrite = int(cfg.maxBytes - bytesWritten)
				}
				if _, writeErr := output.Write(buf[:toWrite]); writeErr != nil {
					return writeErr
				}
				bytesWritten += int64(toWrite)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("failed to read response body: %w", err)
			}
		}
	}

	// Timing: response done
	if timing != nil {
		timing.responseDone = time.Now()
	}

	// Check for Alt-Svc hints (e.g., server might advertise HTTP/2 fallback)
	if altSvc := resp.Header.Get("Alt-Svc"); altSvc != "" {
		printAltSvcHint(altSvc, cfg)
	}

	// Print timing if requested
	if timing != nil && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "%s\n", timing.durations())
	}

	return nil
}

// HTTP/2 implementation

func runHTTP2(conn *tls.Conn, request string, cfg *config, timing *timingInfo) error {
	// Parse the HTTP/1.1 request into method, path, headers, body
	method, path, headers, body, err := parseHTTPRequest(request)
	if err != nil {
		return err
	}

	// Print request if requested
	if cfg.printRequest && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] Sending HTTP/2 request:\n")
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
		fmt.Fprintf(os.Stderr, "%s %s\n", method, path)
		for k, v := range headers {
			fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
		}
		if body != "" {
			fmt.Fprintf(os.Stderr, "\n%s", body)
		}
		fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 40))
	}

	// Create HTTP/2 framer with wrapped connection for frame dumping
	var frameConn io.ReadWriter = conn
	if cfg.dumpFrames {
		frameConn = &dumpingConn{conn: conn, cfg: cfg}
	}
	framer := http2.NewFramer(frameConn, frameConn)

	// Send HTTP/2 client preface
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return fmt.Errorf("failed to send client preface: %w", err)
	}

	if cfg.dumpFrames && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "\n[*] HTTP/2 Connection Preface\n")
		fmt.Fprintf(os.Stderr, "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n\n")
	}

	// Send SETTINGS frame
	if err := framer.WriteSettings(); err != nil {
		return fmt.Errorf("failed to write settings: %w", err)
	}
	if cfg.dumpFrames && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] SEND: SETTINGS frame\n")
	}

	// Timing: request send start
	if timing != nil {
		timing.sendStart = time.Now()
	}

	// Send HEADERS frame
	headerBlock, err := encodeHeaders(method, path, headers, cfg)
	if err != nil {
		return fmt.Errorf("failed to encode headers: %w", err)
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: headerBlock,
		EndStream:     body == "",
		EndHeaders:    true,
	}); err != nil {
		return fmt.Errorf("failed to write headers: %w", err)
	}
	if cfg.dumpFrames && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] SEND: HEADERS frame (stream 1, %d bytes HPACK data)\n", len(headerBlock))
	}

	// Send DATA frame if there's a body
	if body != "" {
		if err := framer.WriteData(1, true, []byte(body)); err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}
		if cfg.dumpFrames && !cfg.quiet {
			fmt.Fprintf(os.Stderr, "[*] SEND: DATA frame (stream 1, %d bytes)\n", len(body))
		}
	}

	// Timing: request send done
	if timing != nil {
		timing.sendDone = time.Now()
	}

	// Read response
	err = readHTTP2Response(framer, cfg, timing)

	// Display timing
	if timing != nil && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "\n[*] Timing breakdown:\n")
		fmt.Fprintf(os.Stderr, "%s\n", timing.durations())
	} else if !cfg.quiet {
		fmt.Fprintf(os.Stderr, "\n[*] Response received\n")
	}

	return err
}

func parseHTTPRequest(request string) (method, path string, headers map[string]string, body string, err error) {
	headers = make(map[string]string)

	// Split into lines
	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return "", "", nil, "", fmt.Errorf("empty request")
	}

	// Parse request line
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return "", "", nil, "", fmt.Errorf("invalid request line %q: expected format 'METHOD PATH HTTP/VERSION', got %d parts", lines[0], len(parts))
	}
	method = parts[0]
	path = parts[1]

	// Parse headers
	i := 1
	for i < len(lines) && lines[i] != "" {
		line := lines[i]
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			i++
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])
		headers[strings.ToLower(key)] = value
		i++
	}

	// Get body (everything after the blank line)
	if i < len(lines)-1 {
		body = strings.Join(lines[i+1:], "\r\n")
		body = strings.TrimRight(body, "\r\n")
	}

	return method, path, headers, body, nil
}

func extractHostFromRequest(request string) (string, error) {
	// Parse the request to get headers
	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("empty request: no lines found")
	}

	// Look for Host header
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			break // End of headers
		}
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		if strings.ToLower(key) == "host" {
			value := strings.TrimSpace(line[colonIdx+1:])
			if value == "" {
				return "", fmt.Errorf("host header is present but empty (add a value like 'Host: example.com')")
			}
			return value, nil
		}
	}

	return "", fmt.Errorf("host header not found in request (add 'Host: example.com' header or specify target on command line)")
}

func encodeHeaders(method, path string, headers map[string]string, cfg *config) ([]byte, error) {
	buf := &bytes.Buffer{}
	encoder := hpack.NewEncoder(buf)

	// Encode pseudo-headers first (required by HTTP/2)
	if err := encoder.WriteField(hpack.HeaderField{Name: ":method", Value: method}); err != nil {
		return nil, fmt.Errorf("failed to encode :method header: %w", err)
	}
	if err := encoder.WriteField(hpack.HeaderField{Name: ":path", Value: path}); err != nil {
		return nil, fmt.Errorf("failed to encode :path header: %w", err)
	}
	if err := encoder.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"}); err != nil {
		return nil, fmt.Errorf("failed to encode :scheme header: %w", err)
	}

	// Get authority from Host header
	if host, ok := headers["host"]; ok {
		if err := encoder.WriteField(hpack.HeaderField{Name: ":authority", Value: host}); err != nil {
			return nil, fmt.Errorf("failed to encode :authority header: %w", err)
		}
	}

	// Encode regular headers (skip Host as it's now :authority)
	for k, v := range headers {
		if k == "host" || k == "connection" || k == "transfer-encoding" || k == "upgrade" {
			continue // These are not allowed in HTTP/2
		}
		if err := encoder.WriteField(hpack.HeaderField{Name: k, Value: v}); err != nil {
			return nil, fmt.Errorf("failed to encode header %s: %w", k, err)
		}
	}

	headerBlock := buf.Bytes()

	if cfg.dumpFrames && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] HPACK Encoded Headers (%d bytes)\n", len(headerBlock))
		if cfg.verbose {
			fmt.Fprintf(os.Stderr, "Hex dump:\n%s\n", hex.Dump(headerBlock))
		}
	}

	return headerBlock, nil
}

func readHTTP2Response(framer *http2.Framer, cfg *config, timing *timingInfo) error {
	output := os.Stdout
	var bytesWritten int64
	headersReceived := false
	responseHeaders := make(map[string]string)

	decoder := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		responseHeaders[f.Name] = f.Value
	})

	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			if err == io.EOF {
				if timing != nil && timing.responseDone.IsZero() {
					timing.responseDone = time.Now()
				}
				break
			}
			return fmt.Errorf("failed to read frame: %w", err)
		}

		switch f := frame.(type) {
		case *http2.SettingsFrame:
			// Respond with SETTINGS ACK
			if err := framer.WriteSettingsAck(); err != nil {
				return fmt.Errorf("failed to write SETTINGS ACK: %w", err)
			}

		case *http2.HeadersFrame:
			// Capture first byte timing when we receive headers
			if timing != nil && timing.firstByte.IsZero() {
				timing.firstByte = time.Now()
			}

			// Decode headers
			if _, err := decoder.Write(f.HeaderBlockFragment()); err != nil {
				return fmt.Errorf("failed to decode headers: %w", err)
			}

			if !headersReceived {
				headersReceived = true
				if !cfg.bodyOnly {
					// Print status line
					status := responseHeaders[":status"]
					protocol := cfg.colorize(colorGray, "HTTP/2")
					coloredStatus := cfg.colorStatus(status)
					if _, err := fmt.Fprintf(output, "%s %s\r\n", protocol, coloredStatus); err != nil {
						return err
					}

					// Print headers
					for k, v := range responseHeaders {
						if !strings.HasPrefix(k, ":") {
							headerKey := cfg.colorHeaderKey(http.CanonicalHeaderKey(k))
							if _, err := fmt.Fprintf(output, "%s: %s\r\n", headerKey, v); err != nil {
								return err
							}
						}
					}
					if _, err := fmt.Fprintf(output, "\r\n"); err != nil {
						return err
					}
				}
			}

			if cfg.headersOnly {
				if timing != nil && timing.responseDone.IsZero() {
					timing.responseDone = time.Now()
				}
				return nil
			}

		case *http2.DataFrame:
			if !cfg.headersOnly && len(f.Data()) > 0 {
				toWrite := f.Data()
				if cfg.maxBytes > 0 && bytesWritten+int64(len(toWrite)) > cfg.maxBytes {
					remaining := cfg.maxBytes - bytesWritten
					if remaining <= 0 {
						return nil // Already at limit
					}
					if int64(len(toWrite)) > remaining {
						toWrite = toWrite[:remaining]
					}
				}
				if _, err := output.Write(toWrite); err != nil {
					return err
				}
				bytesWritten += int64(len(toWrite))

				if cfg.maxBytes > 0 && bytesWritten >= cfg.maxBytes {
					if timing != nil && timing.responseDone.IsZero() {
						timing.responseDone = time.Now()
					}
					return nil
				}
			}

			if f.StreamEnded() {
				if timing != nil && timing.responseDone.IsZero() {
					timing.responseDone = time.Now()
				}
				return nil
			}

		case *http2.GoAwayFrame:
			if !cfg.quiet {
				fmt.Fprintf(os.Stderr, "[*] Server sent GOAWAY\n")
			}
			if timing != nil && timing.responseDone.IsZero() {
				timing.responseDone = time.Now()
			}
			return nil

		case *http2.RSTStreamFrame:
			return fmt.Errorf("stream reset by server: %v", f.ErrCode)
		}
	}

	// Check for Alt-Svc hints
	if altSvc, ok := responseHeaders["alt-svc"]; ok && altSvc != "" {
		printAltSvcHint(altSvc, cfg)
	}

	return nil
}

// dumpingConn wraps a connection to dump frame bytes
type dumpingConn struct {
	conn io.ReadWriter
	cfg  *config
}

func (dc *dumpingConn) Read(p []byte) (n int, err error) {
	n, err = dc.conn.Read(p)
	if err == nil && dc.cfg.verbose && n >= 9 {
		dumpRawFrame(p[:n], "RECV", dc.cfg)
	}
	return
}

func (dc *dumpingConn) Write(p []byte) (n int, err error) {
	if dc.cfg.verbose && len(p) >= 9 {
		dumpRawFrame(p, "SEND", dc.cfg)
	}
	return dc.conn.Write(p)
}

func dumpRawFrame(data []byte, direction string, cfg *config) {
	if len(data) < 9 {
		return
	}

	length := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	frameType := http2.FrameType(data[3])
	flags := http2.Flags(data[4])
	streamID := uint32(data[5])<<24 | uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	streamID = streamID & 0x7fffffff

	fmt.Fprintf(os.Stderr, "\n[%s] Frame: %s\n", direction, frameType)
	fmt.Fprintf(os.Stderr, "      Length: %d, Flags: 0x%02x, Stream: %d\n", length, flags, streamID)

	if length > 0 && len(data) >= int(9+length) {
		payload := data[9 : 9+length]
		fmt.Fprintf(os.Stderr, "Payload:\n%s\n", hex.Dump(payload[:min(int(length), 256)]))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// WebSocket implementation

func runWebSocket(request string, cfg *config, timing *timingInfo) error {
	// Extract the URL from the request for gorilla/websocket
	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return fmt.Errorf("empty request: no lines found in request data")
	}

	// Parse request line to get path
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return fmt.Errorf("invalid request line %q: expected format 'METHOD PATH HTTP/VERSION'", lines[0])
	}
	path := parts[1]

	// Build WebSocket URL
	scheme := "ws://"
	if cfg.useTLS {
		scheme = "wss://"
	}

	// Extract host from request
	host := ""
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}
	if host == "" {
		host = cfg.target
	}

	url := scheme + host + path

	// Print what we're connecting to
	if !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[*] Establishing WebSocket connection to %s\n", url)
	}

	// Start timing
	startTime := time.Now()
	if timing != nil {
		timing.dnsStart = startTime
	}

	// Create WebSocket dialer with custom TLS config if needed
	dialer := &websocket.Dialer{
		HandshakeTimeout: cfg.timeout,
	}
	if cfg.noVerify {
		dialer.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	// Parse custom headers from request
	headers := http.Header{}
	skipHeaders := map[string]bool{
		"host":                  true,
		"upgrade":               true,
		"connection":            true,
		"sec-websocket-key":     true,
		"sec-websocket-version": true,
	}

	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if colonIdx := strings.Index(line, ":"); colonIdx != -1 {
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			// Skip WebSocket-specific headers that the dialer sets
			if !skipHeaders[strings.ToLower(key)] {
				headers.Add(key, value)
			}
		}
	}

	// Connect to WebSocket
	wsConn, resp, err := dialer.Dial(url, headers)
	if err != nil {
		return fmt.Errorf("websocket dial failed: %w", err)
	}
	// Note: connection is closed in handleWebSocketSession

	elapsed := time.Since(startTime)
	if timing != nil {
		timing.responseDone = time.Now()
	}

	if !cfg.quiet {
		protocol := cfg.colorize(colorGray, "WebSocket")
		coloredStatus := cfg.colorStatus(strconv.Itoa(resp.StatusCode))
		fmt.Fprintf(os.Stderr, "%s %s %s\n", protocol, coloredStatus, resp.Status)
		fmt.Fprintf(os.Stderr, "[*] Connection established in %v\n\n", elapsed.Round(time.Millisecond))
		if timing != nil {
			fmt.Fprintf(os.Stderr, "[*] Timing breakdown:\n")
			fmt.Fprintf(os.Stderr, "%s\n\n", timing.durations())
		}
		fmt.Fprintf(os.Stderr, "[*] Type messages and press Enter to send. Press Ctrl+C to exit.\n\n")
	}

	// Handle WebSocket communication
	return handleWebSocketSession(wsConn, cfg)
}

func handleWebSocketSession(conn *websocket.Conn, cfg *config) error {
	defer func() {
		// Close connection, ignore error as we're already shutting down
		_ = conn.Close()
	}()

	// Create context for goroutine coordination
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure all goroutines are stopped

	// Channel to signal completion (buffer size 2 for both goroutines)
	done := make(chan error, 2)

	// Start reading messages from WebSocket
	go func() {
		defer cancel() // Cancel context when this goroutine exits
		for {
			select {
			case <-ctx.Done():
				return
			default:
				// Set read deadline to allow periodic context checks
				conn.SetReadDeadline(time.Now().Add(wsReadDeadline))
				messageType, message, err := conn.ReadMessage()
				if err != nil {
					// Check if it's a timeout (expected for context checking)
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue // Continue loop to check context
					}
					// Real error or connection closed
					if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
						done <- fmt.Errorf("websocket read error: %w", err)
					} else {
						done <- nil // Normal closure
					}
					return
				}

				// Print received message
				if !cfg.quiet {
					typeStr := "TEXT"
					if messageType == websocket.BinaryMessage {
						typeStr = "BINARY"
					}
					fmt.Fprintf(os.Stderr, "\n[*] Received %s message (%d bytes)\n", typeStr, len(message))
				}
				fmt.Printf("%s\n", message)
			}
		}
	}()

	// Read from stdin and send messages
	go func() {
		defer cancel() // Cancel context when this goroutine exits
		scanner := bufio.NewScanner(os.Stdin)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if !scanner.Scan() {
					// Scanner finished (EOF or error)
					if err := scanner.Err(); err != nil {
						done <- fmt.Errorf("stdin read error: %w", err)
					} else {
						done <- nil // EOF on stdin (e.g., Ctrl+D)
					}
					return
				}
				text := scanner.Text()
				if err := conn.WriteMessage(websocket.TextMessage, []byte(text)); err != nil {
					done <- fmt.Errorf("websocket write error: %w", err)
					return
				}
				if !cfg.quiet {
					fmt.Fprintf(os.Stderr, "[*] Sent message: %s\n", text)
				}
			}
		}
	}()

	// Wait for completion or error
	err := <-done

	// Send close message
	closeErr := conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if closeErr != nil && !cfg.quiet {
		fmt.Fprintf(os.Stderr, "[!] Warning: failed to send close frame: %v\n", closeErr)
	}

	if !cfg.quiet {
		fmt.Fprintf(os.Stderr, "\n[*] WebSocket connection closed\n")
	}

	return err
}
