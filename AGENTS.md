# Agent Guidelines for htreq

This document provides coding guidelines and conventions for AI coding agents working on the htreq project.

## Project Overview

htreq is a command-line tool for sending raw HTTP requests over TCP or TLS. It's written in Go and supports:
- HTTP/1.1 with chunked encoding
- HTTP/2 with ALPN negotiation
- WebSocket protocol
- TLS with auto-detection
- Unix socket connections
- Environment variable expansion

**Main file:** `main.go` (single-file architecture, ~1350 lines)

## Build Commands

### Build for Development
```bash
make build
# Or directly:
go build -o htreq .
```

### Build Release Version
```bash
make build-release
# Builds with optimizations: -ldflags="-s -w"
```

### Install to System
```bash
sudo make install
# Installs to /usr/local/bin/htreq
```

### Clean Build Artifacts
```bash
make clean
```

### Run Tests
```bash
make test
# Note: Currently runs compare_versions.sh if available
```

### Running the Tool
```bash
# Basic usage
./htreq -f examples/get-https.http

# With flags
./htreq --http2 -f examples/http2-example.http
./htreq --websocket -f examples/websocket-echo.http
./htreq --env-file .env -f request.http
```

### Testing a Single Feature
Since this is a single Go file project without unit tests, test individual features by:
```bash
# 1. Build the binary
go build -o htreq .

# 2. Test specific functionality
./htreq -f examples/get-https.http          # Test HTTPS
./htreq --http2 -f examples/http2-example.http  # Test HTTP/2
./htreq --websocket -f examples/websocket-echo.http  # Test WebSocket

# 3. Check for Go syntax/type errors
go build -o /dev/null .
```

### Linting and Formatting
```bash
# Format code
go fmt ./...

# Run go vet
go vet ./...

# Run golangci-lint (if installed)
golangci-lint run
```

## Code Style Guidelines

### Imports
- Use standard library packages first, then external packages
- Group imports in this order:
  1. Standard library (crypto/*, encoding/*, fmt, io, net, os, etc.)
  2. External packages (github.com/*)
- Current external dependencies:
  - `github.com/gorilla/websocket` - WebSocket support
  - `golang.org/x/net/http2` - HTTP/2 protocol
  - `golang.org/x/term` - Terminal detection

Example from main.go:3-25:
```go
import (
    "bufio"
    "bytes"
    "crypto/sha256"
    "crypto/tls"
    // ... more standard library
    
    "github.com/gorilla/websocket"
    "golang.org/x/net/http2"
    "golang.org/x/net/http2/hpack"
    "golang.org/x/term"
)
```

### Formatting
- Use tabs for indentation (Go standard)
- Run `go fmt` before committing
- Maximum line length: ~120 characters (flexible)
- Use `gofmt` style for all code

### Types and Structs
- Use descriptive struct names in camelCase
- Define config structs for grouping related settings
- Use pointer receivers for methods that modify state
- Use value receivers for read-only methods

Example from main.go:40-62:
```go
type config struct {
    target       string
    file         string
    useTLS       bool
    useHTTP2     bool
    // ... more fields
    useColor     bool // Computed fields with comments
}
```

### Naming Conventions
- **Functions**: Use camelCase, starting with lowercase for private functions
- **Exported functions**: Start with uppercase (e.g., `ParseTarget`)
- **Variables**: Use descriptive camelCase names
- **Constants**: Use camelCase with const keyword, or ALL_CAPS for exported constants
- **Acronyms**: Keep uppercase in names (TLS, HTTP, URL not Tls, Http, Url)

Examples:
```go
const colorReset = "\033[0m"    // Private constant
func parseArgs() *config        // Private function
func dumpTLSInfo(...)          // TLS in caps
func runHTTP2(...)             // HTTP2 not Http2
```

### Error Handling
- Always check and handle errors explicitly
- Use `fmt.Errorf` with `%w` for error wrapping
- Return errors instead of calling `os.Exit()` (except in main)
- Use descriptive error messages with context
- Print errors to stderr using `fmt.Fprintf(os.Stderr, ...)`

Examples from main.go:
```go
// Good error wrapping
if err != nil {
    return fmt.Errorf("connection failed: %w", err)
}

// Error checking with defer cleanup
defer func() {
    if err := conn.Close(); err != nil && !cfg.quiet {
        fmt.Fprintf(os.Stderr, "[!] Warning: failed to close connection: %v\n", err)
    }
}()
```

### Function Structure
- Keep functions focused on a single responsibility
- Extract complex logic into helper functions
- Functions should be ordered logically (high-level first, helpers later)
- Use early returns to reduce nesting

Function organization in main.go:
1. `main()` - entry point
2. `parseArgs()` - command-line parsing  
3. `run()` - main execution flow
4. Protocol handlers: `runHTTP2()`, `runWebSocket()`
5. Helper functions: `connect()`, `readResponse()`, etc.

### Comments
- Use `//` for single-line comments
- Add comments for complex logic, protocol details, or non-obvious code
- Document exported functions (if any) with GoDoc style
- Use section comments to organize code blocks

Examples:
```go
// ANSI color codes
const (
    colorReset = "\033[0m"
    ...
)

// Color helpers
func (cfg *config) colorize(color, text string) string {
    ...
}
```

### Command-Line Flag Handling
- Use the `flag` package for argument parsing
- Support both short and long flag names where appropriate
- Provide helpful usage/help messages
- Validate flag combinations and provide clear error messages

Example from main.go:155-177:
```go
flag.StringVar(&cfg.file, "f", "", "Read request from file")
flag.StringVar(&cfg.file, "file", "", "Read request from file")
flag.BoolVar(&cfg.quiet, "q", false, "Suppress stderr messages")
flag.BoolVar(&cfg.quiet, "quiet", false, "Suppress stderr messages")
```

### Network and Protocol Code
- Use proper connection lifecycle (defer close)
- Set timeouts on network operations
- Handle TLS with proper configuration
- Respect quiet mode for informational messages
- Print verbose output to stderr, response data to stdout

### Testing and Validation
- Validate user input early
- Check for conflicting flags before execution (main.go:214-248)
- Test edge cases (empty requests, missing headers, etc.)
- Use the example files in `examples/` for manual testing

## Git Conventions

### Commit Messages
- Use imperative mood ("Add feature" not "Added feature")
- Keep first line under 72 characters
- Reference issues when applicable
- Format: `<type>: <description>`

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
```
feat: add support for custom TLS certificates
fix: handle empty Host header gracefully
docs: update README with WebSocket examples
refactor: extract HTTP/2 frame handling to separate function
```

### Branch Naming
- Feature branches: `feature/description`
- Bug fixes: `fix/description`
- Documentation: `docs/description`

## Common Patterns in This Codebase

### Color Output
- Use `cfg.useColor` to check if colors should be used
- Colors determined by terminal detection: `term.IsTerminal()`
- Provide colorizing helper methods on config struct

### Stderr vs Stdout
- **Stdout**: Response data only (can be piped)
- **Stderr**: Informational messages, errors, timing
- Respect `--quiet` flag to suppress stderr output

### Protocol Detection
- Auto-enable TLS for port 443
- Support explicit `--tls` and `--no-tls` flags
- Extract host from request if not provided

### Request Handling
- Normalize line endings to CRLF
- Support environment variable expansion
- Validate Content-Length against actual body size
- Strip trailing whitespace from request bodies

## Dependencies

### Adding New Dependencies
```bash
# Add a new dependency
go get github.com/example/package

# Tidy up go.mod and go.sum
go mod tidy
```

### Current Dependencies (go.mod)
- `github.com/gorilla/websocket v1.5.3`
- `golang.org/x/net v0.47.0`
- `golang.org/x/term v0.37.0`

## Project Structure

```
htreq/
├── main.go              # Single main file with all code
├── go.mod               # Go module definition
├── go.sum               # Dependency checksums
├── Makefile             # Build commands
├── README.md            # User documentation
├── LICENSE              # GPL v3.0
└── examples/            # Example request files
    ├── README.md
    ├── get-https.http
    ├── post-json.http
    ├── http2-example.http
    ├── websocket-echo.http
    └── ...
```

## When Making Changes

1. **Build and test** after every change
2. **Run `go fmt`** before committing
3. **Test with example files** in `examples/`
4. **Validate error cases** (missing files, invalid flags, network errors)
5. **Check both quiet and verbose modes**
6. **Test TLS and non-TLS connections**
7. **Verify colored output works in terminal and plain output when piped**

## Performance Considerations

- Use buffered I/O for network operations
- Respect `--max-bytes` limit to avoid memory issues
- Use streaming for response bodies (don't buffer entire response)
- Set reasonable timeouts (default: 10s)

## Security Notes

- Support `--no-verify` flag for testing but warn about usage
- Don't log sensitive data (tokens, passwords) in verbose mode
- Handle TLS certificate verification properly by default
- Sanitize file paths to prevent directory traversal
