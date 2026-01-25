#!/bin/bash
# Integration tests for htreq
# Tests against real HTTP services to validate end-to-end functionality

set -e  # Exit on first error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/htreq"
FIXTURES_DIR="$SCRIPT_DIR/fixtures"
TMP_DIR=$(mktemp -d)

# Cleanup on exit
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Helper functions
print_test_header() {
    echo ""
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_failure() {
    echo -e "${RED}✗${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Test execution function
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    local should_fail="${4:-false}"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    
    local output_file="$TMP_DIR/output_$TESTS_RUN.txt"
    local stderr_file="$TMP_DIR/stderr_$TESTS_RUN.txt"
    
    # Run command and capture output
    set +e
    eval "$test_command" > "$output_file" 2> "$stderr_file"
    local exit_code=$?
    set -e
    
    # Check exit code
    if [ "$should_fail" = "true" ]; then
        if [ $exit_code -eq 0 ]; then
            print_failure "$test_name (expected failure but succeeded)"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    else
        if [ $exit_code -ne 0 ]; then
            print_failure "$test_name (exit code: $exit_code)"
            echo "  stderr: $(cat "$stderr_file" | head -5)"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    fi
    
    # Check output pattern if provided
    if [ -n "$expected_pattern" ]; then
        if grep -q "$expected_pattern" "$output_file" || grep -q "$expected_pattern" "$stderr_file"; then
            print_success "$test_name"
            TESTS_PASSED=$((TESTS_PASSED + 1))
            return 0
        else
            print_failure "$test_name (pattern not found: $expected_pattern)"
            echo "  Output: $(cat "$output_file" | head -5)"
            TESTS_FAILED=$((TESTS_FAILED + 1))
            return 1
        fi
    else
        print_success "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    fi
}

# Verify binary exists
if [ ! -f "$BINARY" ]; then
    echo -e "${RED}Error: htreq binary not found at $BINARY${NC}"
    echo "Please run 'make build' first"
    exit 1
fi

echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  htreq Integration Test Suite${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo "Binary: $BINARY"
echo "Fixtures: $FIXTURES_DIR"
echo ""

# ============================================================================
# Basic HTTP/1.1 Tests
# ============================================================================
print_test_header "HTTP/1.1 Basic Requests"

run_test \
    "GET request to httpbin.org" \
    "$BINARY -f $FIXTURES_DIR/get-https.http" \
    "HTTP/1.1 200"

run_test \
    "POST request with JSON body" \
    "$BINARY -f $FIXTURES_DIR/post-json.http" \
    "HTTP/1.1 200"

run_test \
    "GET request with explicit target" \
    "$BINARY httpbin.org:443 -f $FIXTURES_DIR/get-https.http" \
    "HTTP/1.1 200"

# Note: stdin without any flags shows usage (by design)
# Stdin reading works when combined with target or other flags
run_test \
    "GET request via stdin with target" \
    "cat $FIXTURES_DIR/get-https.http | $BINARY httpbin.org:443" \
    "HTTP/1.1 200"

# ============================================================================
# TLS Tests
# ============================================================================
print_test_header "TLS Functionality"

run_test \
    "TLS auto-detection on port 443" \
    "$BINARY httpbin.org:443 -f $FIXTURES_DIR/get-https.http" \
    "HTTP/1.1 200"

run_test \
    "--dump-tls without request file" \
    "$BINARY httpbin.org:443 --dump-tls" \
    "Protocol:"

run_test \
    "--dump-tls with explicit target" \
    "$BINARY httpbin.org:443 --dump-tls" \
    "Protocol:"

run_test \
    "Explicit --tls flag" \
    "$BINARY --tls -f $FIXTURES_DIR/get-https.http" \
    "HTTP/1.1 200"

run_test \
    "Non-TLS request on port 80" \
    "$BINARY httpbin.org:80 -f $FIXTURES_DIR/get-http.http" \
    "HTTP/1.1 200"

# ============================================================================
# Output Flags
# ============================================================================
print_test_header "Output Control Flags"

run_test \
    "--body flag (body only)" \
    "$BINARY -f $FIXTURES_DIR/get-https.http --body" \
    '"url"'

run_test \
    "--head flag (headers only)" \
    "$BINARY -f $FIXTURES_DIR/get-https.http --head" \
    "HTTP/1.1 200"

run_test \
    "--quiet flag suppresses stderr" \
    "$BINARY -f $FIXTURES_DIR/get-https.http --quiet 2>&1" \
    "HTTP/1.1 200"

# ============================================================================
# HTTP/2 Tests
# ============================================================================
print_test_header "HTTP/2 Support"

run_test \
    "HTTP/2 request to cloudflare.com" \
    "$BINARY --http2 -f $FIXTURES_DIR/get-http2.http" \
    "HTTP/2"

run_test \
    "HTTP/2 with --dump-frames" \
    "$BINARY --http2 --dump-frames -f $FIXTURES_DIR/get-http2.http 2>&1" \
    "SETTINGS"

# ============================================================================
# Error Cases
# ============================================================================
print_test_header "Error Handling"

run_test \
    "Invalid request format" \
    "$BINARY -f $FIXTURES_DIR/invalid-request.http" \
    "Host header not found" \
    "true"

run_test \
    "Non-existent file" \
    "$BINARY -f /tmp/nonexistent_file_12345.http" \
    "" \
    "true"

run_test \
    "Missing target without Host header" \
    "printf 'GET / HTTP/1.1\r\n\r\n' | $BINARY --no-color" \
    "Host.*header" \
    "true"

run_test \
    "Conflicting flags --tls and --no-tls" \
    "$BINARY --tls --no-tls -f $FIXTURES_DIR/get-https.http" \
    "" \
    "true"

run_test \
    "Conflicting flags --head and --body" \
    "$BINARY --head --body -f $FIXTURES_DIR/get-https.http" \
    "" \
    "true"

run_test \
    "--dump-frames without --http2" \
    "$BINARY --dump-frames -f $FIXTURES_DIR/get-https.http" \
    "requires --http2" \
    "true"

# ============================================================================
# Advanced Features
# ============================================================================
print_test_header "Advanced Features"

run_test \
    "--timeout flag" \
    "$BINARY --timeout 30s -f $FIXTURES_DIR/get-https.http" \
    "HTTP/1.1 200"

run_test \
    "--max-bytes flag limits output" \
    "$BINARY --max-bytes 100 -f $FIXTURES_DIR/get-https.http" \
    "HTTP"

run_test \
    "--no-verify flag for TLS" \
    "$BINARY --no-verify -f $FIXTURES_DIR/get-https.http" \
    "HTTP/1.1 200"

# ============================================================================
# Test Summary
# ============================================================================
echo ""
echo -e "${BLUE}=====================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}=====================================${NC}"
echo ""
echo "Total tests run:    $TESTS_RUN"
echo -e "Tests passed:       ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed:       ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
