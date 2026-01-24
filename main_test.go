package main

import (
	"os"
	"testing"
)

// Test parseTarget function
func TestParseTarget(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		useTLS   bool
		wantHost string
		wantPort string
	}{
		{"host with port", "example.com:8080", false, "example.com", "8080"},
		{"host without port, no TLS", "example.com", false, "example.com", "80"},
		{"host without port, with TLS", "example.com", true, "example.com", "443"},
		{"IPv4 with port", "192.168.1.1:443", true, "192.168.1.1", "443"},
		{"IPv6 with port", "[::1]:8080", false, "[::1]", "8080"},
		{"host with multiple colons", "api.example.com:9000", false, "api.example.com", "9000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotPort := parseTarget(tt.target, tt.useTLS)
			if gotHost != tt.wantHost {
				t.Errorf("parseTarget() host = %v, want %v", gotHost, tt.wantHost)
			}
			if gotPort != tt.wantPort {
				t.Errorf("parseTarget() port = %v, want %v", gotPort, tt.wantPort)
			}
		})
	}
}

// Test extractPort function
func TestExtractPort(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{"with port", "example.com:443", "443"},
		{"without port", "example.com", ""},
		{"with non-standard port", "api.example.com:8080", "8080"},
		{"IPv4 with port", "192.168.1.1:80", "80"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractPort(tt.target); got != tt.want {
				t.Errorf("extractPort() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test expandEnvVars function
func TestExpandEnvVars(t *testing.T) {
	// Set up test environment variables
	os.Setenv("TEST_VAR", "test_value")
	os.Setenv("API_KEY", "secret123")
	defer os.Unsetenv("TEST_VAR")
	defer os.Unsetenv("API_KEY")

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple var", "Value is $TEST_VAR", "Value is test_value"},
		{"braced var", "Key: ${API_KEY}", "Key: secret123"},
		{"multiple vars", "$TEST_VAR and ${API_KEY}", "test_value and secret123"},
		{"undefined var", "Value is $UNDEFINED_VAR", "Value is $UNDEFINED_VAR"},
		{"no vars", "plain text", "plain text"},
		{"empty string", "", ""},
		{"var at start", "$TEST_VAR is here", "test_value is here"},
		{"var at end", "Here is $TEST_VAR", "Here is test_value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := expandEnvVars(tt.input); got != tt.want {
				t.Errorf("expandEnvVars() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test extractHostFromRequest function
func TestExtractHostFromRequest(t *testing.T) {
	tests := []struct {
		name    string
		request string
		want    string
		wantErr bool
	}{
		{
			name: "valid host header",
			request: "GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			want:    "example.com",
			wantErr: false,
		},
		{
			name: "host with port",
			request: "POST /api HTTP/1.1\r\n" +
				"Host: api.example.com:8080\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n",
			want:    "api.example.com:8080",
			wantErr: false,
		},
		{
			name: "host with spaces",
			request: "GET / HTTP/1.1\r\n" +
				"Host:   example.com   \r\n" +
				"\r\n",
			want:    "example.com",
			wantErr: false,
		},
		{
			name: "no host header",
			request: "GET / HTTP/1.1\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty request",
			request: "",
			want:    "",
			wantErr: true,
		},
		{
			name: "empty host value",
			request: "GET / HTTP/1.1\r\n" +
				"Host: \r\n" +
				"\r\n",
			want:    "",
			wantErr: true,
		},
		{
			name: "case insensitive host",
			request: "GET / HTTP/1.1\r\n" +
				"HOST: example.com\r\n" +
				"\r\n",
			want:    "example.com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractHostFromRequest(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractHostFromRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractHostFromRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test parseHTTPRequest function
func TestParseHTTPRequest(t *testing.T) {
	tests := []struct {
		name        string
		request     string
		wantMethod  string
		wantPath    string
		wantHeaders map[string]string
		wantBody    string
		wantErr     bool
	}{
		{
			name: "GET request",
			request: "GET /path HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"User-Agent: test\r\n" +
				"\r\n",
			wantMethod: "GET",
			wantPath:   "/path",
			wantHeaders: map[string]string{
				"host":       "example.com",
				"user-agent": "test",
			},
			wantBody: "",
			wantErr:  false,
		},
		{
			name: "POST with body",
			request: "POST /api/users HTTP/1.1\r\n" +
				"Host: api.example.com\r\n" +
				"Content-Type: application/json\r\n" +
				"Content-Length: 18\r\n" +
				"\r\n" +
				`{"name": "Alice"}`,
			wantMethod: "POST",
			wantPath:   "/api/users",
			wantHeaders: map[string]string{
				"host":           "api.example.com",
				"content-type":   "application/json",
				"content-length": "18",
			},
			wantBody: `{"name": "Alice"}`,
			wantErr:  false,
		},
		{
			name:    "empty request",
			request: "",
			wantErr: true,
		},
		{
			name:    "invalid request line",
			request: "INVALID\r\n",
			wantErr: true,
		},
		{
			name: "headers only, no body",
			request: "DELETE /resource/123 HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"\r\n",
			wantMethod: "DELETE",
			wantPath:   "/resource/123",
			wantHeaders: map[string]string{
				"host": "example.com",
			},
			wantBody: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMethod, gotPath, gotHeaders, gotBody, err := parseHTTPRequest(tt.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHTTPRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if gotMethod != tt.wantMethod {
				t.Errorf("parseHTTPRequest() method = %v, want %v", gotMethod, tt.wantMethod)
			}
			if gotPath != tt.wantPath {
				t.Errorf("parseHTTPRequest() path = %v, want %v", gotPath, tt.wantPath)
			}
			if gotBody != tt.wantBody {
				t.Errorf("parseHTTPRequest() body = %v, want %v", gotBody, tt.wantBody)
			}

			// Check headers
			for key, wantValue := range tt.wantHeaders {
				if gotValue, ok := gotHeaders[key]; !ok {
					t.Errorf("parseHTTPRequest() missing header %v", key)
				} else if gotValue != wantValue {
					t.Errorf("parseHTTPRequest() header %v = %v, want %v", key, gotValue, wantValue)
				}
			}
		})
	}
}

// Test parseHeaders function
func TestParseHeaders(t *testing.T) {
	tests := []struct {
		name              string
		headers           string
		wantContentLength *int64
		wantChunked       bool
	}{
		{
			name: "with content-length",
			headers: "HTTP/1.1 200 OK\r\n" +
				"Content-Length: 1234\r\n" +
				"\r\n",
			wantContentLength: int64Ptr(1234),
			wantChunked:       false,
		},
		{
			name: "with chunked encoding",
			headers: "HTTP/1.1 200 OK\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"\r\n",
			wantContentLength: nil,
			wantChunked:       true,
		},
		{
			name: "with both (chunked takes precedence)",
			headers: "HTTP/1.1 200 OK\r\n" +
				"Content-Length: 100\r\n" +
				"Transfer-Encoding: chunked\r\n" +
				"\r\n",
			wantContentLength: int64Ptr(100),
			wantChunked:       true,
		},
		{
			name: "no content indicators",
			headers: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n",
			wantContentLength: nil,
			wantChunked:       false,
		},
		{
			name: "invalid content-length",
			headers: "HTTP/1.1 200 OK\r\n" +
				"Content-Length: invalid\r\n" +
				"\r\n",
			wantContentLength: nil,
			wantChunked:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotContentLength, gotChunked := parseHeaders(tt.headers)

			if (gotContentLength == nil) != (tt.wantContentLength == nil) {
				t.Errorf("parseHeaders() contentLength = %v, want %v", gotContentLength, tt.wantContentLength)
			} else if gotContentLength != nil && *gotContentLength != *tt.wantContentLength {
				t.Errorf("parseHeaders() contentLength = %v, want %v", *gotContentLength, *tt.wantContentLength)
			}

			if gotChunked != tt.wantChunked {
				t.Errorf("parseHeaders() chunked = %v, want %v", gotChunked, tt.wantChunked)
			}
		})
	}
}

// Test colorize method
func TestConfigColorize(t *testing.T) {
	tests := []struct {
		name     string
		useColor bool
		color    string
		text     string
		want     string
	}{
		{"with color enabled", true, colorRed, "error", colorRed + "error" + colorReset},
		{"with color disabled", false, colorRed, "error", "error"},
		{"empty text with color", true, colorBlue, "", colorBlue + colorReset},
		{"empty text no color", false, colorBlue, "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{useColor: tt.useColor}
			if got := cfg.colorize(tt.color, tt.text); got != tt.want {
				t.Errorf("colorize() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test colorStatus method
func TestConfigColorStatus(t *testing.T) {
	tests := []struct {
		name     string
		useColor bool
		status   string
		want     string
	}{
		{"2xx green", true, "200", colorGreen + "200" + colorReset},
		{"3xx cyan", true, "301", colorCyan + "301" + colorReset},
		{"4xx yellow", true, "404", colorYellow + "404" + colorReset},
		{"5xx red", true, "500", colorRed + "500" + colorReset},
		{"unknown unchanged", true, "100", "100"},
		{"no color", false, "200", "200"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config{useColor: tt.useColor}
			if got := cfg.colorStatus(tt.status); got != tt.want {
				t.Errorf("colorStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test tlsVersionString function
func TestTLSVersionString(t *testing.T) {
	tests := []struct {
		name    string
		version uint16
		want    string
	}{
		{"TLS 1.0", 0x0301, "TLS 1.0"},
		{"TLS 1.1", 0x0302, "TLS 1.1"},
		{"TLS 1.2", 0x0303, "TLS 1.2"},
		{"TLS 1.3", 0x0304, "TLS 1.3"},
		{"unknown version", 0x0400, "Unknown (0x0400)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tlsVersionString(tt.version); got != tt.want {
				t.Errorf("tlsVersionString() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test min helper function
func TestMin(t *testing.T) {
	tests := []struct {
		name string
		a    int
		b    int
		want int
	}{
		{"a smaller", 5, 10, 5},
		{"b smaller", 10, 5, 5},
		{"equal", 7, 7, 7},
		{"zero", 0, 5, 0},
		{"negative", -5, 3, -5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := min(tt.a, tt.b); got != tt.want {
				t.Errorf("min() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Test validateConfig function
func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid config",
			cfg:     &config{},
			wantErr: false,
		},
		{
			name: "headersOnly and bodyOnly conflict",
			cfg: &config{
				headersOnly: true,
				bodyOnly:    true,
			},
			wantErr: true,
			errMsg:  "cannot use --head and --body together",
		},
		{
			name: "useTLS and noTLS conflict",
			cfg: &config{
				useTLS: true,
				noTLS:  true,
			},
			wantErr: true,
			errMsg:  "cannot use --tls and --no-tls together",
		},
		{
			name: "unix socket with TLS",
			cfg: &config{
				unixSocket: "/var/run/docker.sock",
				useTLS:     true,
			},
			wantErr: true,
			errMsg:  "cannot use --tls with --unix-socket",
		},
		{
			name: "unix socket with HTTP/2",
			cfg: &config{
				unixSocket: "/var/run/docker.sock",
				useHTTP2:   true,
			},
			wantErr: true,
			errMsg:  "--http2 cannot be used with --unix-socket",
		},
		{
			name: "unix socket with WebSocket",
			cfg: &config{
				unixSocket:   "/var/run/docker.sock",
				useWebSocket: true,
			},
			wantErr: true,
			errMsg:  "--websocket cannot be used with --unix-socket",
		},
		{
			name: "dump-frames without HTTP/2",
			cfg: &config{
				dumpFrames: true,
				useHTTP2:   false,
			},
			wantErr: true,
			errMsg:  "--dump-frames requires --http2",
		},
		{
			name: "WebSocket and HTTP/2 conflict",
			cfg: &config{
				useWebSocket: true,
				useHTTP2:     true,
			},
			wantErr: true,
			errMsg:  "cannot use --websocket and --http2 together",
		},
		{
			name: "valid HTTP/2 config",
			cfg: &config{
				useHTTP2:   true,
				dumpFrames: true,
			},
			wantErr: false,
		},
		{
			name: "valid WebSocket config",
			cfg: &config{
				useWebSocket: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("validateConfig() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

// Helper function to create int64 pointer
func int64Ptr(i int64) *int64 {
	return &i
}
