# htreq

[![Build Status](https://github.com/BasicAcid/htreq/workflows/Build%20and%20Test/badge.svg)](https://github.com/BasicAcid/htreq/actions)
[![Release](https://img.shields.io/github/v/release/BasicAcid/htreq)](https://github.com/BasicAcid/htreq/releases/latest)
[![License](https://img.shields.io/github/license/BasicAcid/htreq)](LICENSE)

Send raw HTTP requests over TCP or TLS.

htreq is a command-line tool for testing HTTP APIs with complete control over the request. What you write is exactly what gets sent over the wire - no abstraction, no magic.

## Features

- HTTP/1.1 with chunked encoding
- HTTP/2 with ALPN negotiation
- WebSocket protocol support
- TLS with auto-detection for port 443
- Unix socket support (e.g., Docker API)
- Environment variable expansion
- Colored output (auto-disabled when piped)
- Response timing

## Installation

### Debian/Ubuntu Package

Download the `.deb` package from the [releases page](https://github.com/BasicAcid/htreq/releases/latest):

```bash
# For amd64 (x86_64)
wget https://github.com/BasicAcid/htreq/releases/latest/download/htreq_VERSION_amd64.deb
sudo dpkg -i htreq_VERSION_amd64.deb

# For arm64
wget https://github.com/BasicAcid/htreq/releases/latest/download/htreq_VERSION_arm64.deb
sudo dpkg -i htreq_VERSION_arm64.deb
```

### From Source

**Requirements:** Go 1.24+

```bash
git clone https://github.com/BasicAcid/htreq
cd htreq
make
sudo make install  # installs to /usr/local/bin
```

## Usage

Create a request file with raw HTTP:

```http
POST /api/users HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Length: 27

{"name": "Alice", "age": 30}
```

Send it:
```bash
htreq -f request.http
```

The target (host:port) can be specified explicitly or extracted from the Host header. TLS is automatically enabled for port 443.

## Examples

**Simple GET request:**
```bash
echo "GET /json HTTP/1.1
Host: httpbin.org

" | htreq
```

**POST with JSON:**
```bash
htreq -f post.http --body | jq
```

**HTTP/2:**
```bash
htreq --http2 -f request.http
```

**WebSocket:**
```bash
htreq --websocket -f websocket.http
# Type messages, press Enter to send, Ctrl+C to exit
```

**Environment variables:**
```bash
# Create .env file
cat > .env << EOF
API_TOKEN=secret-token
EOF

# Use in request
echo "GET /api HTTP/1.1
Host: api.example.com
Authorization: Bearer \$API_TOKEN

" | htreq --env-file .env
```

**Unix socket (Docker API):**
```bash
sudo htreq --unix-socket /var/run/docker.sock -f docker-version.http
```

**Scripting:**
```bash
# Extract token and use in next request
TOKEN=$(htreq -f login.http --body | jq -r '.token')
export API_TOKEN="$TOKEN"
htreq --env -f authenticated.http
```

## Options

```
Usage: htreq [target] [options]

Arguments:
  target                  host[:port] (optional if Host header present)

Options:
  -f, --file FILE         Request file (default: stdin)
  --unix-socket PATH      Connect to Unix socket
  --env                   Expand environment variables
  --env-file FILE         Load variables from file
  --tls                   Force TLS (auto-enabled for port 443)
  --no-tls                Disable TLS
  --no-verify             Skip TLS certificate verification
  --dump-tls              Show TLS session info
  --http2                 Use HTTP/2
  --websocket, --ws       Use WebSocket protocol
  --dump-frames           Show HTTP/2 frames
  --timeout DURATION      Socket timeout (default: 10s)
  --max-bytes N           Limit response output
  --print-request         Show request being sent
  --head                  Show only headers
  --body                  Show only body
  --no-color              Disable colored output
  -q, --quiet             Suppress informational messages
  -v, --verbose           Verbose output
```

## Request File Format

Standard HTTP format:

```http
METHOD /path HTTP/1.1
Header-Name: value
Another-Header: value

Optional body content
```

Lines must end with `\r\n` or `\n` (htreq normalizes automatically).

Use `$VAR` or `${VAR}` for environment variable substitution with `--env` flag.

## Examples Directory

The `examples/` directory contains ready-to-run request files:

```bash
htreq -f examples/get-https.http
htreq -f examples/post-json.http
htreq --http2 -f examples/http2-example.http
htreq --websocket -f examples/websocket-echo.http
```

See `examples/README.md` for complete list.

## License

GNU General Public License v3.0 - see LICENSE file.
