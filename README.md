# htreq

[![Build Status](https://github.com/BasicAcid/htreq/workflows/Build%20and%20Test/badge.svg)](https://github.com/BasicAcid/htreq/actions)
[![Release](https://img.shields.io/github/v/release/BasicAcid/htreq)](https://github.com/BasicAcid/htreq/releases/latest)
[![License](https://img.shields.io/github/license/BasicAcid/htreq)](LICENSE)

Send raw HTTP requests over TCP or TLS with complete control.

**What makes htreq different:** Unlike curl which abstracts the request, or Hurl which uses its own syntax, htreq sends exactly what you write - raw HTTP bytes over the wire. No hidden headers, no automatic behaviors, just your request exactly as specified.

## Features

- **HTTP/1.1** - Full support including chunked encoding
- **HTTP/2** - With ALPN negotiation and frame inspection
- **WebSocket** - Interactive protocol upgrade and messaging
- **TLS** - Auto-detection for port 443, certificate inspection
- **Unix sockets** - Connect to Docker API and other socket services
- **Environment variables** - Expand `$VAR` in request files
- **Colored output** - Syntax highlighting (auto-disabled when piped)
- **Request timing** - Detailed breakdown of connection phases
- **Automatic retries** - Configurable retry logic for transient failures

## Installation

### Debian/Ubuntu

Download from [releases](https://github.com/BasicAcid/htreq/releases/latest):

```bash
wget https://github.com/BasicAcid/htreq/releases/latest/download/htreq_VERSION_amd64.deb
sudo dpkg -i htreq_VERSION_amd64.deb
```

### From Source

Requires Go 1.24+:

```bash
git clone https://github.com/BasicAcid/htreq
cd htreq
make
sudo make install
```

## Quick Start

Create a request file `request.http`:

```http
GET /get HTTP/1.1
Host: httpbin.org
Accept: application/json
```

Send it:

```bash
htreq -f request.http
```

That's it. The target is extracted from the `Host` header, and TLS is auto-enabled for port 443.

## Usage Examples

### Basic GET Request

**File:** `get.http`
```http
GET /json HTTP/1.1
Host: httpbin.org
Accept: application/json
```

**Command:**
```bash
htreq -f get.http
```

### POST with JSON

**File:** `post.http`
```http
POST /post HTTP/1.1
Host: httpbin.org
Content-Type: application/json
Content-Length: 27

{"name": "Alice", "age": 30}
```

**Command:**
```bash
htreq -f post.http --body | jq .
```

### Environment Variables

Create `.env`:
```
API_TOKEN=your-secret-token
```

**File:** `api.http`
```http
GET /api/data HTTP/1.1
Host: api.example.com
Authorization: Bearer $API_TOKEN
Accept: application/json
```

**Command:**
```bash
htreq --env-file .env -f api.http
```

### HTTP/2

**File:** `http2.http`
```http
GET / HTTP/1.1
Host: cloudflare.com
```

**Command:**
```bash
htreq --http2 -f http2.http
```

### WebSocket

**File:** `websocket.http`
```http
GET /chat HTTP/1.1
Host: websocket.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

**Command:**
```bash
htreq --websocket -f websocket.http
```

Type messages and press Enter to send. Press Ctrl+C to exit.

### Unix Socket (Docker API)

**File:** `docker.http`
```http
GET /containers/json HTTP/1.1
Host: localhost
```

**Command:**
```bash
sudo htreq --unix-socket /var/run/docker.sock -f docker.http
```

### Debugging with Timing

```bash
htreq -f request.http --timing
```

Shows detailed breakdown:
```
[*] Timing breakdown:
DNS lookup:      21.796ms
TCP connect:     33.709ms
TLS handshake:   27.184ms
Request send:    10µs
Server processing: 36.667ms
Content download: 101µs
Total:           119.501ms
```

### Automatic Retries

```bash
htreq -f request.http --retry 3 --retry-delay 2s
```

## Command-Line Options

```
Usage: htreq [target] [options]

Arguments:
  target                  host[:port] (optional if Host header present)

Options:
  -f, --file FILE         Request file (default: stdin)
  --unix-socket PATH      Connect to Unix socket
  --env                   Expand environment variables ($VAR or ${VAR})
  --env-file FILE         Load environment variables from file

  --tls                   Force TLS (auto-enabled for port 443)
  --no-tls                Disable TLS
  --no-verify             Skip TLS certificate verification
  --dump-tls              Show TLS session and certificate info

  --http2                 Use HTTP/2 protocol
  --websocket, --ws       Use WebSocket protocol
  --dump-frames           Show HTTP/2 frames (requires --http2)

  --retry N               Number of retries on failure (default: 0)
  --retry-delay DURATION  Delay between retries (default: 1s)
  --timeout DURATION      Socket timeout (default: 10s)
  --max-bytes N           Limit response output to N bytes

  --print-request         Show request being sent
  --timing                Show detailed request/response timing
  --head                  Show only response headers
  --body                  Show only response body

  --no-color              Disable colored output
  -q, --quiet             Suppress informational messages
  -v, --verbose           Verbose output
```

## Request File Format

Standard HTTP format:

```http
METHOD /path HTTP/1.1
Header-Name: value
Content-Type: application/json
Content-Length: 27

Request body content here
```

**Notes:**
- Line endings are automatically normalized (CRLF or LF accepted)
- Environment variables with `--env`: Use `$VAR` or `${VAR}` syntax
- Target can be specified in the `Host` header or as a command-line argument

## Examples Directory

The `examples/` directory contains ready-to-use request files:

```bash
htreq -f examples/get-https.http
htreq -f examples/post-json.http
htreq --http2 -f examples/http2-example.http
htreq --websocket -f examples/websocket-echo.http
```

See `examples/README.md` for complete documentation.

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE) file.
