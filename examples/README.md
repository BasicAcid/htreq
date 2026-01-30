# Examples

## Basic Usage

HTTPS GET with auto-detected host (from Host header, auto-TLS on port 443):
```bash
./htreq -f examples/get-https.http
```

HTTPS GET with explicit target:
```bash
./htreq example.com -f examples/get-https.http
```

POST with JSON:
```bash
./htreq -f examples/post-json.http
```

Custom headers:
```bash
./htreq -f examples/custom-headers.http
```

## Unix Sockets

Docker API (requires Docker daemon running):
```bash
# Get Docker version
echo "GET /version HTTP/1.1
Host: localhost

" | sudo ./htreq --unix-socket /var/run/docker.sock

# List containers
echo "GET /containers/json HTTP/1.1
Host: localhost

" | sudo ./htreq --unix-socket /var/run/docker.sock
```

## Output Control

Headers only:
```bash
./htreq -f examples/post-json.http --head
```

Body only:
```bash
./htreq -f examples/post-json.http --body
```

Save to file:
```bash
./htreq -f examples/get-https.http > response.txt
```

Limit output:
```bash
./htreq -f examples/get-https.http --max-bytes 1000
```

Disable colors (for scripts or when piping fails to auto-detect):
```bash
./htreq -f examples/get-https.http --no-color
```

## TLS

Dump certificate info (auto-TLS on port 443):
```bash
./htreq github.com:443 --dump-tls
```

Disable verification:
```bash
./htreq self-signed-host.local -f examples/get-https.http --no-verify
```

Force TLS on non-standard port:
```bash
./htreq api.local:8443 --tls -f examples/get-https.http
```

Force plain TCP on port 443:
```bash
./htreq example.com:443 --no-tls -f examples/get-https.http
```

## Basic Authentication

HTTP Basic Authentication with automatic header generation:
```bash
./htreq -f examples/basic-auth.http --user myuser:mypass
```

The `--user` flag automatically generates the `Authorization: Basic` header with base64-encoded credentials.

**Security Warning:** Basic authentication should only be used over HTTPS/TLS. htreq will warn you if you use `--user` without TLS:
```bash
# This will show a warning about plain text credentials
./htreq some-host.com:80 -f request.http --user myuser:mypass --no-tls
```

You can verify the header is being injected correctly:
```bash
./htreq -f examples/basic-auth.http --user myuser:mypass --print-request
```

## Environment Variables

Create a `.env` file and use it with requests:
```bash
cp examples/.env.example .env
# Edit .env with your credentials
```

Example API request with token:
```bash
# Create request file with environment variables
echo "GET /api/data HTTP/1.1
Host: \${API_HOST}
Authorization: Bearer \${API_TOKEN}
Accept: application/json

" > api-request.http

./htreq --env-file .env -f api-request.http
```

OAuth token request example:
```bash
# OAuth token request (requires OAuth server)
echo "POST /auth/realms/example-dev/protocol/openid-connect/token HTTP/1.1
Host: \${OAUTH_HOST}
Content-Type: application/x-www-form-urlencoded
Content-Length: 131

username=\${OAUTH_USER}&password=\${OAUTH_PASSWORD}&grant_type=password&client_id=\${OAUTH_CLIENT_ID}&client_secret=\${OAUTH_CLIENT_SECRET}" > oauth-request.http

./htreq --env-file .env -f oauth-request.http
```

Using shell variables:
```bash
export API_TOKEN="secret"
export API_HOST="api.example.com"
echo "GET /api/data HTTP/1.1
Host: \$API_HOST
Authorization: Bearer \$API_TOKEN

" | ./htreq --env
```

## Debugging

Print request being sent:
```bash
./htreq --print-request -f examples/get-https.http
```

## Performance Measurement

Response time is automatically measured and displayed:
```bash
./htreq -f examples/get-https.http
# Output includes: [*] Response received in 123ms
```

Suppress timing (and all stderr output):
```bash
./htreq -f examples/get-https.http --quiet
```

## Chunked Transfer Encoding

htreq automatically decodes chunked responses:
```bash
./htreq httpbin.org --tls -f examples/chunked-response.http
```

Extract JSON from chunked response:
```bash
./htreq httpbin.org --tls -f examples/chunked-response.http --body -q | jq
```

## HTTP/2

Use HTTP/2 protocol (host auto-detected from request, auto-TLS):
```bash
./htreq --http2 -f examples/http2-example.http
```

Inspect HTTP/2 frames:
```bash
./htreq --http2 --dump-frames -f examples/http2-example.http
```

Verbose frame inspection with hex dumps:
```bash
./htreq --http2 --dump-frames --verbose -f examples/http2-example.http
```

HTTP/2 uses the same request file format as HTTP/1.1 - htreq handles the protocol conversion automatically.

## WebSocket

Interactive WebSocket connections (public echo service):
```bash
./htreq --websocket -f examples/websocket-echo.http
```

## Piping

From file (auto-TLS for port 443):
```bash
cat examples/get-https.http | ./htreq
```

From file with explicit target:
```bash
cat examples/get-https.http | ./htreq example.com
```

Inline:
```bash
echo -e "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | ./htreq
```
