# WebSocket Examples

## Overview

htreq supports WebSocket connections with the `--websocket` flag. After the HTTP upgrade handshake, you can send and receive messages interactively.

## Basic Usage

```bash
./htreq --websocket -f examples/websocket-echo.http
```

Once connected:
- Type a message and press Enter to send
- Received messages are displayed on stdout
- Press Ctrl+C to disconnect

## Request File Format

WebSocket requests use standard HTTP upgrade request format:

```http
GET /path HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
Sec-WebSocket-Version: 13

```

**Note**: The `Upgrade`, `Connection`, `Sec-WebSocket-Key`, and `Sec-WebSocket-Version` headers are automatically set by htreq. You can include them in your request file, but they will be ignored.

## Examples

### Echo Server

Test with a WebSocket echo server that returns whatever you send:

```bash
./htreq --websocket -f examples/websocket-echo.http
```

### Chat Application

Connect to a WebSocket chat server:

```bash
./htreq --websocket -f examples/websocket-chat.http
```

### Secure WebSocket (wss://)

WebSocket over TLS is automatically detected from the Host header and port:

```http
GET /socket HTTP/1.1
Host: secure-server.com:443

```

Or force TLS explicitly:

```bash
./htreq --websocket --tls -f request.http
```

### Custom Headers

Add custom headers like authentication:

```http
GET /socket HTTP/1.1
Host: api.example.com
Authorization: Bearer your-token-here
X-Custom-Header: value

```

### With Environment Variables

Use environment variables for dynamic values:

```bash
# .env file
API_HOST=ws.example.com
AUTH_TOKEN=secret-token
```

```http
GET /socket HTTP/1.1
Host: $API_HOST
Authorization: Bearer $AUTH_TOKEN

```

```bash
./htreq --websocket --env-file .env -f request.http
```

## Features

- **Interactive messaging**: Type and send messages in real-time
- **Bidirectional communication**: Send and receive simultaneously
- **Auto ping/pong**: Handled automatically by gorilla/websocket
- **Clean disconnect**: Sends proper close frame on exit
- **Color output**: Connection status with colored output
- **Timing**: Shows connection establishment time

## Limitations

- **Interactive mode only**: Currently only supports interactive terminal input
- **Text messages**: Optimized for text-based WebSocket communication
- **No binary mode yet**: Binary frame support coming in future updates

## Troubleshooting

### Connection Timeout

If connection hangs, try increasing the timeout:

```bash
./htreq --websocket --timeout 30s -f request.http
```

### TLS Verification

For self-signed certificates:

```bash
./htreq --websocket --no-verify -f request.http
```

### Verbose Output

See connection details:

```bash
./htreq --websocket --verbose -f request.http
```

## Testing Locally

### Simple Node.js WebSocket Server

```javascript
const WebSocket = require('ws');
const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', ws => {
  console.log('Client connected');
  ws.on('message', message => {
    console.log('Received:', message);
    ws.send(`Echo: ${message}`);
  });
});
```

Then connect:

```bash
./htreq --websocket -f examples/websocket-chat.http
```

## Public WebSocket Echo Services

Test with public echo servers:

- `wss://echo.websocket.events/` - WebSocket echo service
- `wss://ws.postman-echo.com/raw` - Postman's echo service  
- `wss://ws.ifelse.io/` - Simple WebSocket echo

## Future Enhancements

- Binary message support
- Non-interactive mode (send predefined messages)
- Message logging to file
- Ping/pong control
- Subprotocol negotiation
- Message compression

## See Also

- [RFC 6455 - The WebSocket Protocol](https://tools.ietf.org/html/rfc6455)
- [gorilla/websocket Documentation](https://pkg.go.dev/github.com/gorilla/websocket)
