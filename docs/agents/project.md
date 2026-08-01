# Project and development

## Overview

htreq is a Go 1.24.4 command-line tool for sending user-authored HTTP requests over TCP or TLS. Supported modes include HTTP/1.1, HTTP/2, HTTP/3, WebSocket, Unix sockets, environment expansion, Basic authentication, retries, redirects, and timing output.

## Layout

- `main.go` — primary implementation (single-file architecture).
- `main_test.go` — unit tests.
- `test/` — integration script and request fixtures.
- `examples/` — documented request examples.
- `README.md` — user-facing reference.
- `ISSUES.md` — active limitations and planned improvements.
- `emacs/` — Emacs and org-mode integration.

## Build and run

```bash
make build                         # development binary: ./htreq
make build-release                 # stripped release binary
make clean                         # remove ./htreq

go build -o htreq .
./htreq -f examples/get-https.http
./htreq --http2 -f examples/http2-example.http
./htreq --websocket -f examples/websocket-echo.http
```

## Architecture and CLI conventions

- `main()` parses arguments and manages retries.
- `run()` validates configuration, loads request data, selects the protocol path, and applies the total request deadline.
- Protocol handlers own their connection lifecycle unless a caller explicitly owns the connection.
- Use the `flag` package. Provide short aliases only where they improve established CLI ergonomics.
- Validate conflicting flags before connecting and return descriptive errors; only `main()` should call `os.Exit`.
- The configured target is the network destination. The `Host` header is request metadata and may differ only where protocol behavior explicitly supports it.

## Dependencies

Current direct dependencies are Gorilla WebSocket, `golang.org/x/net`, and `golang.org/x/term`; HTTP/3 uses the indirect `quic-go` dependency. Prefer the standard library. Add dependencies with `go get`, then run `go mod tidy`.
