# Network and security guidance

## Network behavior

- Apply the configured absolute deadline to DNS, TCP/Unix dialing, TLS, request writes, and response reads.
- Close every connection on all error paths. Do not double-close connections owned by a caller.
- Use buffered or streaming I/O and enforce limits on untrusted data. `--max-bytes` limits output; it does not replace parser-specific bounds.
- Keep stdout limited to response data. Connection details, warnings, timing, frame dumps, and errors belong on stderr and honor `--quiet`.
- TLS verification is enabled by default. `--no-verify` is for explicit testing only; avoid logging request secrets.

## Raw-request contract

htreq should send the user-authored HTTP/1.1 request without silently adding or rewriting headers. HTTP/2, HTTP/3, and WebSocket necessarily translate some request details; make that translation explicit, minimal, and documented.

## Sensitive operations

- Do not forward credentials, cookies, or token-like headers across redirect authorities.
- Refuse TLS-to-plaintext redirects unless a future, explicitly documented opt-in is added.
- Do not automatically retry non-idempotent requests without an explicit unsafe opt-in.
- Treat environment-file loading and variable expansion as secret-bearing operations. Do not print expanded values in diagnostics.
- Validate request-controlled hosts, paths, sizes, frame boundaries, and chunk sizes before allocating or sending data.
