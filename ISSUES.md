# Known Issues & Improvements

## Bugs / Correctness Issues

### 1. HTTP/2 missing WINDOW_UPDATE — hangs on large responses
**Severity:** High
**Location:** `main.go:2020-2145` (`readHTTP2Response`)

The HTTP/2 implementation reads DATA frames but never sends `WINDOW_UPDATE` frames. For responses larger than the initial flow-control window size (65535 bytes by default), the server will stop sending data, causing the connection to hang until timeout.

**Status:** Fixed — WINDOW_UPDATE frames now sent for both connection (stream 0) and stream after each DATA frame. Also handles incoming `WindowUpdateFrame` from server.

---

### 2. Redirect reuses stale TCP connection
**Severity:** Medium
**Location:** `main.go:603-669` (`runHTTP1WithRedirects`)

When following redirects to the same host, the code reuses the same `conn` for subsequent requests. HTTP/1.1 connections are not guaranteed to be reusable after reading a response (the server may send `Connection: close` or just close). The code never checks if the connection is still alive. If the server closed it, the next Write/Read fails with a confusing error.

**Fix:** Either always reconnect on each redirect, or check the `Connection` response header.

**Status:** Fixed — reconnect when target changes, TLS requirement changes, or server sends `Connection: close`. `parseRedirectLocation` now returns the scheme so http→https upgrades are handled correctly. Connection ownership is tracked so the caller's deferred close is never double-fired.

---

### 3. Double DNS lookup in `connect()`
**Severity:** Medium
**Location:** `main.go:1069-1088`

`connect()` first calls `resolver.LookupHost()` for timing, then `net.DialTimeout()` which does its own DNS resolution internally. The two lookups may resolve to different IPs. Use `net.Dialer` with a custom resolver or `net.Dialer.ControlContext` to hook into the connection lifecycle for timing without duplicate work.

**Status:** Open

---

### 4. HTTP/2 duplicate headers lost
**Severity:** Medium
**Location:** `main.go:2024-2027` (`readHTTP2Response`)

HTTP/2 can have duplicate headers (e.g., `set-cookie`). Storing response headers in `map[string]string` means only the last value per key is kept. Should use `map[string][]string` or `http.Header`.

**Status:** Open

---

### 5. `prefixConn` prefix truncation (latent)
**Severity:** Low
**Location:** `main.go:1035-1042`

If the prefix is larger than the caller's buffer `p`, only `copy(p, c.prefix)` bytes are returned and the rest of the prefix is lost because `c.used` is set to `true` unconditionally. Currently the prefix is always exactly 1 byte (for TTFB timing), so this works in practice, but it's a latent bug.

**Status:** Open

---

### 6. Custom `min()` shadows Go 1.21+ builtin
**Severity:** Low
**Location:** `main.go:2188-2193`

Go 1.21+ has a builtin `min()`. With `go 1.24.4`, the custom definition is unnecessary and could confuse contributors. Remove it and use the builtin.

**Status:** Open

---

### 7. WebSocket stdin goroutine can't be interrupted
**Severity:** Low
**Location:** `main.go:2390` (`handleWebSocketSession`)

The stdin-reading goroutine calls `scanner.Scan()` which blocks on `os.Stdin`. The `select` with `ctx.Done()` only runs between iterations. If stdin is blocked waiting for input, `cancel()` won't unblock it. The goroutine hangs until the 300ms timeout at line 2429.

**Status:** Open

---

### 8. Response colorizer doesn't track header/body boundary
**Severity:** Low
**Location:** `main.go:198` (`colorizeHTTPResponse`)

After the status line, any line containing `:` is colorized as a header, including body lines if the header/body boundary isn't cleanly separated. The function doesn't track whether it's past the `\r\n\r\n` boundary.

**Status:** Open

---

## Design Suggestions

### 9. Timeout applies per-phase, not total
**Location:** `main.go:324, 874, 1088`

The same `cfg.timeout` is used independently for DNS, TCP connect, TLS handshake, and response reading. In the worst case, a request could take up to `4 * timeout`. A total deadline would be more intuitive.

---

### 10. Three functions for host:port parsing
**Location:** `main.go:1147, 1161, 1170`

`parseTarget`, `extractPort`, and `splitHostPort` all wrap `net.SplitHostPort` with slightly different defaults. `splitHostPort` is used only once (in `runHTTP3`). Consider consolidating.

---

### 11. `loadEnvFile` sets real process env vars without prefix check
**Location:** `main.go:1218`

`os.Setenv` affects the entire process environment. The security warning about non-`HTREQ_` prefixed vars (line 1291) is undermined by the fact that `loadEnvFile` itself sets arbitrary env vars without any prefix check.
