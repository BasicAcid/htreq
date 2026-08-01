# Known Issues & Improvements

This file tracks user-impacting gaps in the current implementation. Items are ordered by priority; line references identify the relevant functions rather than brittle exact line numbers.

## Open issues

### 1. WebSocket sessions can fail or hang after short idle periods
**Severity:** High
**Location:** `handleWebSocketSession`

The receive loop sets a 100 ms read deadline to poll for context cancellation. Gorilla WebSocket treats read errors, including timeouts, as terminal. Retrying after a timeout can leave the session coordinator blocked waiting on `done`.

**Recommended fix:** Do not use short read deadlines for polling. Close the underlying connection on cancellation to unblock `ReadMessage`, treat every read error as terminal, and ensure every goroutine reports completion exactly once.

---

### 2. HTTP/2 mishandles valid header-only responses and SETTINGS ACKs
**Severity:** High
**Location:** `readHTTP2Response`

A response ending on its `HEADERS` frame (`HEAD`, 204, 304, etc.) is not recognized as complete, so the client waits for another frame until the deadline. The client also ACKs incoming SETTINGS frames without checking whether they are already ACKs, violating HTTP/2 SETTINGS acknowledgement rules.

**Recommended fix:** Return when a completed response header block has `END_STREAM`; write a SETTINGS ACK only when `!frame.IsAck()`.

---

### 3. HTTP/3 ignores redirect controls
**Severity:** High
**Location:** `runHTTP3`

`http.Client` uses Go's default redirect policy. Therefore HTTP/3 redirects are followed even without `--follow`, and `--max-redirects` is ignored.

**Recommended fix:** Set `CheckRedirect` to reject redirects unless `--follow` is enabled and enforce `maxRedirects`. Keep behavior consistent with HTTP/1.1.

---

### 4. Retries can replay non-idempotent requests
**Severity:** High
**Location:** `main`, `isRetryableError`

The retry loop retries any request after a matching transport error. If a server processed a POST/PATCH but the response was lost, retrying can duplicate the side effect.

**Recommended fix:** Retry only idempotent methods by default. Require an explicit unsafe-retry opt-in for other methods and warn before replaying a request body.

---

### 5. HTTP/1 response headers have no size limit
**Severity:** High
**Location:** `readResponse`, `readResponseWithInfo`

Both readers buffer incoming bytes until `\r\n\r\n` without a maximum header size. A peer that never finishes headers can cause unbounded memory growth; `--max-bytes` does not protect this buffer.

**Recommended fix:** Add a configurable or conservative maximum response-header size and fail with a clear error once it is exceeded. Use bounded/streaming reads where possible.

---

### 6. HTTP/2 lacks full frame fragmentation support
**Severity:** Medium
**Location:** `runHTTP2`, `readHTTP2Response`

The implementation assumes a header block fits in a single HEADERS frame and a request body fits in one DATA frame. It does not handle CONTINUATION frames or peer frame-size constraints, causing failures with large headers/bodies or fragmented responses.

**Recommended fix:** Accumulate HEADERS/CONTINUATION fragments until `END_HEADERS`; split outbound headers and DATA according to negotiated peer limits.

---

### 7. Redirect URI resolution is incomplete
**Severity:** Medium
**Location:** `parseRedirectLocation`

Manual parsing does not correctly resolve relative paths, query-only and fragment references, scheme-relative URLs, mixed-case schemes, or all absolute URLs.

**Recommended fix:** Represent the current request as a `net/url.URL`, resolve `Location` with `ResolveReference`, and use normalized resolved URLs for redirect-loop detection.

---

### 8. Documentation and tests need alignment
**Severity:** Medium
**Location:** `README.md`, `AGENTS.md`, `Makefile`, `main_test.go`, `test/integration_test.sh`

The README's “no automatic behaviors” claim conflicts with HTTP/3's current implicit redirects. `AGENTS.md` still says the program is about 1350 lines with no unit tests. Default `make test` does not run integration tests, and the existing integration suite relies on external services. Unit coverage is low for protocol and error paths.

**Recommended fix:** Update documentation after redirect behavior is fixed; make local deterministic integration tests part of the normal test target; add tests for every issue above.

## Recently resolved

- HTTP/2 sends connection and stream `WINDOW_UPDATE` frames for received DATA.
- Redirects reconnect when the target/TLS mode changes or the server sends `Connection: close`.
- HTTP/1.1 redirects strip credential/token headers on an authority change and reject HTTPS-to-HTTP downgrades.
- Timed connections avoid a second DNS lookup.
- HTTP/2 preserves duplicate response headers.
- `prefixConn` preserves prefixes across short reads.
- The request deadline covers DNS, TCP, TLS, send, and receive phases.
- Response colorization stops at the header/body boundary.
- Environment-file expansion warns for non-`HTREQ_` variables.
