# Known Issues & Improvements

This file tracks user-impacting gaps in the current implementation. Items are ordered by priority; line references identify the relevant functions rather than brittle exact line numbers.

## Open issues

### 1. Retries can replay non-idempotent requests
**Severity:** High
**Location:** `main`, `isRetryableError`

The retry loop retries any request after a matching transport error. If a server processed a POST/PATCH but the response was lost, retrying can duplicate the side effect.

**Recommended fix:** Retry only idempotent methods by default. Require an explicit unsafe-retry opt-in for other methods and warn before replaying a request body.

---

### 2. HTTP/1 response headers have no size limit
**Severity:** High
**Location:** `readResponse`, `readResponseWithInfo`

Both readers buffer incoming bytes until `\r\n\r\n` without a maximum header size. A peer that never finishes headers can cause unbounded memory growth; `--max-bytes` does not protect this buffer.

**Recommended fix:** Add a configurable or conservative maximum response-header size and fail with a clear error once it is exceeded. Use bounded/streaming reads where possible.

---

### 3. HTTP/2 lacks full frame fragmentation support
**Severity:** Medium
**Location:** `runHTTP2`, `readHTTP2Response`

The implementation assumes a header block fits in a single HEADERS frame and a request body fits in one DATA frame. It does not handle CONTINUATION frames or peer frame-size constraints, causing failures with large headers/bodies or fragmented responses.

**Recommended fix:** Accumulate HEADERS/CONTINUATION fragments until `END_HEADERS`; split outbound headers and DATA according to negotiated peer limits.

---

### 4. Redirect URI resolution is incomplete
**Severity:** Medium
**Location:** `parseRedirectLocation`

Manual parsing does not correctly resolve relative paths, query-only and fragment references, scheme-relative URLs, mixed-case schemes, or all absolute URLs.

**Recommended fix:** Represent the current request as a `net/url.URL`, resolve `Location` with `ResolveReference`, and use normalized resolved URLs for redirect-loop detection.

---

### 5. Documentation and tests need alignment
**Severity:** Medium
**Location:** `README.md`, `AGENTS.md`, `Makefile`, `main_test.go`, `test/integration_test.sh`

The README's “no automatic behaviors” claim conflicts with HTTP/3's current implicit redirects. `AGENTS.md` still says the program is about 1350 lines with no unit tests. Default `make test` does not run integration tests, and the existing integration suite relies on external services. Unit coverage is low for protocol and error paths.

**Recommended fix:** Update documentation after redirect behavior is fixed; make local deterministic integration tests part of the normal test target; add tests for every issue above.

## Recently resolved

- HTTP/2 sends connection and stream `WINDOW_UPDATE` frames for received DATA.
- HTTP/2 completes header-only responses and acknowledges only non-ACK SETTINGS frames.
- HTTP/3 follows redirects only with `--follow`, enforces `--max-redirects`, and rejects HTTPS-to-HTTP downgrades.
- Redirects reconnect when the target/TLS mode changes or the server sends `Connection: close`.
- HTTP/1.1 redirects strip credential/token headers on an authority change and reject HTTPS-to-HTTP downgrades.
- WebSocket sessions close the connection to unblock reads instead of retrying timed-out reads.
- Timed connections avoid a second DNS lookup.
- HTTP/2 preserves duplicate response headers.
- `prefixConn` preserves prefixes across short reads.
- The request deadline covers DNS, TCP, TLS, send, and receive phases.
- Response colorization stops at the header/body boundary.
- Environment-file expansion warns for non-`HTREQ_` variables.
