# htreq agent guide

`AGENTS.md` is the entry point for contributors and coding agents. Read this file first, then read the linked guide(s) relevant to the work before editing.

## Project at a glance

htreq is a Go CLI that sends user-authored raw HTTP requests over TCP, TLS, HTTP/2, HTTP/3, WebSocket, or Unix sockets. The main implementation is [`main.go`](main.go); its unit tests are in [`main_test.go`](main_test.go).

## Required workflow

1. Read the relevant guide below and inspect existing code/tests before changing behavior.
2. Keep response data on stdout; diagnostics, warnings, and timing on stderr. Respect `--quiet`.
3. For Go changes, run `gofmt`, `go test ./...`, `go vet ./...`, and `go build -o /dev/null .` before reporting completion.
4. Add deterministic tests for bug fixes and behavior changes. Do not rely solely on external-service integration tests.
5. Keep user-facing documentation and [`ISSUES.md`](ISSUES.md) in sync with behavior and known limitations.

## Guides

- [Project and development](docs/agents/project.md) — layout, dependencies, build commands, architecture, and CLI conventions.
- [Go code style](docs/agents/code-style.md) — formatting, naming, errors, and maintainability.
- [Testing](docs/agents/testing.md) — required validation, local tests, and integration-test constraints.
- [Network and security](docs/agents/network-security.md) — connection lifecycle, deadlines, raw-request behavior, and sensitive data.
- [Git and documentation](docs/agents/git-and-docs.md) — commits, branches, and documentation upkeep.

## Non-negotiable guardrails

- Preserve the tool's raw-request intent: do not introduce hidden request rewriting or automatic protocol behavior without an explicit flag and documentation.
- Treat redirects, retries, TLS changes, environment expansion, and verbose logging as security-sensitive.
- Bound untrusted network input and preserve total request deadlines.
- Use the standard library before adding dependencies; run `go mod tidy` after dependency changes.
