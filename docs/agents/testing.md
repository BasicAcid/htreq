# Testing and validation

## Required checks for Go changes

```bash
gofmt -w main.go main_test.go
go test ./...
go vet ./...
go build -o /dev/null .
```

Use `go test -race ./...` for changes involving goroutines, channels, shared state, or connection lifecycle.

## Test strategy

- Add unit tests in `main_test.go` for parsers, request transformations, flag validation, and error cases.
- Prefer local deterministic tests (`net.Pipe`, `httptest`, or controlled listeners) for protocol behavior and regressions.
- Include edge cases: malformed requests, absent/duplicate headers, IPv6 targets, short reads/writes, deadline expiry, and output limits.
- Exercise both `--quiet` and normal stderr output when adding diagnostics.

## Integration tests

```bash
make test-unit
make test-integration
make test-all
```

`test/integration_test.sh` contacts external services, so it is useful as a smoke test but must not be the sole proof of correctness. The default `make test` runs unit tests only.
