# Go code style

- Use `gofmt`; use tabs and conventional Go formatting.
- Group standard-library imports before external imports.
- Use descriptive camelCase names. Keep protocol acronyms uppercase (`HTTP`, `TLS`, `URL`).
- Keep functions focused; use early returns to avoid deep nesting.
- Use pointer receivers only when mutation is required.
- Return contextual errors with `fmt.Errorf("operation failed: %w", err)`.
- Check errors explicitly. Close resources with `defer`; report non-actionable close failures only when useful and not quiet.
- Add comments for protocol rules, security decisions, and non-obvious state/lifecycle behavior—not for self-evident code.

## Maintainability

The project intentionally remains centered on `main.go`, so avoid creating unrelated abstractions. Extract helpers when a behavior has clear inputs/outputs and can be unit-tested independently. Keep protocol parsing and output handling separate where practical.

When changing raw-request behavior, preserve duplicate headers and byte semantics unless the selected protocol forbids them. Any unavoidable normalization in HTTP/2 or HTTP/3 must be documented.
