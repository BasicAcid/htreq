# Git and documentation

## Git conventions

- Use imperative commit subjects under 72 characters.
- Format: `<type>: <description>` where type is `feat`, `fix`, `docs`, `style`, `refactor`, `test`, or `chore`.
- Suggested branches: `feature/description`, `fix/description`, and `docs/description`.
- Keep generated binaries and coverage files untracked.

## Documentation upkeep

- Update `README.md` for user-visible flags, behavior, examples, or compatibility changes.
- Update `ISSUES.md` when resolving or discovering material correctness, security, performance, or roadmap issues.
- Keep this guide structure current: `AGENTS.md` is the entry point, while detailed contributor guidance belongs in `docs/agents/`.
- Examples must match the current command-line interface and supported protocols.
