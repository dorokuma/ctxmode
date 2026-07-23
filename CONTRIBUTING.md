# Contributing

## Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/).

Given a version number `MAJOR.MINOR.PATCH`:

- **MAJOR** — incompatible API or tool contract changes (removing/renaming a tool, changing argument semantics, breaking existing MCP clients).
- **MINOR** — backward-compatible new features (new tool, new config option, new runtime support).
- **PATCH** — backward-compatible bug fixes.

### Rules

1. Every change must be recorded in `CHANGELOG.md` under an `[Unreleased]` section (or directly in the release section if releasing immediately).
2. Releases must be tagged with `vX.Y.Z` (e.g., `v1.1.0`).
3. Breaking changes MUST bump MAJOR.

## Development workflow

1. Create a feature branch from `main`.
2. Make your changes. Keep them focused — one change per branch.
3. Build and test: `go build ./... && go test ./...`
4. Update `CHANGELOG.md`.
5. Open a pull request against `main`.

## Code style

- Standard Go conventions (`gofmt`, `go vet`).
- Keep functions focused on one task.
- Avoid adding dependencies without discussion.
