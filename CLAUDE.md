# Claude Code Instructions

## Project Tracking

- Use **GitHub Issues**, **Labels**, **Milestones**, and **Projects** for all project tracking and development planning
- Do NOT generate local status/tracking markdown files (e.g., STATUS.md, TODO.md, PROGRESS.md, etc.)
- When creating work items, open GitHub Issues with appropriate labels
- Group related issues under GitHub Milestones for release planning
- Use GitHub Projects boards for workflow visibility

## Versioning & Releases

- Follow [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html) (semver2)
- Maintain `CHANGELOG.md` using [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format
- Update CHANGELOG.md with every user-facing change
- Tag releases as `v<major>.<minor>.<patch>` (e.g., `v0.2.0`)
- License: Apache 2.0, Copyright 2026 Scott Friedman

## Code Quality

- Maintain an **A+ Go Report Card** — run `gofmt`, `go vet`, and lint checks before committing
- All code must pass `gosec`, `govulncheck`, and `staticcheck` without issues
- Security scanning runs in CI on every push and PR

## Build & Test

- `make build` — build server and CLI
- `make build-production` — hardened production build with stripped symbols
- `make test` — run all tests
- `go vet ./...` — static analysis
