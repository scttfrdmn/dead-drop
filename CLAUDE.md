# Claude Code Instructions

## Project Tracking

- Use **GitHub Issues**, **Labels**, **Milestones**, and **Projects** for all project tracking and development planning
- Do NOT generate local status/tracking markdown files (e.g., STATUS.md, TODO.md, PROGRESS.md, etc.)
- When creating work items, open GitHub Issues with appropriate labels
- Group related issues under GitHub Milestones for release planning
- Use GitHub Projects boards for workflow visibility

## Build & Test

- `make build` — build server and CLI
- `make build-production` — hardened production build with stripped symbols
- `make test` — run all tests
- `go vet ./...` — static analysis
