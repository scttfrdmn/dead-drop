.PHONY: all build server submit clean test run install fmt lint build-production

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

all: build

build: server submit

server:
	@echo "Building server..."
	@go build -o dead-drop-server ./cmd/server

submit:
	@echo "Building submit CLI..."
	@go build -o dead-drop-submit ./cmd/submit

build-production:
	@echo "Building production binaries (hardened)..."
	@go build -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)" -o dead-drop-server ./cmd/server
	@go build -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)" -o dead-drop-submit ./cmd/submit
	@echo "Production build complete."

clean:
	@echo "Cleaning..."
	@rm -f dead-drop-server dead-drop-submit
	@rm -rf drops/

test:
	@echo "Running tests..."
	@go test -v ./...

run: server
	@echo "Starting server..."
	@./dead-drop-server

install:
	@echo "Installing to GOPATH/bin..."
	@go install ./cmd/server
	@go install ./cmd/submit

fmt:
	@echo "Formatting code..."
	@go fmt ./...

lint:
	@echo "Running linter..."
	@golangci-lint run || true
