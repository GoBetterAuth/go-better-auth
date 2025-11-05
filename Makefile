.PHONY: help build run test clean install setup
.PHONY: test test-coverage
.PHONY: lint fmt vet deps-update all check quick-check ci

# Variables
APP_NAME=go-better-auth
BINARY_PATH=./bin/$(APP_NAME)
SQLITE_DB?=app.db
POSTGRES_URL?=host=localhost user=postgres dbname=gobetterauth sslmode=disable

# Help command
help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

# Build commands
build: ## Build the package (library)
	@echo "Building $(APP_NAME) package..."
	@go build ./...
	@echo "Build complete!"

build-cli: ## Build CLI tool
	@echo "Building CLI tool..."
	@[ -f cmd/cli/main.go ] && CGO_ENABLED=1 go build -o $(BINARY_PATH)-cli ./cmd/cli || echo "No cmd/cli/main.go found"

# Run commands
run: ## Run example (if cmd/main.go exists)
	@[ -f cmd/main.go ] && go run ./cmd || echo "No cmd/main.go found. This is a library package."

# Test commands
test: ## Run all tests
	@echo "Running tests..."
	@CGO_ENABLED=1 go test -v ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@CGO_ENABLED=1 go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"
	@go tool cover -func=coverage.out | grep total | awk '{print "Total coverage: " $$3}'

# Dependency management
install: ## Install dependencies
	@echo "Installing dependencies..."
	@go mod download
	@go mod tidy

deps-update: ## Update dependencies
	@echo "Updating dependencies..."
	@go get -u ./...
	@go mod tidy

# Clean commands
clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@go clean

# Code quality
lint: ## Run linter
	@echo "Running linter..."
	@golangci-lint run

fmt: ## Format code
	@echo "Formatting code..."
	@go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	@go vet ./...

# Development setup
setup: install ## Setup development environment
	@echo "Setting up development environment..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install github.com/cosmtrek/air@latest
	@echo "Development environment setup complete!"

# All-in-one commands
all: clean install build check ## Clean, install deps, build, and run all checks

check: fmt vet lint test ## Run all checks (format, vet, lint, test)

quick-check: fmt vet test ## Run quick checks (format, vet, fast tests)

ci: clean install check ## CI pipeline (clean, install, check)

# Default target
.DEFAULT_GOAL := help
