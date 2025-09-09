# Docker Compose Validator Makefile

# Variables
BINARY_NAME=dockerval
MAIN_PACKAGE=.
BUILD_DIR=build
VERSION?=1.0.0
LDFLAGS=-ldflags "-X main.Version=${VERSION}"

# Default target
.PHONY: all
all: clean deps build

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Build the binary
.PHONY: build
build:
	@echo "Building ${BINARY_NAME}..."
	mkdir -p ${BUILD_DIR}
	go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME} ${MAIN_PACKAGE}

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building for multiple platforms..."
	mkdir -p ${BUILD_DIR}
	
	# Linux AMD64
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-amd64 ${MAIN_PACKAGE}
	
	# Linux ARM64
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-linux-arm64 ${MAIN_PACKAGE}
	
	# macOS AMD64
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-amd64 ${MAIN_PACKAGE}
	
	# macOS ARM64 (Apple Silicon)
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-darwin-arm64 ${MAIN_PACKAGE}
	
	# Windows AMD64
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe ${MAIN_PACKAGE}

# Install binary to system
.PHONY: install
install: build
	@echo "Installing ${BINARY_NAME} to /usr/local/bin..."
	sudo cp ${BUILD_DIR}/${BINARY_NAME} /usr/local/bin/
	sudo chmod +x /usr/local/bin/${BINARY_NAME}

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run with example file
.PHONY: test-run
test-run: build
	@echo "Testing with example compose file..."
	./${BUILD_DIR}/${BINARY_NAME} validate example-docker-compose.yml

# Run with verbose output
.PHONY: test-verbose
test-verbose: build
	@echo "Testing with verbose output..."
	./${BUILD_DIR}/${BINARY_NAME} validate -v example-docker-compose.yml

# Test JSON output
.PHONY: test-json
test-json: build
	@echo "Testing JSON output..."
	./${BUILD_DIR}/${BINARY_NAME} validate -o json example-docker-compose.yml

# Test directory scan
.PHONY: test-scan
test-scan: build
	@echo "Testing directory scan..."
	./${BUILD_DIR}/${BINARY_NAME} scan .

# Test configuration check
.PHONY: test-check
test-check: build
	@echo "Testing configuration check..."
	./${BUILD_DIR}/${BINARY_NAME} check

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf ${BUILD_DIR}

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	./${BUILD_DIR}/${BINARY_NAME} --help > docs/CLI.md

# Create release package
.PHONY: package
package: build-all
	@echo "Creating release packages..."
	mkdir -p ${BUILD_DIR}/packages
	
	# Linux packages
	tar -czf ${BUILD_DIR}/packages/${BINARY_NAME}-${VERSION}-linux-amd64.tar.gz -C ${BUILD_DIR} ${BINARY_NAME}-linux-amd64 README.md
	tar -czf ${BUILD_DIR}/packages/${BINARY_NAME}-${VERSION}-linux-arm64.tar.gz -C ${BUILD_DIR} ${BINARY_NAME}-linux-arm64 README.md
	
	# macOS packages
	tar -czf ${BUILD_DIR}/packages/${BINARY_NAME}-${VERSION}-darwin-amd64.tar.gz -C ${BUILD_DIR} ${BINARY_NAME}-darwin-amd64 README.md
	tar -czf ${BUILD_DIR}/packages/${BINARY_NAME}-${VERSION}-darwin-arm64.tar.gz -C ${BUILD_DIR} ${BINARY_NAME}-darwin-arm64 README.md
	
	# Windows package
	zip -j ${BUILD_DIR}/packages/${BINARY_NAME}-${VERSION}-windows-amd64.zip ${BUILD_DIR}/${BINARY_NAME}-windows-amd64.exe README.md

# Development setup
.PHONY: dev-setup
dev-setup:
	@echo "Setting up development environment..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/goreleaser/goreleaser@latest

# Watch for changes and rebuild (requires entr)
.PHONY: watch
watch:
	@echo "Watching for changes..."
	find . -name "*.go" | entr -r make build

# Benchmark the tool
.PHONY: benchmark
benchmark: build
	@echo "Running benchmarks..."
	time ./${BUILD_DIR}/${BINARY_NAME} validate example-docker-compose.yml
	time ./${BUILD_DIR}/${BINARY_NAME} scan .

# Security check
.PHONY: security
security:
	@echo "Running security checks..."
	gosec ./...

# Docker build (for containerized usage)
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t ${BINARY_NAME}:${VERSION} .

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all          - Clean, install deps, and build"
	@echo "  deps         - Install Go dependencies"
	@echo "  build        - Build binary for current platform"
	@echo "  build-all    - Build for all supported platforms"
	@echo "  install      - Install binary to system PATH"
	@echo "  test         - Run Go tests"
	@echo "  test-run     - Test with example file"
	@echo "  test-verbose - Test with verbose output"
	@echo "  test-json    - Test JSON output format"
	@echo "  test-scan    - Test directory scanning"
	@echo "  test-check   - Test configuration check"
	@echo "  clean        - Remove build artifacts"
	@echo "  fmt          - Format Go code"
	@echo "  lint         - Run linter"
	@echo "  docs         - Generate documentation"
	@echo "  package      - Create release packages"
	@echo "  dev-setup    - Setup development tools"
	@echo "  watch        - Watch for changes and rebuild"
	@echo "  benchmark    - Run performance benchmarks"
	@echo "  security     - Run security checks"
	@echo "  docker-build - Build Docker image"
	@echo "  help         - Show this help"
