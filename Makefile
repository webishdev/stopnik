# Variables
NAME := stopnik
VERSION ?= dev
GOOS ?= linux
GOARCH ?= amd64
GIT_HASH := $(shell git rev-parse --short=11 HEAD)
BIN_DIR := bin
BINARY_NAME := stopnik
MAIN_PATH := ./cmd/stopnik

# Default target
all: test lint

build-all: clean build-linux-intel build-linux-arm build-macos-intel build-macos-arm build-windows-intel build-windows-arm

build-ci: clean
	@echo "Building CI"
ifeq ($(CI_OS),ubuntu-latest)
	@$(MAKE) build-linux-intel
	@$(MAKE) build-linux-arm
	@$(MAKE) build-windows-intel
	@$(MAKE) build-windows-arm
else ifeq ($(CI_OS),macos-latest)
	@$(MAKE) build-macos-intel
	@$(MAKE) build-macos-arm
else ifeq ($(CI_OS),windows-latest)
	@$(MAKE) build-windows-intel
	@$(MAKE) build-windows-arm
else
	@echo "Could not detect build platform"
endif

build-windows-intel:
	@$(MAKE) build GOOS=windows GOARCH=amd64 BINARY_NAME=stopnik.exe

build-windows-arm:
	@$(MAKE) build GOOS=windows GOARCH=arm64 BINARY_NAME=stopnik.exe

build-linux-intel:
	@$(MAKE) build GOOS=linux GOARCH=amd64

build-linux-arm:
	@$(MAKE) build GOOS=linux GOARCH=arm64

build-macos-intel:
	@$(MAKE) build GOOS=darwin GOARCH=amd64

build-macos-arm:
	@$(MAKE) build GOOS=darwin GOARCH=arm64

# Build the application
build:
	@echo "Building $(BINARY_NAME) version $(VERSION) ($(GIT_HASH)) for $(GOOS) $(GOARCH) into $(BIN_DIR)"
	@mkdir -p $(BIN_DIR)/$(GOOS)/$(GOARCH)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-ldflags="-s -w -X 'main.Version=$(VERSION)' -X 'main.GitHash=$(GIT_HASH)'" \
		-o $(BIN_DIR)/$(GOOS)/$(GOARCH)/$(BINARY_NAME) $(MAIN_PATH)
	@cd $(BIN_DIR)/$(GOOS)/$(GOARCH) && sha256sum $(BINARY_NAME) >> SHA256SUMS
	@command -v zip >/dev/null 2>&1 && cd $(BIN_DIR)/$(GOOS)/$(GOARCH) && zip -q -r ../$(NAME).$(VERSION)-$(GOOS)-$(GOARCH).zip ./

lint: clean-lint
	@echo "Linting"
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || \
        echo "golangci-lint not installed; skipping"

# Run tests
test:
	@echo "Running tests"
	go test ./...

test-ci:
	@echo "Running tests for CI/CD"
	go test ./... -json > testresults.json

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts"
	@rm -rf $(BIN_DIR)

clean-test:
	@echo "Cleaning test results"
	@rm -f testresults.json
	@rm -rf ./test_coverage

clean-lint:
	@echo "Cleaning lint result"
	@rm -rf .lint_result/

clean-all: clean clean-lint clean-test

# Show help
help:
	@echo "not implemented yet"
