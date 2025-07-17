
SHELL = /bin/bash
.SHELLFLAGS = -o pipefail -c

.PHONY: help
help: ## Print info about all commands
	@echo "Commands:"
	@echo
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "    \033[01;32m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build all executables
	go build ./cmd/plcli

.PHONY: all
all: build

.PHONY: test
test: ## Run tests
	go test -short ./...

.PHONY: coverage-html
coverage-html: ## Generate test coverage report and open in browser
	go test ./... -coverpkg=./... -coverprofile=test-coverage.out
	go tool cover -html=test-coverage.out

.PHONY: lint
lint: ## Verify code style and run static checks
	go vet ./...
	test -z $(gofmt -l ./...)

.PHONY: golangci-lint
golangci-lint: ## Additional static linting
	golangci-lint run

.PHONY: fmt
fmt: ## Run syntax re-formatting (modify in place)
	go fmt ./...

.PHONY: check
check: ## Compile everything, checking syntax (does not output binaries)
	go build ./...

.env:
	if [ ! -f ".env" ]; then cp example.dev.env .env; fi
