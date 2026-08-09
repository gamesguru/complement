SHELL := /bin/bash
.DEFAULT_GOAL := help

STYLE_CYAN := $(shell tput setaf 6 2>/dev/null || printf '\033[36m')
STYLE_RESET := $(shell tput sgr0 2>/dev/null || printf '\033[0m')

GO ?= go
STATICCHECK ?= staticcheck
GOLANGCI_LINT ?= golangci-lint
VETFLAGS ?=
STATICCHECKFLAGS ?=
GOLANGCI_LINTFLAGS ?=
PKGS := ./...

# Complement itself is only a test harness: running the suite requires a
# built homeserver image (see README.md). TESTPKGS/TESTFLAGS let you scope a
# run without editing the command line every time, e.g.:
#   make test TESTPKGS=./tests/msc4499/... TESTFLAGS='-run TestMSC4499Key -v'
COMPLEMENT_BASE_IMAGE ?=
TESTPKGS ?= ./tests/...
TESTFLAGS ?= -v

.PHONY: help
help: ## Show available targets
	@grep -hE '^[a-zA-Z0-9_\/-]+:[[:space:]]*## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":[[:space:]]*## "}; {printf "$(STYLE_CYAN)%-12s$(STYLE_RESET) %s\n", $$1, $$2}'

.PHONY: format
format: ## Format Go source files
	$(GO) fmt $(PKGS)

.PHONY: build
build: ## Compile all packages (does not require a homeserver image)
	$(GO) build $(PKGS)

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(VETFLAGS) $(PKGS)

.PHONY: lint
lint: ## Run lint checks (vet, staticcheck, golangci-lint)
	$(GO) vet $(VETFLAGS) $(PKGS)
	$(STATICCHECK) -checks=all $(STATICCHECKFLAGS) $(PKGS)
	# install with, i.e., `curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b "$$(go env GOPATH)/bin" v2.12.2`
	$(GOLANGCI_LINT) run $(GOLANGCI_LINTFLAGS) $(PKGS)

.PHONY: test
test: ## Run the Complement test suite against COMPLEMENT_BASE_IMAGE (scope with TESTPKGS/TESTFLAGS)
ifeq ($(strip $(COMPLEMENT_BASE_IMAGE)),)
	$(error COMPLEMENT_BASE_IMAGE is not set; see README.md for how to build a homeserver image)
endif
	COMPLEMENT_BASE_IMAGE=$(COMPLEMENT_BASE_IMAGE) $(GO) test $(TESTFLAGS) $(TESTPKGS)

.PHONY: tidy
tidy: ## Tidy module dependencies
	$(GO) mod tidy

.PHONY: clean
clean: ## Remove generated test cache
	$(GO) clean -testcache
