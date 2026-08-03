# NexProwl build targets.
#
# Everything here is a thin wrapper around the go tool — you never need make
# to work on this project. Its one real job is stamping version metadata, so a
# locally built binary reports a real version instead of "dev".
#
# On Windows: use `go build ./...` directly, or run these through Git Bash /
# WSL. There is no make on a stock Windows install.

BINARY  := nexprowl
# The leading "v" is stripped so a local build reports the same shape as a
# release build, which GoReleaser produces from the tag without it.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//' || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

PKG     := github.com/Arseno25/nexprowl/internal/scanner
LDFLAGS := -s -w \
	-X $(PKG).Version=$(VERSION) \
	-X $(PKG).Commit=$(COMMIT) \
	-X $(PKG).Date=$(DATE)

# Coverage floor enforced by CI. Keep in sync with .github/workflows/ci.yml.
COVERAGE_FLOOR := 70

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build ./nexprowl with version metadata
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) .
	@echo "built $(BINARY) $(VERSION)"

.PHONY: install
install: ## Build and install into $(go env GOPATH)/bin
	go install -trimpath -ldflags="$(LDFLAGS)" .
	@echo "installed to $$(go env GOPATH)/bin/$(BINARY)"

.PHONY: test
test: ## Run the test suite
	go test -count=1 ./...

.PHONY: race
race: ## Run tests under the race detector (needs a C compiler)
	go test -count=1 -race ./...

.PHONY: cover
cover: ## Run tests and enforce the coverage floor
	go test -count=1 -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1
	@total=$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	awk -v t="$$total" -v f="$(COVERAGE_FLOOR)" 'BEGIN { if (t < f) { printf "coverage %.1f%% is below the %d%% floor\n", t, f; exit 1 } }'

.PHONY: fmt
fmt: ## Format the tree
	gofmt -w .

.PHONY: check
check: ## Everything CI checks, minus the cross-compile
	@test -z "$$(gofmt -l .)" || { echo "gofmt: unformatted files:"; gofmt -l .; exit 1; }
	go vet ./...
	$(MAKE) race
	$(MAKE) cover
	go build ./...

.PHONY: clean
clean: ## Remove build and test artifacts
	rm -rf $(BINARY) $(BINARY).exe coverage.out dist/
