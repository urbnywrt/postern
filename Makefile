# Developer entry points. From Windows Git Bash run them inside WSL:
#   bash scripts/wsl 'make build'

MODULE := github.com/urbnywrt/postern
BIN    := bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.Version=$(VERSION) \
	-X $(MODULE)/internal/version.Commit=$(COMMIT) \
	-X $(MODULE)/internal/version.Date=$(DATE)

# The end-to-end and integration tests are built with these tags only; vet and
# lint take them, as CI does, so that those tests are checked as well.
TEST_TAGS := e2e,integration

.PHONY: build test vet lint hooks

# Static binaries for the host platform; cross-compile with GOOS=linux GOARCH=arm64.
build:
	mkdir -p $(BIN)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/postern-node ./cmd/node
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/postern-panel ./cmd/panel

# Extra flags go in TESTFLAGS, for example: make test TESTFLAGS=-race
test:
	go test $(TESTFLAGS) ./...

vet:
	go vet ./...
	go vet -tags $(TEST_TAGS) ./...

# The tags leave no file out, so this one run covers the plain build too.
lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is not installed: https://golangci-lint.run/welcome/install/" >&2; exit 1; }
	golangci-lint run --build-tags $(TEST_TAGS) ./...

# Install the git hooks (deny-list check and secret scan) for this clone.
hooks:
	bash scripts/install-hooks.sh
